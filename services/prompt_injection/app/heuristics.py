"""
Stage 1 -- heuristic / regex pass. Fast, deterministic, always runs, no ML.

Looks for these in every extracted span:
  1. Known injection phrasings (config-driven, editable without a redeploy),
     matched both against the raw text AND against a "de-spaced" version
     (to catch keyword evasion like "i g n o r e") and a ROT13-decoded
     version (to catch that specific classic obfuscation).
  2. Attacker obfuscation tricks specific to this threat model:
     zero-width/invisible unicode, homoglyph substitution, suspicious
     base64 or hex-encoded blobs.
  3. Combines all of the above into a single confidence contribution +
     human-readable match reasons, for the `evidence` field downstream.

Nothing here calls out to the network or loads a model -- this stage is
supposed to be cheap enough to run on every span, every request.

Known gap (see README "Known limitations"): this is still a fixed list
of specific tricks, not a general-purpose obfuscation detector. A
sufficiently creative encoding we haven't thought to check for will
still get through Stage 1 untouched (though it may still be caught by
Stage 2's semantic similarity, which doesn't care how the words are
spelled).
"""

from __future__ import annotations

import base64
import codecs
import re
from dataclasses import dataclass, field

from app.extraction import Span

# Zero-width / invisible characters commonly used to hide text from a
# human reader while an AI agent's tokenizer still sees it.
_ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u00ad": "SOFT HYPHEN",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
}

# Cyrillic/Greek characters (lowercase and uppercase) that are visually
# indistinguishable from common Latin letters -- classic homoglyph
# attack material for smuggling text past naive keyword filters.
_HOMOGLYPHS = {
    # lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ɡ": "g", "α": "a", "ο": "o",
    "ν": "v", "ԛ": "q", "ѡ": "w",
    # uppercase (Cyrillic capitals that look like Latin capitals)
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ѕ": "S", "Ј": "J",
}

_BASE64_BLOCK_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")

# \xNN-style hex escapes (e.g. Python/JS string escapes hiding text),
# and plain long runs of hex digits that could be a hex-encoded payload.
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){6,}")
_HEX_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{20,}(?![0-9A-Fa-f])")

# Sequences of single word-characters separated by spaces/dots/dashes/
# underscores, e.g. "i g n o r e" or "i.g.n.o.r.e" or "i_g_n_o_r_e" --
# a common trick to break up a keyword so naive substring matching
# misses it. Requires at least 4 characters in the run to avoid
# collapsing coincidental short sequences ("a b" in normal prose).
_DESPACE_RUN_RE = re.compile(r"\b\w(?:[ .\-_]\w){3,}\b")


def _despace(text: str) -> str:
    """Collapse spaced/punctuated-out single-character runs back into words."""
    return _DESPACE_RUN_RE.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), text)


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


@dataclass
class HeuristicResult:
    span: Span
    score: float  # 0.0 - 1.0
    reasons: list[str] = field(default_factory=list)


def _compile_phrase_patterns(phrases: list[str]) -> list[re.Pattern]:
    patterns = []
    for phrase in phrases:
        # Turn each configured phrase into a whitespace-tolerant, case
        # insensitive regex (so "ignore   previous\ninstructions" still
        # matches), rather than a brittle literal substring match.
        escaped_words = [re.escape(w) for w in phrase.split()]
        pattern = r"\s+".join(escaped_words)
        patterns.append(re.compile(pattern, re.IGNORECASE))
    return patterns


def _looks_like_base64(candidate: str) -> bool:
    try:
        decoded = base64.b64decode(candidate + "==", validate=False)
    except Exception:
        return False
    # Heuristic: require a minimum decoded length so short coincidental
    # matches (e.g. a long CamelCase identifier) are less likely to
    # trip this.
    return len(decoded) >= 16


def _try_decode_hex(candidate: str) -> str | None:
    cleaned = candidate.replace("\\x", "")
    if len(cleaned) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(cleaned).decode("utf-8", errors="strict")
        return decoded if decoded.isprintable() else None
    except (ValueError, UnicodeDecodeError):
        return None


class HeuristicScanner:
    def __init__(self, config: dict):
        heur_cfg = config.get("regex_heuristics", {})
        self.enabled = heur_cfg.get("enabled", True)
        self.phrases = heur_cfg.get("suspicious_phrases", [])
        self._phrase_patterns = list(zip(self.phrases, _compile_phrase_patterns(self.phrases)))

        self.phrase_weight = heur_cfg.get("phrase_weight", 0.9)
        self.zero_width_weight = heur_cfg.get("zero_width_weight", 0.85)
        self.homoglyph_weight = heur_cfg.get("homoglyph_weight", 0.6)
        self.base64_weight = heur_cfg.get("base64_weight", 0.5)
        # Slightly lower than a direct phrase match: decoding is strong
        # evidence of deliberate obfuscation, but the decoded content
        # itself is what actually matched, one step removed from plain text.
        self.encoded_phrase_weight = heur_cfg.get("encoded_phrase_weight", 0.8)

    def _find_phrase_match(self, text: str) -> tuple[str, re.Match] | None:
        for phrase, pattern in self._phrase_patterns:
            m = pattern.search(text)
            if m:
                return phrase, m
        return None

    def score_span(self, span: Span) -> HeuristicResult:
        if not self.enabled:
            return HeuristicResult(span=span, score=0.0, reasons=[])

        text = span.text
        reasons: list[str] = []
        contributions: list[float] = []

        # 1a. Known injection phrasings, matched directly.
        direct_match = self._find_phrase_match(text)
        if direct_match:
            phrase, _ = direct_match
            reasons.append(f'matched suspicious phrase "{phrase}"')
            contributions.append(self.phrase_weight)
        else:
            # 1b. Same phrases, but against a de-spaced version of the
            # text -- catches "i g n o r e   t h e   d e v e l o p e r"
            # style keyword-splitting evasion.
            despaced = _despace(text)
            if despaced != text:
                despaced_match = self._find_phrase_match(despaced)
                if despaced_match:
                    phrase, _ = despaced_match
                    reasons.append(f'matched suspicious phrase "{phrase}" after removing spacing used to evade detection')
                    contributions.append(self.encoded_phrase_weight)

            # 1c. Same phrases, but against a ROT13-decoded version --
            # catches that one specific classic obfuscation cheaply.
            rot13_text = _rot13(text)
            rot13_match = self._find_phrase_match(rot13_text)
            if rot13_match:
                phrase, _ = rot13_match
                reasons.append(f'matched suspicious phrase "{phrase}" after ROT13-decoding the span')
                contributions.append(self.encoded_phrase_weight)

            # 1d. Hex-escaped or hex-encoded blocks that decode to
            # readable text containing a known phrase.
            for candidate in list(_HEX_ESCAPE_RE.findall(text)) + list(_HEX_RUN_RE.findall(text)):
                decoded = _try_decode_hex(candidate)
                if decoded:
                    hex_match = self._find_phrase_match(decoded)
                    if hex_match:
                        phrase, _ = hex_match
                        reasons.append(f'matched suspicious phrase "{phrase}" after hex-decoding an embedded block')
                        contributions.append(self.encoded_phrase_weight)
                        break

        # 2. Zero-width / invisible unicode.
        found_zw = sorted({ch for ch in text if ch in _ZERO_WIDTH_CHARS})
        if found_zw:
            names = ", ".join(_ZERO_WIDTH_CHARS[ch] for ch in found_zw)
            reasons.append(f"contains invisible unicode characters ({names})")
            contributions.append(self.zero_width_weight)

        # 3. Homoglyph substitution -- only meaningful when mixed into
        # otherwise-Latin text (a purely Cyrillic/Greek span is just
        # written in that language, not an attack).
        homoglyph_hits = [ch for ch in text if ch in _HOMOGLYPHS]
        has_latin = bool(re.search(r"[A-Za-z]", text))
        if homoglyph_hits and has_latin:
            examples = ", ".join(sorted(set(f"{ch}\u2192{_HOMOGLYPHS[ch]}" for ch in homoglyph_hits))[:5])
            reasons.append(f"contains homoglyph substitutions mixed with Latin text ({examples})")
            contributions.append(self.homoglyph_weight)

        # 4. Suspicious base64-looking blocks.
        for candidate in _BASE64_BLOCK_RE.findall(text):
            if _looks_like_base64(candidate):
                preview = candidate[:12] + ("\u2026" if len(candidate) > 12 else "")
                reasons.append(f"contains a suspicious base64-looking block ({preview})")
                contributions.append(self.base64_weight)
                break  # one is enough signal

        score = max(contributions) if contributions else 0.0
        # Small bump if multiple independent signals fire together --
        # stacking tricks is itself suspicious.
        if len(contributions) > 1:
            score = min(1.0, score + 0.1 * (len(contributions) - 1))

        return HeuristicResult(span=span, score=round(score, 4), reasons=reasons)