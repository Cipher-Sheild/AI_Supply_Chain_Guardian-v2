"""
Stage 0 — span extraction.

Pulls natural-language, human-readable spans out of an incoming artifact:
code comments, Python docstrings, and README/markdown prose. These are
the surfaces a *human* rarely reads closely but an *AI coding agent*
often ingests wholesale — which is exactly why they're the vector for
indirect prompt injection (see services/prompt_injection/README.md for
the threat model).

Design notes
------------
- `extract_spans(artifact) -> list[Span]` is the single public entrypoint.
- Language-specific extractors are registered in `_EXTRACTORS` so new
  languages/config formats can be plugged in later without touching the
  dispatch logic (YAML/JSON/Dockerfile scanning is explicitly out of
  scope for this version — see project doc §2).
- Extraction is best-effort and regex/AST based, not a full compiler
  front-end. Comments living inside string literals, or unusual/exotic
  syntax, can produce false positives or misses — see README "Known
  limitations".
"""

from __future__ import annotations

import ast
import io
import tokenize
from functools import lru_cache
import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Location:
    """Where a span came from, for explainability in findings."""

    line: Optional[int] = None
    source_type: str = "unknown"  # "comment" | "docstring" | "markdown_prose"
    filename: Optional[str] = None


@dataclass
class Span:
    text: str
    location: Location
    source_type: str  # mirrors location.source_type, kept flat for convenience


def _guess_language(artifact: dict) -> str:
    """
    Resolve known filename extensions before caller hints, then use explicit
    language/type and content sniffing when the filename is unrecognized.
    """
    filename = (artifact.get("filename") or artifact.get("file_path") or "").lower()
    if filename.endswith((".py", ".pyi")):
        return "python"
    if filename.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    if filename.endswith((".ts", ".tsx")):
        return "typescript"
    for extension,language in [('.go','go'),('.java','java'),('.php','php')]:
        if filename.endswith(extension):return language
    if filename.endswith((".md", ".markdown")):
        return "markdown"


    explicit = (artifact.get("language") or artifact.get("type") or "").strip().lower()
    if explicit in _EXTRACTORS:
        return explicit
    # Common aliases seen in the wild.
    aliases = {
        "py": "python",
        "js": "javascript",
        "jsx": "javascript",
        "ts": "typescript",
        "tsx": "typescript",
        "md": "markdown",
        "markdown": "markdown",
        "code": None,  # too generic, fall through to filename/content sniff
    }
    if explicit in aliases and aliases[explicit]:
        return aliases[explicit]

    content = artifact.get("content", "") or ""
    stripped = content.lstrip()
    if stripped.startswith(("# ", "#!")) or "def " in content or "import " in content:
        return "python"
    if re.search(r"^#{1,6}\s", content, re.MULTILINE) or "```" in content:
        return "markdown"

    return "plaintext"


# ---------------------------------------------------------------------------
# Python: line comments (#) + docstrings (via ast, with a regex fallback)
# ---------------------------------------------------------------------------

_PY_LINE_COMMENT_RE = re.compile(r"(?<!['\"])#(.*)$", re.MULTILINE)
_TRIPLE_QUOTED_RE = re.compile(r"(['\"]{3})(.*?)\1", re.DOTALL)


def _extract_python(content: str, filename: Optional[str]) -> list[Span]:
    spans: list[Span] = []

    # Python's lexer keeps hashes in quoted values out of the comment stream.
    try:
        for token in tokenize.generate_tokens(io.StringIO(content).readline):
            if token.type==tokenize.COMMENT and token.string[1:].strip():
                spans.append(Span(token.string[1:].strip(),Location(line=token.start[0],source_type='comment',filename=filename),'comment'))
    except (tokenize.TokenError,IndentationError):
        pass  # Keep valid prefix comments; the code agent reports malformed syntax.

    # Docstrings — prefer the AST so we only capture *real* docstrings
    # (module/class/function), not arbitrary triple-quoted strings.
    docstring_texts_seen: set[str] = set()
    try:
        tree = ast.parse(content)
        candidates: list[ast.AST] = [tree]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                candidates.append(node)
        for node in candidates:
            doc = ast.get_docstring(node, clean=True)
            if doc and doc.strip():
                lineno = getattr(node, "lineno", None)
                spans.append(
                    Span(
                        text=doc.strip(),
                        location=Location(line=lineno, source_type="docstring", filename=filename),
                        source_type="docstring",
                    )
                )
                docstring_texts_seen.add(doc.strip())
    except SyntaxError:
        # Artifact isn't valid, parseable Python (e.g. a snippet, or
        # AI-generated code with a typo) — fall back to a regex sweep
        # for triple-quoted strings so we still get *some* coverage.
        for match in _TRIPLE_QUOTED_RE.finditer(content):
            text = match.group(2).strip()
            if text and text not in docstring_texts_seen:
                line = content[: match.start()].count("\n") + 1
                spans.append(
                    Span(
                        text=text,
                        location=Location(line=line, source_type="docstring", filename=filename),
                        source_type="docstring",
                    )
                )

    return spans


# ---------------------------------------------------------------------------
# JS/TS-style: // line comments and /* */ block comments
# ---------------------------------------------------------------------------

_LINE_COMMENT_RE = re.compile(r"//(.*)$", re.MULTILINE)
_BLOCK_COMMENT_RE = re.compile(r"/\*(.*?)\*/", re.DOTALL)


@lru_cache(maxsize=8)
def _comment_parser(language):
    from tree_sitter import Language,Parser
    if language=='typescript':
        import tree_sitter_typescript as grammar
        capsule=grammar.language_typescript()
    elif language=='tsx':
        import tree_sitter_typescript as grammar
        capsule=grammar.language_tsx()
    else:
        module=__import__('tree_sitter_'+language)
        capsule=module.language_php_only() if language=='php' else module.language()
    return Language(capsule)


def _extract_c_style(content: str, filename: Optional[str],language=None) -> list[Span]:
    language=language or ('tsx' if (filename or '').endswith('.tsx') else 'typescript' if (filename or '').endswith('.ts') else 'go' if (filename or '').endswith('.go') else 'java' if (filename or '').endswith('.java') else 'php' if (filename or '').endswith('.php') else 'javascript')
    from tree_sitter import Parser
    raw=content.encode();tree=Parser(_comment_parser(language)).parse(raw);stack=[tree.root_node];spans=[]
    while stack:
        node=stack.pop()
        if 'comment' in node.type:
            text=raw[node.start_byte:node.end_byte].decode(errors='replace')
            if text.startswith('/*'):text=text[2:-2]
            elif text.startswith('//'):text=text[2:]
            elif text.startswith('#'):text=text[1:]
            text=text.strip().strip('*').strip()
            if text:spans.append(Span(text,Location(line=node.start_point.row+1,source_type='comment',filename=filename),'comment'))
        else:stack.extend(reversed(node.children))
    return spans


# ---------------------------------------------------------------------------
# Markdown: strip fenced code blocks for prose, but still scan the code
# inside those fences for comments (per project doc §2 — code blocks in
# markdown should still be scanned for comments; prose is the main target).
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)


def _extract_markdown(content: str, filename: Optional[str]) -> list[Span]:
    spans: list[Span] = []

    # Scan fenced code blocks for comments, using the fence's language tag
    # when we recognize it.
    for match in _FENCE_RE.finditer(content):
        lang = (match.group(1) or "").strip().lower()
        code = match.group(2)
        line_offset = content[: match.start(2)].count("\n")
        sub_spans: list[Span] = []
        if lang in ("python", "py"):
            sub_spans = _extract_python(code, filename)
        elif lang in ("javascript", "js", "typescript", "ts", "jsx", "tsx","go","java","php"):
            grammar={"js":"javascript","jsx":"javascript","ts":"typescript"}.get(lang,lang)
            sub_spans = _extract_c_style(code, filename,grammar)
        else:
            # Unknown/absent language tag — best-effort with both comment
            # styles, since either could plausibly appear.
            sub_spans = _extract_plaintext(code, filename)
        for s in sub_spans:
            if s.location.line is not None:
                s.location.line += line_offset
            spans.append(s)

    # Prose = everything outside fenced code blocks.
    prose = _FENCE_RE.sub(lambda match:"\n"*match.group(0).count("\n"), content)
    # Split into paragraphs so each finding can point at a smaller region
    # instead of "somewhere in this README".
    for match in re.finditer(r'\S(?:.*?\S)?(?=\n[ \t]*\n|\s*\Z)',prose,re.DOTALL):
        spans.append(Span(match.group(0),Location(line=prose[:match.start()].count('\n')+1,source_type='markdown_prose',filename=filename),'markdown_prose'))

    return spans


def _extract_plaintext(content: str, filename: Optional[str]) -> list[Span]:
    """Fallback: treat the whole thing as one prose span."""
    text = content.strip()
    if not text:
        return []
    return [
        Span(
            text=text,
            location=Location(line=1, source_type="markdown_prose", filename=filename),
            source_type="markdown_prose",
        )
    ]


_EXTRACTORS: dict[str, Callable[[str, Optional[str]], list[Span]]] = {
    "python": _extract_python,
    "javascript": _extract_c_style,
    "typescript": _extract_c_style,
    "go": lambda c,f:_extract_c_style(c,f,"go"),
    "java": lambda c,f:_extract_c_style(c,f,"java"),
    "php": lambda c,f:_extract_c_style(c,f,"php"),
    "markdown": _extract_markdown,
    "plaintext": _extract_plaintext,
}


def extract_spans(artifact: dict) -> list[Span]:
    """
    Entry point for Stage 0. `artifact` is the same dict trust_engine
    posts to every detector's /analyze — at minimum a `content` string,
    optionally `type`/`language` and `filename` hints.
    """
    content = artifact.get("content") or ""
    if not content.strip():
        return []

    filename = artifact.get("filename") or artifact.get("file_path")
    language = _guess_language(artifact)
    extractor = _EXTRACTORS.get(language, _extract_plaintext)
    return extractor(content, filename)
