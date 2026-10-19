"""
Stage 2 -- embedding similarity pass. Fast, always runs (on spans not
already flagged high-confidence by Stage 1), no LLM call.

Embeds each candidate span with sentence-transformers/all-MiniLM-L6-v2
(small, CPU-friendly) and compares it against a curated set of "known
injection" example embeddings loaded from app/data/injection_anchors.json.
The model and the anchor embeddings are both loaded once and cached in
memory (see get_model() / get_anchor_embeddings()) -- get_anchor_embeddings
is called eagerly at server startup (see main.py) rather than lazily on
first request, so the large one-time model-load cost happens once at
boot instead of delaying whichever request happens to be first.

Batching
--------
batch_similarity_to_anchors() embeds many spans in a single model call
instead of one call per span, since on CPU the per-call overhead in
sentence-transformers is significant relative to the actual compute.

Long-span chunking
--------------------
MiniLM has a real input length limit (~256 tokens). A very long
docstring or comment naively passed to model.encode() gets silently
truncated -- anything past the limit is never actually seen by the
model, meaning an injection buried in the middle or end of a large
block of text could slip through untouched. To avoid this,
_chunk_text() splits long spans into overlapping word-windows; each
span's final similarity score is the MAX similarity across its chunks,
so a suspicious sentence anywhere in a long span is caught, not just
whatever happened to be in the first ~256 tokens.

Offline/test fallback
----------------------
Downloading the real MiniLM weights requires network access to the
HuggingFace Hub, which isn't available in every environment. If the
real model can't be loaded, this module transparently falls back to a
dependency-free bag-of-words cosine similarity so Stage 2 still
produces a meaningful (if less semantically rich) score instead of
silently no-op'ing or crashing the request.
"""

from __future__ import annotations

import json
import hashlib
import logging
import math
import os
import re
import threading
from functools import lru_cache
from pathlib import Path
from typing import Optional

from app.extraction import Span

logger = logging.getLogger("prompt_injection.embeddings")

_ANCHORS_PATH = Path(__file__).parent / "data" / "injection_anchors.json"
_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# Chunking parameters for long spans. MiniLM's real limit is ~256
# tokens; we chunk by words (a rough but simple proxy for tokens) well
# under that limit to leave headroom, with overlap so a phrase that
# straddles a chunk boundary isn't missed entirely.
_CHUNK_SIZE_WORDS = 150
_CHUNK_OVERLAP_WORDS = 30

_model_lock = threading.RLock()
_model = None
_model_load_failed = False
_anchor_embeddings = None  # cached at startup, see get_anchor_embeddings()
_anchor_texts: list[str] = []


def _load_anchor_texts() -> list[str]:
    global _anchor_texts
    if _anchor_texts:
        return _anchor_texts
    with open(_ANCHORS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    _anchor_texts = [row["text"] for row in data if row.get("label") == "injection"]
    return _anchor_texts


def validate_local_snapshot(local):
    """Verify the recorded pinned weights before loading an on-disk model."""
    manifest_path=local.parent/'embedding-manifest.json'
    if manifest_path.stat().st_size>131072:raise ValueError('embedding manifest exceeds budget')
    manifest=json.loads(manifest_path.read_text())
    expected=os.getenv('EMBEDDING_MODEL_REVISION','1110a243fdf4706b3f48f1d95db1a4f5529b4d41')
    if manifest.get('repo')!=_MODEL_NAME or manifest.get('revision')!=expected:
        raise ValueError('embedding snapshot identity does not match pinned revision')
    files=manifest.get('files')
    if not isinstance(files,dict) or not files or len(files)>1024 or 'model.safetensors' not in files:
        raise ValueError('embedding snapshot manifest incomplete')
    root=local.resolve();total=0
    for name,expected_hash in files.items():
        candidate=local/name
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
            raise ValueError('embedding manifest contains unsafe path')
        total+=candidate.stat().st_size
        if total>512*1024*1024:raise ValueError('embedding snapshot exceeds budget')
        digest=hashlib.sha256()
        with candidate.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
        if digest.hexdigest()!=expected_hash:raise ValueError('embedding snapshot checksum mismatch')


def _try_load_model():
    """
    Attempt to load the real sentence-transformers model. Returns None
    (and sets _model_load_failed) if it can't be loaded -- e.g. no
    network access to download weights on first run.
    """
    global _model_load_failed
    try:
        from sentence_transformers import SentenceTransformer

        local=Path(os.getenv("EMBEDDING_MODEL_PATH",str(Path(__file__).resolve().parents[1]/"models"/"minilm")))
        if local.is_dir():validate_local_snapshot(local)
        options = {'trust_remote_code': False, 'model_kwargs': {'use_safetensors': True}}
        model = (SentenceTransformer(str(local), local_files_only=True, **options) if local.is_dir()
                 else SentenceTransformer(_MODEL_NAME, revision=os.getenv("EMBEDDING_MODEL_REVISION", "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"), **options))
        return model
    except Exception as exc:  # noqa: BLE001 -- any failure means "use fallback"
        logger.warning(
            "Could not load %s (%s). Falling back to bag-of-words similarity "
            "for Stage 2 -- see README 'Known limitations'.",
            _MODEL_NAME,
            exc,
        )
        _model_load_failed = True
        return None


def get_model():
    """Lazily load and cache the embedding model (or None if unavailable)."""
    global _model
    with _model_lock:
        if _model is None and not _model_load_failed:
            _model = _try_load_model()
        return _model


def preload() -> None:
    """
    Eagerly load the model and anchor embeddings. Called once from
    main.py's startup event so the large one-time cost (13-70+ seconds
    observed in testing) happens at server boot, not on whichever
    request happens to be first. Safe to call multiple times --
    get_model()/get_anchor_embeddings() are already idempotent.
    """
    get_model()
    get_anchor_embeddings()


# ---------------------------------------------------------------------------
# Fallback: dependency-free bag-of-words cosine similarity.
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[a-zA-Z]+")


def _bow_vector(text: str) -> dict[str, int]:
    words = _WORD_RE.findall(text.lower())
    vec: dict[str, int] = {}
    for w in words:
        vec[w] = vec.get(w, 0) + 1
    return vec


def _bow_cosine(a: dict[str, int], b: dict[str, int]) -> float:
    if not a or not b:
        return 0.0
    shared = set(a) & set(b)
    dot = sum(a[w] * b[w] for w in shared)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Chunking for long spans.
# ---------------------------------------------------------------------------


def _chunk_text(text: str) -> list[str]:
    """
    Split `text` into overlapping word-windows if it's long enough to
    risk truncation by the embedding model. Short text is returned
    as a single-item list, unchanged -- this is a no-op for the
    overwhelming majority of spans (most comments/docstrings are far
    under the chunk size).
    """
    words = text.split()
    if len(words) <= _CHUNK_SIZE_WORDS:
        return [text]

    chunks = []
    start = 0
    step = _CHUNK_SIZE_WORDS - _CHUNK_OVERLAP_WORDS
    while start < len(words):
        end = start + _CHUNK_SIZE_WORDS
        chunks.append(" ".join(words[start:end]))
        if end >= len(words):
            break
        start += step
    return chunks


# ---------------------------------------------------------------------------
# Real embeddings: cosine similarity via numpy.
# ---------------------------------------------------------------------------


def get_anchor_embeddings():
    """
    Cache the anchor embeddings in memory -- see preload(), called
    eagerly at server startup so this doesn't happen on the first
    real request.
    """
    global _anchor_embeddings
    if _anchor_embeddings is not None:
        return _anchor_embeddings

    texts = _load_anchor_texts()
    model = get_model()
    if model is not None:
        _anchor_embeddings = ("model", model.encode(texts, convert_to_numpy=True))
    else:
        _anchor_embeddings = ("bow", [_bow_vector(t) for t in texts])
    return _anchor_embeddings


def max_similarity_to_anchors(text: str) -> float:
    """
    Returns the cosine similarity between `text` and its nearest
    "known injection" anchor example, in [0, 1]. Single-span
    convenience wrapper around batch_similarity_to_anchors -- prefer
    the batch version when scoring more than one span in the same
    request (see module docstring).
    """
    return batch_similarity_to_anchors([text])[0]


def batch_similarity_to_anchors(texts: list[str]) -> list[float]:
    """
    Same as max_similarity_to_anchors, but for many spans at once, and
    with chunking applied to any span long enough to risk truncation
    (see module docstring "Long-span chunking"). Each text's final
    score is the MAX similarity across its own chunks, so a suspicious
    sentence anywhere in a long span is caught.

    Returns a list of floats, same order and length as `texts`.
    """
    if not texts:
        return []

    kind, anchors = get_anchor_embeddings()
    if len(anchors) == 0:
        return [0.0] * len(texts)

    # Flatten every text's chunks into one big list for a single batch
    # call, remembering which chunks belong to which original text.
    all_chunks: list[str] = []
    owner_index: list[int] = []
    for i, text in enumerate(texts):
        for chunk in _chunk_text(text):
            all_chunks.append(chunk)
            owner_index.append(i)

    if kind == "model":
        import numpy as np

        model = get_model()
        vecs = model.encode(all_chunks, convert_to_numpy=True)
        anchors_arr = np.asarray(anchors)
        anchor_norms = np.linalg.norm(anchors_arr, axis=1)

        chunk_scores = []
        for v in vecs:
            v_norm = np.linalg.norm(v) or 1e-9
            sims = (anchors_arr @ v) / (anchor_norms * v_norm + 1e-9)
            chunk_scores.append(float(max(0.0, min(1.0, sims.max()))))
    else:
        chunk_scores = []
        for chunk in all_chunks:
            span_vec = _bow_vector(chunk)
            best = max(_bow_cosine(span_vec, a) for a in anchors)
            chunk_scores.append(max(0.0, min(1.0, best)))

    # Reduce chunk scores back to one score per original text (the max
    # across that text's chunks).
    results = [0.0] * len(texts)
    for score, owner in zip(chunk_scores, owner_index):
        if score > results[owner]:
            results[owner] = score
    return results


def combine_confidence(stage1_score: float, stage2_similarity: float, weights: Optional[dict] = None) -> float:
    """
    Fuse Stage 1's heuristic score with Stage 2's embedding similarity.

    NOT a plain weighted average -- that was the original design and
    real testing found a bug in it: when Stage 1 contributes 0 (the
    common case for injection attempts using wording our phrase list
    doesn't recognize), a 50/50 average cuts a perfectly good Stage 2
    signal in half, making Stage 3 escalation nearly unreachable for
    exactly the cases it exists to catch.

    Instead: take the stronger of the two signals, with a modest boost
    when both agree. When one stage is 0, this passes the other
    stage's signal through undiluted.
    """
    stronger = max(stage1_score, stage2_similarity)
    weaker = min(stage1_score, stage2_similarity)
    return round(min(1.0, stronger + 0.5 * weaker), 4)