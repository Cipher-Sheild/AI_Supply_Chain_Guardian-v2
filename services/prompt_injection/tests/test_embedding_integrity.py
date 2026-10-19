import hashlib,json
import pytest
from app.embeddings import validate_local_snapshot


def snapshot(tmp_path):
    root=tmp_path/'minilm';root.mkdir()
    weights=root/'model.safetensors';weights.write_bytes(b'fixture-weights')
    metadata={'repo':'sentence-transformers/all-MiniLM-L6-v2','revision':'1110a243fdf4706b3f48f1d95db1a4f5529b4d41','files':{'model.safetensors':hashlib.sha256(weights.read_bytes()).hexdigest()}}
    (tmp_path/'embedding-manifest.json').write_text(json.dumps(metadata))
    return root


def test_modified_weights_are_rejected(tmp_path):
    root=snapshot(tmp_path);validate_local_snapshot(root)
    (root/'model.safetensors').write_bytes(b'modified')
    with pytest.raises(ValueError,match='checksum'):validate_local_snapshot(root)


def test_snapshot_path_escape_is_rejected(tmp_path):
    root=snapshot(tmp_path);manifest=tmp_path/'embedding-manifest.json'
    metadata=json.loads(manifest.read_text());metadata['files']['../outside']='a'*64
    manifest.write_text(json.dumps(metadata))
    with pytest.raises(ValueError,match='unsafe'):validate_local_snapshot(root)


def test_verified_local_model_disallows_pickle_and_remote_code(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace
    from app import embeddings
    root=snapshot(tmp_path)
    observed={}
    def construct(path, **kwargs):
        observed.update(kwargs)
        return object()
    monkeypatch.setenv('EMBEDDING_MODEL_PATH', str(root))
    monkeypatch.setitem(sys.modules, 'sentence_transformers', SimpleNamespace(SentenceTransformer=construct))
    assert embeddings._try_load_model() is not None
    assert observed == {'local_files_only': True, 'trust_remote_code': False,
                        'model_kwargs': {'use_safetensors': True}}
