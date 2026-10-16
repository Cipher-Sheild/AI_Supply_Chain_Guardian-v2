"""Read the versioned capability matrix bundled into this service."""
import json
from pathlib import Path
MATRIX = json.loads(Path(__file__).with_name("capabilities.json").read_text())
CODE_EXTENSIONS = set(MATRIX["code_extensions"])
ARTIFACT_TYPES = set(MATRIX["types"])


def supports(agent, artifact_type):
    return agent in MATRIX["types"].get(artifact_type, [])

def unsupported_path(path):
    name = (path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in MATRIX["unsupported_manifests"] or name in MATRIX["unsupported_workflows"] or any(name.endswith(ext) for ext in MATRIX["unsupported_code_extensions"])
