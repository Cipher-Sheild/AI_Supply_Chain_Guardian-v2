from dataclasses import dataclass
import re

@dataclass(frozen=True)
class ImageReference:
    original: str
    repository: str
    tag: str = "latest"
    digest: str | None = None
    registry: str = "docker.io"

    @classmethod
    def parse(cls, reference):
        if not reference or reference.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_$][A-Za-z0-9_$./:@{}-]*", reference):
            raise ValueError("invalid image reference")
        name, sep, digest = reference.partition("@")
        if sep and not re.fullmatch(r"sha256:[a-fA-F0-9]{64}", digest):
            raise ValueError("invalid image digest")
        slash = name.rfind("/")
        colon = name.rfind(":")
        tag = "latest"
        if colon > slash:
            name, tag = name[:colon], name[colon+1:]
            if not tag: raise ValueError("empty image tag")
        first = name.split("/")[0]
        registry = first if "/" in name and ("." in first or ":" in first or first == "localhost") else "docker.io"
        return cls(reference, name, tag, digest if sep else None, registry)
