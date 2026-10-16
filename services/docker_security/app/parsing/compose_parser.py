import yaml
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class ComposeService:
    name: str
    image: Optional[str] = None
    build: Optional[Any] = None
    privileged: bool = False
    volumes: List[Any] = field(default_factory=list)
    ports: List[Any] = field(default_factory=list)
    network_mode: Optional[str] = None
    pid: Optional[str] = None
    ipc: Optional[str] = None
    cap_add: List[str] = field(default_factory=list)
    cap_drop: List[str] = field(default_factory=list)
    security_opt: List[str] = field(default_factory=list)
    deploy: Dict[str, Any] = field(default_factory=dict)
    environment: Any = None
    user: Optional[str] = None
    read_only: Optional[bool] = None
    devices: List[Any] = field(default_factory=list)
    raw_dict: Dict[str, Any] = field(default_factory=dict)
    line_number: int = 1

MAX_CONTENT_BYTES = 1 * 1024 * 1024  # 1MB limit

class ComposeParser:
    """
    Parses docker-compose.yml / compose.yaml content into structured service definitions.
    """

    def __init__(self, content: str):
        if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
            raise ValueError(f"Input Compose file size exceeds maximum allowed limit of {MAX_CONTENT_BYTES} bytes.")
        self.content = content
        self.data: Dict[str, Any] = {}
        self.services: List[ComposeService] = []
        self.is_valid_compose = False
        self._parse()

    def _parse(self):
        try:
            from app.bounded_yaml import load
            parsed = load(self.content)
            if isinstance(parsed, dict):
                self.data = parsed
                services_dict = parsed.get("services")
                if isinstance(services_dict, dict):
                    self.is_valid_compose = True
                    raw_lines = self.content.splitlines()

                    for s_name, s_data in services_dict.items():
                        if not isinstance(s_data, dict):
                            raise ValueError("service must be a mapping")

                        # Approximate line number by finding service name line
                        line_num = 1
                        for idx, l in enumerate(raw_lines):
                            if l.strip().startswith(f"{s_name}:"):
                                line_num = idx + 1
                                break

                        service = ComposeService(
                            name=s_name,
                            image=s_data.get("image"),
                            build=s_data.get("build"),
                            privileged=bool(s_data.get("privileged", False)),
                            volumes=s_data.get("volumes", []) or [],
                            ports=s_data.get("ports", []) or [],
                            network_mode=s_data.get("network_mode"),
                            pid=s_data.get("pid"),
                            ipc=s_data.get("ipc"),
                            cap_add=s_data.get("cap_add", []) or [],
                            cap_drop=s_data.get("cap_drop", []) or [],
                            security_opt=s_data.get("security_opt", []) or [],
                            deploy=s_data.get("deploy", {}) or {},
                            environment=s_data.get("environment"),
                            user=str(s_data.get("user")) if s_data.get("user") is not None else None,
                            read_only=s_data.get("read_only"),
                            devices=s_data.get("devices", []) or [],
                            raw_dict=s_data,
                            line_number=line_num
                        )
                        self.services.append(service)
        except Exception as exc:
            self.is_valid_compose = False
            self.services = []
            raise ValueError("Malformed Compose definition") from exc

    @staticmethod
    def is_compose_content(content: str) -> bool:
        """
        Quick heuristic to detect if content is a docker-compose file.
        """
        try:
            from app.bounded_yaml import load
            parsed = load(content)
            if isinstance(parsed, dict) and "services" in parsed and isinstance(parsed["services"], dict):
                return True
        except Exception:
            pass
        return False
