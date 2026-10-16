import re
from typing import List, Dict, Any, Optional
from app.parsing.compose_parser import ComposeParser, ComposeService
from app.schema import Finding

DANGEROUS_HOST_PATHS = {"/", "/etc", "/proc", "/sys", "/root", "/boot", "/var/run", "/var"}
SENSITIVE_DB_PORTS = {5432, 3306, 6379, 27017, 9200, 27018, 1433}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH", "SYS_RAWIO"}

SECRET_PATTERN = re.compile(
    r'(?i)(api[_-]?key|secret|password|passwd|token|auth[_-]?token|private[_-]?key|aws[_-]?access|aws[_-]?secret)',
    re.IGNORECASE
)

class ComposeRulesEngine:
    """
    Evaluates custom security rules (DSG-C001 through DSG-C011) on docker-compose files.
    """

    def evaluate(self, parser: ComposeParser, file_path: str = "docker-compose.yml") -> List[Finding]:
        findings: List[Finding] = []

        if not parser.services:
            return findings

        for service in parser.services:
            s_name = service.name
            line_num = service.line_number

            # DSG-C001: privileged: true (HARD-BLOCK)
            if service.privileged:
                findings.append(
                    Finding(
                        detector_id="DSG-C001",
                        file_path=file_path,
                        line_number=line_num,
                        preview=f"service '{s_name}': privileged: true",
                        confidence=1.0,
                        severity="critical",
                        reason=f"Service '{s_name}' enables privileged mode, granting full host root capabilities and enabling container escape.",
                        remediation="Remove `privileged: true` and grant specific required Linux capabilities via `cap_add` instead.",
                        sources=["custom:DSG-C001"],
                        category="container_escape",
                        hard_block=True
                    )
                )

            # DSG-C002 & DSG-C003: Volume mounts (docker.sock HARD-BLOCK & host path mounts)
            for vol in service.volumes:
                vol_str = str(vol)
                host_part = str(vol.get('source','')) if isinstance(vol,dict) else vol_str.split(":")[0]

                # DSG-C002: docker.sock (HARD-BLOCK)
                if host_part in {'/var/run/docker.sock','/run/docker.sock'} or (host_part.startswith('/') and host_part.endswith('/docker.sock')):
                    findings.append(
                        Finding(
                            detector_id="DSG-C002",
                            file_path=file_path,
                            line_number=line_num,
                            preview=f"service '{s_name}': volume {vol_str}",
                            confidence=1.0,
                            severity="critical",
                            reason=f"Service '{s_name}' mounts host Docker socket (/var/run/docker.sock), allowing full root control over host Docker daemon.",
                            remediation="Avoid mounting Docker socket into containers. Use a dedicated proxy API or container management tool if required.",
                            sources=["custom:DSG-C002"],
                            category="container_escape",
                            hard_block=True
                        )
                    )

                # DSG-C003: Dangerous host mounts
                norm_host = host_part.rstrip("/") or "/"
                if norm_host in DANGEROUS_HOST_PATHS or norm_host.startswith(("/etc/", "/proc/", "/sys/", "/root/", "/boot/")):
                    findings.append(
                        Finding(
                            detector_id="DSG-C003",
                            file_path=file_path,
                            line_number=line_num,
                            preview=f"service '{s_name}': volume mount '{vol_str}'",
                            confidence=0.95,
                            severity="high",
                            reason=f"Service '{s_name}' mounts sensitive host path '{host_part}'.",
                            remediation="Mount isolated named volumes or specific non-sensitive subdirectories.",
                            sources=["custom:DSG-C003"],
                            category="host_isolation"
                        )
                    )

            # DSG-C004: Host namespaces (network_mode: host, pid: host, ipc: host)
            if service.network_mode == "host":
                findings.append(
                    Finding(
                        detector_id="DSG-C004",
                        file_path=file_path,
                        line_number=line_num,
                        preview=f"service '{s_name}': network_mode: host",
                        confidence=1.0,
                        severity="high",
                        reason=f"Service '{s_name}' uses host network namespace, bypassing network isolation.",
                        remediation="Use custom user-defined bridge networks.",
                        sources=["custom:DSG-C004"],
                        category="network_isolation"
                    )
                )
            if service.pid == "host":
                findings.append(
                    Finding(
                        detector_id="DSG-C004",
                        file_path=file_path,
                        line_number=line_num,
                        preview=f"service '{s_name}': pid: host",
                        confidence=1.0,
                        severity="high",
                        reason=f"Service '{s_name}' shares host PID namespace.",
                        remediation="Remove `pid: host` to preserve container process isolation.",
                        sources=["custom:DSG-C004"],
                        category="process_isolation"
                    )
                )
            if service.ipc == "host":
                findings.append(
                    Finding(
                        detector_id="DSG-C004",
                        file_path=file_path,
                        line_number=line_num,
                        preview=f"service '{s_name}': ipc: host",
                        confidence=1.0,
                        severity="high",
                        reason=f"Service '{s_name}' shares host IPC namespace.",
                        remediation="Remove `ipc: host`.",
                        sources=["custom:DSG-C004"],
                        category="process_isolation"
                    )
                )

            # DSG-C005: Dangerous Linux capabilities
            for cap in service.cap_add:
                cap_upper = str(cap).upper()
                if cap_upper in DANGEROUS_CAPS:
                    findings.append(
                        Finding(
                            detector_id="DSG-C005",
                            file_path=file_path,
                            line_number=line_num,
                            preview=f"service '{s_name}': cap_add [{cap_upper}]",
                            confidence=1.0,
                            severity="high",
                            reason=f"Service '{s_name}' adds dangerous capability '{cap_upper}'.",
                            remediation=f"Avoid adding capability {cap_upper} unless strictly required.",
                            sources=["custom:DSG-C005"],
                            category="capability_abuse"
                        )
                    )

            # DSG-C006: Security opt unconfined
            for s_opt in service.security_opt:
                opt_str = str(s_opt).lower()
                if "unconfined" in opt_str or "label:disable" in opt_str or "label=disable" in opt_str:
                    findings.append(
                        Finding(
                            detector_id="DSG-C006",
                            file_path=file_path,
                            line_number=line_num,
                            preview=f"service '{s_name}': security_opt [{opt_str}]",
                            confidence=1.0,
                            severity="high",
                            reason=f"Service '{s_name}' disables seccomp/apparmor/selinux security options ({opt_str}).",
                            remediation="Use default or custom hardened security profiles.",
                            sources=["custom:DSG-C006"],
                            category="security_profiles"
                        )
                    )

            # DSG-C007: No resource limits
            has_limits = False
            if service.deploy and isinstance(service.deploy, dict):
                limits = service.deploy.get("resources", {}).get("limits", {})
                if limits:
                    has_limits = True
            elif "mem_limit" in service.raw_dict or "cpus" in service.raw_dict:
                has_limits = True

            if not has_limits:
                findings.append(
                    Finding(
                        detector_id="DSG-C007",
                        file_path=file_path,
                        line_number=line_num,
                        preview=f"service '{s_name}': missing resource limits",
                        confidence=0.9,
                        severity="medium",
                        reason=f"Service '{s_name}' does not specify CPU/Memory resource limits.",
                        remediation="Define memory and CPU limits in `deploy.resources.limits` to prevent DoS.",
                        sources=["custom:DSG-C007"],
                        category="resilience"
                    )
                )

            # DSG-C008: Database ports published to host 0.0.0.0
            for port in service.ports:
                p_str = str(port)
                if isinstance(port,dict):
                    target=str(port.get('target',''))
                    host_ip=str(port.get('host_ip','0.0.0.0'))
                else:
                    parts=p_str.rsplit(':',2)
                    target=parts[-1].split('/',1)[0]
                    host_ip=parts[0] if len(parts)==3 else '0.0.0.0'
                if host_ip in {'127.0.0.1','::1','[::1]'} or host_ip.startswith('127.'):
                    continue
                match=re.fullmatch(r'(\d+)(?:-(\d+))?',target)
                if not match:continue
                first=int(match.group(1));last=int(match.group(2) or first)
                sensitive=next((number for number in SENSITIVE_DB_PORTS if first<=number<=last),None)
                if sensitive is not None:
                    findings.append(Finding(detector_id='DSG-C008',file_path=file_path,line_number=line_num,
                        preview=f"service '{s_name}': published target {target}",confidence=.95,severity='high',
                        reason=f"Service '{s_name}' publishes sensitive container port {sensitive} on a non-loopback interface.",
                        remediation='Bind published ports to loopback or restrict authenticated network access.',
                        sources=['custom:DSG-C008'],category='exposed_service'))
            # DSG-C009: Literal secrets in environment
            env_data = service.environment
            if env_data:
                env_items = []
                if isinstance(env_data, dict):
                    env_items = [f"{k}={v}" for k, v in env_data.items()]
                elif isinstance(env_data, list):
                    env_items = [str(item) for item in env_data]

                for item in env_items:
                    if "=" in item:
                        k, v = item.split("=", 1)
                        if v and not v.startswith("${") and SECRET_PATTERN.search(k):
                            findings.append(
                                Finding(
                                    detector_id="DSG-C009",
                                    file_path=file_path,
                                    line_number=line_num,
                                    preview=f"service '{s_name}': {k}=[REDACTED SECRET]",
                                    confidence=0.95,
                                    severity="critical",
                                    reason=f"Service '{s_name}' embeds literal secret in environment variable '{k}'.",
                                    remediation=f"Use environment variable expansion (e.g. {k}=${{{k}}}) or Compose secret files.",
                                    sources=["custom:DSG-C009"],
                                    category="secret_leak"
                                )
                            )

            # DSG-C010: image:latest / devices
            if service.image:
                img_tag = service.image.split(":")[-1] if ":" in service.image else "latest"
                if img_tag in ["latest", ""] or ":" not in service.image:
                    findings.append(
                        Finding(
                            detector_id="DSG-C010",
                            file_path=file_path,
                            line_number=line_num,
                            preview=f"service '{s_name}': image: '{service.image}'",
                            confidence=1.0,
                            severity="medium",
                            reason=f"Service '{s_name}' uses image with unpinned/latest tag.",
                            remediation="Pin service image to explicit version tag.",
                            sources=["custom:DSG-C010"],
                            category="supply_chain"
                        )
                    )
            if service.devices:
                findings.append(
                    Finding(
                        detector_id="DSG-C010",
                        file_path=file_path,
                        line_number=line_num,
                        preview=f"service '{s_name}': devices access",
                        confidence=0.9,
                        severity="medium",
                        reason=f"Service '{s_name}' mounts host device nodes.",
                        remediation="Restrict host device access.",
                        sources=["custom:DSG-C010"],
                        category="hardware_access"
                    )
                )

            # DSG-C011: Service runs as root / no read_only
            if service.user is None or service.user in ["root", "0", "0:0"]:
                findings.append(
                    Finding(
                        detector_id="DSG-C011",
                        file_path=file_path,
                        line_number=line_num,
                        preview=f"service '{s_name}': runs as root (user: {service.user or 'default root'})",
                        confidence=0.85,
                        severity="medium",
                        reason=f"Service '{s_name}' runs with root privileges.",
                        remediation="Specify a non-root `user:` in compose service definition.",
                        sources=["custom:DSG-C011"],
                        category="privilege_escalation"
                    )
                )

        return findings
