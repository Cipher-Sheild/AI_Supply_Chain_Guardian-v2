import re
from typing import List, Optional, Set
from app.parsing.dockerfile_parser import DockerfileParser, DockerfileStage, DockerInstruction
from app.schema import Finding

SECRET_KEY_REGEX = re.compile(
    r'(?i)(api[_-]?key|secret|password|passwd|token|auth[_-]?token|private[_-]?key|aws[_-]?[a-z0-9_-]*key)\s*[:=\s]\s*["\']?[a-zA-Z0-9_\-.~!@#$%^&*()]{6,}',
    re.IGNORECASE
)
AWS_KEY_REGEX = re.compile(r'AKIA[0-9A-Z]{16}')

BUILD_TOOLS_PATTERNS = {"gcc", "g++", "make", "python3-dev", "build-essential", "gfortran", "cargo", "go"}
DANGEROUS_PORTS = {22, 23, 3389, 5432, 6379, 27017}
HARD_BLOCK_PORTS = {2375, 2376}  # Unencrypted Docker Daemon ports

STANDARD_BASE_IMAGES = {
    "ubuntu", "debian", "alpine", "python", "node", "golang", "rust", "nginx",
    "postgres", "redis", "busybox", "centos", "fedora", "amazonlinux", "archlinux"
}

def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class DockerfileRulesEngine:
    """
    Evaluates pure Python custom rules (DSG-D001 through DSG-D013) on a Dockerfile.
    """

    def __init__(self, allowlisted_registries: Optional[List[str]] = None):
        self.allowlisted_registries = allowlisted_registries or [
            "docker.io", "ghcr.io", "gcr.io", "ecr.aws", "quay.io"
        ]

    def evaluate(self, parser: DockerfileParser, file_path: str = "Dockerfile") -> List[Finding]:
        findings: List[Finding] = []

        if not parser.stages:
            return findings

        final_stage = parser.get_final_stage()

        # DSG-D001: Final stage runs as root
        if final_stage:
            user_insts = [i for i in final_stage.instructions if i.instruction == "USER"]
            if not user_insts:
                findings.append(
                    Finding(
                        detector_id="DSG-D001",
                        file_path=file_path,
                        line_number=final_stage.instructions[0].line_number,
                        preview="No USER instruction in final build stage",
                        confidence=1.0,
                        severity="high",
                        reason="Final container image runs as root user by default.",
                        remediation="Add a non-root USER instruction (e.g. USER 10001:10001 or USER appuser).",
                        sources=["custom:DSG-D001"],
                        category="privilege_escalation"
                    )
                )
            else:
                last_user = user_insts[-1].args.strip().lower()
                if last_user.split(':',1)[0] in {'root','0'}:
                    findings.append(
                        Finding(
                            detector_id="DSG-D001",
                            file_path=file_path,
                            line_number=user_insts[-1].line_number,
                            preview=f"USER {last_user}",
                            confidence=1.0,
                            severity="high",
                            reason="Final container stage explicitly switches to root user.",
                            remediation="Switch to a non-root user (e.g. USER appuser).",
                            sources=["custom:DSG-D001"],
                            category="privilege_escalation"
                        )
                    )

        # Iterate all stages for stage-level and instruction-level rules
        for stage in parser.stages:
            # DSG-D002: Base image untagged or latest
            tag = stage.base_image_tag.lower()
            if tag in ["latest", ""] or not tag:
                findings.append(
                    Finding(
                        detector_id="DSG-D002",
                        file_path=file_path,
                        line_number=stage.instructions[0].line_number,
                        preview=stage.instructions[0].args,
                        confidence=1.0,
                        severity="medium",
                        reason=f"Base image '{stage.base_image}' uses latest/unpinned tag.",
                        remediation="Pin base image to a specific immutable tag or digest (e.g., python:3.11-slim-bookworm).",
                        sources=["custom:DSG-D002"],
                        category="supply_chain"
                    )
                )

            # DSG-D012: Typosquat / lookalike base image detection
            img_name_only = stage.base_image.split('/')[-1]
            for std_img in STANDARD_BASE_IMAGES:
                if img_name_only != std_img:
                    dist = _levenshtein(img_name_only, std_img)
                    if dist == 1:
                        findings.append(
                            Finding(
                                detector_id="DSG-D012",
                                file_path=file_path,
                                line_number=stage.instructions[0].line_number,
                                preview=stage.base_image,
                                confidence=1.0,
                                severity="critical",
                                reason=f"Base image '{stage.base_image}' looks like a typosquatted version of standard image '{std_img}'.",
                                remediation=f"Verify if base image should be '{std_img}' instead.",
                                sources=["custom:DSG-D012"],
                                category="typosquatting",
                                hard_block=True
                            )
                        )
                        break

            # DSG-D013: Base image from non-allowlisted registry
            if "/" in stage.base_image and "." in stage.base_image.split("/")[0]:
                registry_domain = stage.base_image.split("/")[0].lower()
                if registry_domain.startswith("http:") or (
                    self.allowlisted_registries and registry_domain not in [r.lower() for r in self.allowlisted_registries]
                ):
                    findings.append(
                        Finding(
                            detector_id="DSG-D013",
                            file_path=file_path,
                            line_number=stage.instructions[0].line_number,
                            preview=stage.base_image,
                            confidence=0.9,
                            severity="high",
                            reason=f"Base image registry '{registry_domain}' is not in the allowlisted registries.",
                            remediation=f"Use approved registries ({', '.join(self.allowlisted_registries)}).",
                            sources=["custom:DSG-D013"],
                            category="untrusted_source"
                        )
                    )

            # Instruction-level analysis
            for inst in stage.instructions:
                text = inst.raw_text
                if inst.instruction=='ONBUILD':
                    findings.append(Finding(detector_id='DSG-D014',file_path=file_path,line_number=inst.line_number,
                        preview='ONBUILD '+inst.args[:80],confidence=.95,severity='high',
                        reason='Image defines a deferred build trigger that executes in downstream builds.',
                        remediation='Review deferred instructions and avoid inheriting unverified build triggers.',
                        sources=['custom:DSG-D014'],category='supply_chain'))

                # DSG-D003: Secret-like literals in ENV or ARG
                if inst.instruction in ["ENV", "ARG"]:
                    if SECRET_KEY_REGEX.search(inst.args) or AWS_KEY_REGEX.search(inst.args):
                        findings.append(
                            Finding(
                                detector_id="DSG-D003",
                                file_path=file_path,
                                line_number=inst.line_number,
                                preview=f"{inst.instruction} [REDACTED SECRET]",
                                confidence=0.95,
                                severity="critical",
                                reason=f"Hardcoded secret or credential detected in {inst.instruction} instruction.",
                                remediation="Do not embed secrets in Dockerfile build instructions. Use Docker build secrets or environment variables at runtime.",
                                sources=["custom:DSG-D003"],
                                category="secret_leak"
                            )
                        )

                # DSG-D004: Remote script execution (curl|sh, ADD http)
                if inst.instruction == "RUN":
                    if re.search(r'curl\s+[^|\n]*\|\s*(ba)?sh', inst.args, re.IGNORECASE) or \
                       re.search(r'wget\s+[^|\n]*\|\s*(ba)?sh', inst.args, re.IGNORECASE):
                        findings.append(
                            Finding(
                                detector_id="DSG-D004",
                                file_path=file_path,
                                line_number=inst.line_number,
                                preview=inst.args[:80],
                                confidence=1.0,
                                severity="high",
                                reason="Pipe to shell detected (curl | sh / wget | bash).",
                                remediation="Download script, verify integrity hash/checksum, and run locally.",
                                sources=["custom:DSG-D004"],
                                category="remote_code_execution"
                            )
                        )
                elif inst.instruction == "ADD":
                    if inst.args.startswith("http://") or inst.args.startswith("https://"):
                        findings.append(
                            Finding(
                                detector_id="DSG-D004",
                                file_path=file_path,
                                line_number=inst.line_number,
                                preview=inst.args[:80],
                                confidence=1.0,
                                severity="high",
                                reason="ADD with HTTP/HTTPS URL downloads unverified remote file.",
                                remediation="Use RUN curl/wget with explicit verification instead of ADD for remote URLs.",
                                sources=["custom:DSG-D004"],
                                category="remote_code_execution"
                            )
                        )

                # DSG-D005: TLS verification disabled
                if inst.instruction == "RUN":
                    if re.search(r'curl\s+-[k|K]|--insecure', inst.args) or \
                       re.search(r'wget\s+--no-check-certificate', inst.args) or \
                       'NODE_TLS_REJECT_UNAUTHORIZED=0' in inst.args or \
                       'PIP_TRUSTED_HOST' in inst.args or \
                       'strict-ssl false' in inst.args:
                        findings.append(
                            Finding(
                                detector_id="DSG-D005",
                                file_path=file_path,
                                line_number=inst.line_number,
                                preview=inst.args[:80],
                                confidence=1.0,
                                severity="high",
                                reason="TLS certificate verification explicitly disabled.",
                                remediation="Enable TLS verification and install required CA certificates.",
                                sources=["custom:DSG-D005"],
                                category="insecure_transport"
                            )
                        )

                # DSG-D006: Dangerous EXPOSE ports
                if inst.instruction == "EXPOSE":
                    ports = re.findall(r'\b\d+\b', inst.args)
                    for p_str in ports:
                        port_num = int(p_str)
                        if port_num in HARD_BLOCK_PORTS:
                            findings.append(
                                Finding(
                                    detector_id="DSG-D006",
                                    file_path=file_path,
                                    line_number=inst.line_number,
                                    preview=f"EXPOSE {port_num}",
                                    confidence=1.0,
                                    severity="critical",
                                    reason=f"Exposing Docker Daemon management port {port_num} exposes the host to immediate container escape.",
                                    remediation=f"Do not expose Docker socket or daemon port {port_num}.",
                                    sources=["custom:DSG-D006"],
                                    category="container_escape",
                                    hard_block=True
                                )
                            )
                        elif port_num in DANGEROUS_PORTS:
                            findings.append(
                                Finding(
                                    detector_id="DSG-D006",
                                    file_path=file_path,
                                    line_number=inst.line_number,
                                    preview=f"EXPOSE {port_num}",
                                    confidence=0.9,
                                    severity="high",
                                    reason=f"Exposing sensitive service port {port_num} directly in container.",
                                    remediation="Restrict port exposition or ensure service is protected behind authenticated proxy.",
                                    sources=["custom:DSG-D006"],
                                    category="exposed_service"
                                )
                            )

                # DSG-D007: Over-permissive permissions (chmod 777)
                if inst.instruction == "RUN":
                    if re.search(r'chmod\s+([a-z0-9+-=]*\s+)*(777|a\+rwx)', inst.args):
                        findings.append(
                            Finding(
                                detector_id="DSG-D007",
                                file_path=file_path,
                                line_number=inst.line_number,
                                preview=inst.args[:80],
                                confidence=1.0,
                                severity="high",
                                reason="World-writable permissions (chmod 777 / a+rwx) applied.",
                                remediation="Grant minimal required permissions (e.g., chmod 755 or 644).",
                                sources=["custom:DSG-D007"],
                                category="overpermissive_permissions"
                            )
                        )

                # DSG-D008: Remote access / admin tools installed in final stage
                if stage.is_final_stage and inst.instruction == "RUN":
                    if re.search(r'\b(openssh-server|sudo)\b', inst.args):
                        findings.append(
                            Finding(
                                detector_id="DSG-D008",
                                file_path=file_path,
                                line_number=inst.line_number,
                                preview=inst.args[:80],
                                confidence=0.95,
                                severity="high",
                                reason="Admin/remote access tool (openssh-server or sudo) installed in final production image.",
                                remediation="Do not include SSH daemon or sudo in production containers. Use `docker exec` for administrative tasks.",
                                sources=["custom:DSG-D008"],
                                category="unnecessary_services"
                            )
                        )

                # DSG-D009: COPY of credential files or COPY . .
                if inst.instruction == "COPY":
                    args_lower = inst.args.lower()
                    if re.search(r'\.(env|pem|key|pkcs12)|id_rsa|service-account\.json', args_lower):
                        findings.append(
                            Finding(
                                detector_id="DSG-D009",
                                file_path=file_path,
                                line_number=inst.line_number,
                                preview=inst.args,
                                confidence=0.95,
                                severity="high",
                                reason="COPY instruction copies credential or key files into image layer.",
                                remediation="Add sensitive credential files to .dockerignore.",
                                sources=["custom:DSG-D009"],
                                category="secret_leak"
                            )
                        )

                # DSG-D011: Build tools left in final image
                if stage.is_final_stage and inst.instruction == "RUN":
                    matched_tools = [tool for tool in BUILD_TOOLS_PATTERNS if re.search(rf'\b{tool}\b', inst.args)]
                    if matched_tools and "apt-get remove" not in inst.args and "apk del" not in inst.args:
                        findings.append(
                            Finding(
                                detector_id="DSG-D011",
                                file_path=file_path,
                                line_number=inst.line_number,
                                preview=inst.args[:80],
                                confidence=0.85,
                                severity="medium",
                                reason=f"Build tools ({', '.join(matched_tools)}) installed in final production image stage.",
                                remediation="Use a multi-stage build to compile assets and copy only final binaries to lightweight runtime image.",
                                sources=["custom:DSG-D011"],
                                category="bloat_attack_surface"
                            )
                        )

        # DSG-D010: Missing HEALTHCHECK in final stage
        if final_stage:
            healthcheck_insts = [i for i in final_stage.instructions if i.instruction == "HEALTHCHECK"]
            if not healthcheck_insts:
                findings.append(
                    Finding(
                        detector_id="DSG-D010",
                        file_path=file_path,
                        line_number=final_stage.instructions[0].line_number,
                        preview="No HEALTHCHECK instruction",
                        confidence=1.0,
                        severity="low",
                        reason="Missing HEALTHCHECK instruction in container image.",
                        remediation="Add HEALTHCHECK instruction (e.g. HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1).",
                        sources=["custom:DSG-D010"],
                        category="best_practices"
                    )
                )

        return findings
