"""Guardian-owned Dockerfile linting; no subprocesses or downloaded scanners.

Configuration rules are evaluated separately. Image CVEs require package inventory
and advisory data and are never inferred from a Dockerfile tag.
"""
import re
import time
from app.engines.result import EngineResult
from app.parsing import DockerfileParser
from app.schema import Finding


class NativeDockerLint:
    def analyze(self, content, file_path="Dockerfile"):
        started = time.perf_counter()
        findings = []
        def emit(inst, code, severity, reason, remediation):
            findings.append(Finding(detector_id=code, file_path=file_path,
                line_number=inst.line_number, preview=inst.instruction,
                severity=severity, confidence=0.95, reason=reason,
                remediation=remediation, sources=["guardian:native-docker"],
                category="docker_security"))
        try:
            parser = DockerfileParser(content)
            if not parser.stages:
                raise ValueError("FROM required")
            known = {"FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV",
                     "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR",
                     "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL"}
            for inst in parser.instructions:
                args = inst.args
                if inst.instruction not in known:
                    raise ValueError("unknown Dockerfile instruction")
                if "<<" in args:
                    return EngineResult(False, "heredoc analysis not implemented", findings=findings)
                if inst.instruction == "WORKDIR" and not args.startswith(("/", "$")):
                    emit(inst,"GDL001","medium","Relative WORKDIR depends on inherited state.","Use an absolute WORKDIR.")
                if inst.instruction == "RUN":
                    if re.search(r"\bapt(?:-get)?\s+update\b",args) and not re.search(r"\bapt(?:-get)?\s+install\b",args):
                        emit(inst,"GDL002","medium","Package index update is separated from installation.","Update and install in the same RUN instruction.")
                    if re.search(r"\bapt(?:-get)?\s+install\b",args):
                        if "--no-install-recommends" not in args:
                            emit(inst,"GDL003","low","Recommended packages expand the image attack surface.","Add --no-install-recommends.")
                        if "/var/lib/apt/lists" not in args:
                            emit(inst,"GDL004","low","Package indexes remain in the image layer.","Remove /var/lib/apt/lists/* in the same instruction.")
                    if re.search(r"\bapk\s+add\b",args) and "--no-cache" not in args:
                        emit(inst,"GDL005","low","APK cache is retained.","Use apk add --no-cache.")
                    if re.search(r"\b(?:apt-get|apk|yum|dnf)\s+upgrade\b",args):
                        emit(inst,"GDL006","medium","Unbounded system upgrades reduce build reproducibility.","Update the pinned base image and pin required packages.")
                if inst.instruction in {"CMD","ENTRYPOINT"} and not args.startswith("["):
                    emit(inst,"GDL007","low","Shell-form startup may interfere with signal delivery.","Use JSON exec form or explicitly forward signals.")
                if inst.instruction == "ADD" and not args.lstrip().startswith("--checksum="):
                    emit(inst,"GDL008","low","ADD has implicit extraction and download behavior.","Prefer COPY for local files; verify remote downloads.")
            # The lightweight parser must not silently discard malformed physical lines.
            covered = set()
            for inst in parser.instructions:
                covered.update(range(inst.line_number,inst.line_number+len(inst.raw_text.splitlines())))
            if any(i not in covered and line.strip() and not line.lstrip().startswith("#")
                   for i,line in enumerate(content.splitlines(),1)):
                return EngineResult(False,"unparsed Dockerfile lines",findings=findings)
        except (ValueError, TypeError) as exc:
            return EngineResult(False,str(exc),findings=findings)
        return EngineResult(True,duration_ms=(time.perf_counter()-started)*1000,findings=findings)


class NativeConfigCompletion:
    """Completion evidence for Guardian's separately executed configuration rules."""
    def analyze(self, content, file_path="Dockerfile", is_compose=False):
        return EngineResult(True)
