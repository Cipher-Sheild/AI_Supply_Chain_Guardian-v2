from app.parsing.dockerfile_parser import DockerfileParser
from app.schema import HardenedOutput
from app.engines.native import NativeDockerLint
from app.rules.dockerfile_rules import DockerfileRulesEngine

class DockerfileHardener:
    """Suggestions only. Re-linting does not prove a Docker build or runtime behavior."""
    def __init__(self, hadolint_engine=None, rules_engine=None):
        self.hadolint_engine=hadolint_engine or NativeDockerLint()
        self.rules_engine=rules_engine or DockerfileRulesEngine()

    def harden(self, original_content, original_findings_count=0):
        parser = DockerfileParser(original_content)
        final = parser.get_final_stage()
        lines = original_content.splitlines()
        applied = []
        if final:
            # Restrict transformations to the final stage, with its last effective USER.
            start = final.instructions[0].line_number - 1
            for i in range(start, len(lines)):
                line = lines[i]
                if "apt-get install" in line and "--no-install-recommends" not in line:
                    lines[i]=line.replace("apt-get install", "apt-get install --no-install-recommends")
                    applied.append("Suggested apt install without recommendations")
            users=[inst.args.strip().split(":")[0] for inst in final.instructions if inst.instruction == "USER"]
            nonroot=bool(users and users[-1].lower() not in {"root","0"})
            image=final.base_image.lower()
            alpine=image.split("/")[-1] == "alpine" or "alpine" in final.base_image_tag
            debian=image.split("/")[-1] in {"ubuntu","debian"} or "slim" in final.base_image_tag
            if not nonroot and not final.is_stage_alias and (alpine or debian) and "distroless" not in image:
                create="RUN addgroup -S appgroup && adduser -S -G appgroup appuser" if alpine else "RUN groupadd -r appgroup && useradd -r -g appgroup appuser"
                # Append after the last USER (and all RUNs); never insert in a builder.
                lines.extend(["# Suggested non-root runtime user; verify ownership and build",create,"USER appuser"])
                applied.append("Suggested final-stage non-root user")
        hardened="\n".join(lines)
        lint=self.hadolint_engine.analyze(hardened,"Dockerfile")
        rules=self.rules_engine.evaluate(DockerfileParser(hardened),"Dockerfile")
        remaining=len(lint.findings)+len(rules)
        return HardenedOutput(original=original_content,hardened=hardened,applied_rules=applied,
            verification_passed=False,verification_kind="suggested",remaining_findings_count=remaining,
            lint_completed=lint.completed,lint_improved=lint.completed and remaining < original_findings_count)
