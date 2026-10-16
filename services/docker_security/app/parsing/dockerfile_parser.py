import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class DockerInstruction:
    instruction: str  # e.g., "FROM", "RUN", "USER", "COPY", "ENV", "EXPOSE", "HEALTHCHECK"
    args: str         # e.g., "ubuntu:latest AS builder" or "npm install"
    line_number: int  # 1-indexed
    raw_text: str

@dataclass
class DockerfileStage:
    stage_index: int
    stage_name: Optional[str]
    base_image: str
    base_image_tag: str
    instructions: List[DockerInstruction] = field(default_factory=list)
    is_final_stage: bool = False
    image_ref: str = ""
    is_stage_alias: bool = False

MAX_CONTENT_BYTES = 1 * 1024 * 1024  # 1MB limit

class DockerfileParser:
    """
    Parses a Dockerfile string into structured stages and instructions.
    Handles line continuations (\\) and multi-stage builds.
    """

    def __init__(self, content: str):
        if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
            raise ValueError(f"Input Dockerfile size exceeds maximum allowed limit of {MAX_CONTENT_BYTES} bytes.")
        self.content = content
        self.raw_lines = content.splitlines()
        self.instructions: List[DockerInstruction] = []
        self.stages: List[DockerfileStage] = []
        self._parse()

    def _parse(self):
        current_instruction = None
        current_args = []
        start_line = 1
        current_raw = []

        lines = self.raw_lines
        i = 0
        while i < len(lines):
            line_num = i + 1
            line = lines[i]
            stripped = line.strip()

            # Skip comments and empty lines if not continuing a previous instruction
            if not current_instruction and (not stripped or stripped.startswith('#')):
                i += 1
                continue

            # Remove trailing comments if not quoted, but keep command
            clean_line = line
            if '#' in clean_line and not current_instruction:
                # simple comment strip unless inside quotes
                comment_idx = clean_line.find('#')
                if comment_idx == 0:
                    i += 1
                    continue

            if not current_instruction:
                # Find instruction keyword
                match = re.match(r'^\s*([A-Z]+)\s+(.*)$', clean_line, re.IGNORECASE)
                if match:
                    instruction_kw = match.group(1).upper()
                    rest = match.group(2)
                    current_instruction = instruction_kw
                    start_line = line_num
                    current_raw = [line]

                    if rest.endswith('\\'):
                        current_args.append(rest[:-1].strip())
                    else:
                        current_args.append(rest.strip())
                        self.instructions.append(
                            DockerInstruction(
                                instruction=current_instruction,
                                args=" ".join(current_args),
                                line_number=start_line,
                                raw_text="\n".join(current_raw)
                            )
                        )
                        current_instruction = None
                        current_args = []
                        current_raw = []
                else:
                    i += 1
                    continue
            else:
                current_raw.append(line)
                if stripped.endswith('\\'):
                    current_args.append(stripped[:-1].strip())
                else:
                    current_args.append(stripped)
                    self.instructions.append(
                        DockerInstruction(
                            instruction=current_instruction,
                            args=" ".join(current_args),
                            line_number=start_line,
                            raw_text="\n".join(current_raw)
                        )
                    )
                    current_instruction = None
                    current_args = []
                    current_raw = []
            i += 1

        if current_instruction and current_args:
            self.instructions.append(
                DockerInstruction(
                    instruction=current_instruction,
                    args=" ".join(current_args),
                    line_number=start_line,
                    raw_text="\n".join(current_raw)
                )
            )

        self._build_stages()

    def _build_stages(self):
        current_stage: Optional[DockerfileStage] = None
        stage_idx = 0

        for inst in self.instructions:
            if inst.instruction == "FROM":
                if current_stage:
                    self.stages.append(current_stage)

                # Parse FROM image [AS name]
                args = inst.args
                # handle flags like --platform=linux/amd64
                args_clean = re.sub(r'--[a-zA-Z0-9_-]+=\S+\s*', '', args).strip()
                parts = args_clean.split()
                image_ref = parts[0] if parts else "scratch"

                stage_name = None
                if len(parts) >= 3 and parts[1].upper() == "AS":
                    stage_name = parts[2]

                from app.registry.image_reference import ImageReference
                ref = ImageReference.parse(image_ref)
                base_image, tag = ref.repository, ref.digest or ref.tag
                aliases = {stage.stage_name.lower() for stage in self.stages if stage.stage_name}
                is_alias = image_ref.lower() in aliases or (image_ref.isdigit() and int(image_ref) < stage_idx)

                current_stage = DockerfileStage(
                    stage_index=stage_idx,
                    stage_name=stage_name,
                    base_image=base_image,
                    base_image_tag=tag,
                    instructions=[inst], image_ref=image_ref, is_stage_alias=is_alias
                )
                stage_idx += 1
            else:
                if current_stage:
                    current_stage.instructions.append(inst)

        if current_stage:
            self.stages.append(current_stage)

        if self.stages:
            self.stages[-1].is_final_stage = True

    def get_final_stage(self) -> Optional[DockerfileStage]:
        return self.stages[-1] if self.stages else None
