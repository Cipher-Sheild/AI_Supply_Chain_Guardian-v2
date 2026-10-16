import asyncio
import shutil
import time
import os
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from app.schema import AgentResult
from app.contract import ArtifactRequest, AgentResult as PublicAgentResult
from app.capabilities import MATRIX as CAPABILITIES
from app.parsing import DockerfileParser, ComposeParser
from app.engines import HadolintEngine, TrivyConfigEngine, TrivyImageEngine
from app.engines.result import EngineResult
from app.engines.native import NativeDockerLint, NativeConfigCompletion
from app.rules import DockerfileRulesEngine, ComposeRulesEngine
from app.registry import BaseImageChecker
from app.normalize import FindingsNormalizer
from app.scoring import RiskScorer
from app.harden import DockerfileHardener

AGENT_NAME = "docker_security"
app = FastAPI(title="AI Supply Chain Guardian — Docker Security")
external_scanners = os.getenv("GUARDIAN_EXTERNAL_SCANNERS", "false").lower() == "true"
hadolint_engine = HadolintEngine() if external_scanners else NativeDockerLint()
trivy_config_engine = TrivyConfigEngine() if external_scanners else NativeConfigCompletion()
trivy_image_engine = TrivyImageEngine()
dockerfile_rules_engine = DockerfileRulesEngine()
compose_rules_engine = ComposeRulesEngine()
base_image_checker = BaseImageChecker()
dockerfile_hardener = DockerfileHardener(hadolint_engine, dockerfile_rules_engine)

@app.on_event('startup')
async def start_image_jobs():
    from app.image_jobs import start
    await start()

@app.on_event('shutdown')
async def stop_image_jobs():
    from app.image_jobs import stop
    await stop()

@app.get("/health")
async def health():
    from app.readiness import readiness
    return await readiness(AGENT_NAME)


@app.post("/analyze", response_model=PublicAgentResult)
async def analyze(payload: ArtifactRequest):
    started = time.perf_counter()
    content = payload.content
    path = payload.file_path or payload.filename or "Dockerfile"
    kind = payload.artifact_type or payload.type or "auto"
    if kind == "auto":
        kind = "compose" if path.lower().split("/")[-1] in CAPABILITIES["compose_filenames"] or ComposeParser.is_compose_content(content) else "dockerfile"
    if kind not in ("dockerfile", "compose"):
        return AgentResult(status="stub", coverage="none", unresolved=True, evidence={"reason": "unsupported artifact type"})
    engine_results = {}
    native_images=[]
    raw = []
    async def run(name, function, *args):
        try: result = await __import__("app.runtime",fromlist=["bounded_work"]).bounded_work(function, *args)
        except Exception as exc: result = EngineResult(False, type(exc).__name__)
        if not isinstance(result, EngineResult):
            result = EngineResult(False, "engine returned an invalid completion contract")
        engine_results[name] = result
        raw.extend(result.findings)
    try:
        if kind == "compose":
            parser = ComposeParser(content)
            if not parser.services: raise ValueError("Compose requires a nonempty services mapping")
            raw.extend(compose_rules_engine.evaluate(parser, path))
            if payload.options.get('enable_cve_scan',False):
                from app.registry.image_reference import ImageReference
                for service in parser.services:
                    if service.image:
                        try:
                            if not isinstance(service.image,str) or '$' in service.image:
                                raise ValueError('Compose image requires resolved variables')
                            ImageReference.parse(service.image)
                            if external_scanners:
                                await run('trivy_image:'+service.name,trivy_image_engine.scan_image,
                                          service.image,service.line_number,path)
                            else:native_images.append({'reference':service.image,'line':service.line_number})
                        except ValueError:
                            engine_results['image:'+service.name]=EngineResult(False,'Compose image reference unresolved')
                    else:
                        engine_results['image:'+service.name]=EngineResult(False,'Compose build image requires a supplied built image reference')
            await run("trivy_config" if external_scanners else "guardian_config", trivy_config_engine.analyze, content, path, True)
        else:
            parser = DockerfileParser(content)
            if not parser.stages: raise ValueError("Dockerfile requires FROM")
            raw.extend(dockerfile_rules_engine.evaluate(parser, path))
            tasks = [run("hadolint" if external_scanners else "guardian_lint", hadolint_engine.analyze, content, path),
                     run("trivy_config" if external_scanners else "guardian_config", trivy_config_engine.analyze, content, path, False)]
            for stage in parser.stages:
                if stage.is_stage_alias: continue
                if not (payload.options.get('enable_cve_scan',False) and not external_scanners and stage.base_image!='scratch'):
                    tasks.append(run(f"image_check:{stage.stage_index}", base_image_checker.check_image_exists,
                        stage.image_ref, "", stage.instructions[0].line_number, path))
                if payload.options.get("enable_cve_scan", False) and stage.base_image != "scratch":
                    if external_scanners:
                        tasks.append(run(f"trivy_image:{stage.stage_index}", trivy_image_engine.scan_image,
                            stage.image_ref, stage.instructions[0].line_number, path))
                    else:
                        native_images.append({'reference':stage.image_ref,'line':stage.instructions[0].line_number})
            await asyncio.gather(*tasks)
    except (ValueError, TypeError, AttributeError) as exc:
        return AgentResult(status="error", coverage="none", unresolved=True, evidence={"error": type(exc).__name__, "reason": "artifact could not be parsed"})
    findings = FindingsNormalizer.normalize_and_deduplicate(raw)
    risk, status, severity = RiskScorer.calculate_score(findings)
    incomplete = any(not result.completed for result in engine_results.values())
    hard_block = any(f.hard_block for f in findings)
    hardened = None
    if kind == "dockerfile" and payload.options.get("enable_hardening", True):
        try: hardened = await __import__("app.runtime",fromlist=["bounded_work"]).bounded_work(dockerfile_hardener.harden, content, len(findings))
        except Exception: pass  # Optional suggestion; never used as scan completion evidence.
    output = AgentResult(status="fail" if hard_block else "error" if incomplete else status,
        coverage="partial" if incomplete else "full", unresolved=incomplete,
        decision_floor="reject" if hard_block else "review" if incomplete else "accept", findings=findings,
        evidence={"artifact_type":kind,"scanner_backend":"external" if external_scanners else "guardian_native","engines_executed":["custom_rules",*engine_results],
            "engines":{name:result.evidence() for name,result in engine_results.items()},
            "raw_findings_count":len(raw),"total_findings":len(findings),"risk_score":risk,
            "severity":severity,"execution_time_ms":round((time.perf_counter()-started)*1000,2),
            "hardened_artifact":hardened.model_dump() if hardened else None})
    from app.redaction import redact
    public=PublicAgentResult.model_validate(redact(output.model_dump()))
    if native_images:
        try:
            from app.image_jobs import enqueue
            callback=enqueue(native_images,path,public.model_dump(mode='json'))
            return public.model_copy(update={'status':'pending','callback_id':callback,'coverage':'partial','unresolved':True,
                'decision_floor':'reject' if hard_block else 'review'})
        except Exception:
            return public.model_copy(update={'status':'fail' if hard_block else 'error','coverage':'partial','unresolved':True,
                'decision_floor':'reject' if hard_block else 'review',
                'evidence':{**public.evidence,'native_image_error':'Native image job could not be queued.'}})
    return public


from app.runtime import BoundsMiddleware
app.add_middleware(BoundsMiddleware)
