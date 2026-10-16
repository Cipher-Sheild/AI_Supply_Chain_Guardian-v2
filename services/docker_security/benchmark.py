# # # import time
# # # import json
# # # from typing import Dict, Any, List
# # # from app.parsing import DockerfileParser, ComposeParser
# # # from app.engines import HadolintEngine, TrivyConfigEngine, TrivyImageEngine
# # # from app.rules import DockerfileRulesEngine, ComposeRulesEngine
# # # from app.registry import BaseImageChecker
# # # from app.normalize import FindingsNormalizer
# # # from app.scoring import RiskScorer
# # # from app.harden import DockerfileHardener
# # # from app.cache import cache_instance

# # # BENCHMARK_FIXTURES = [
# # #     {
# # #         "name": "Scenario 1: LLM-Generated Bad Dockerfile (Root + Secrets + Untagged)",
# # #         "type": "dockerfile",
# # #         "content": """
# # # FROM ubuntu:latest
# # # ENV AWS_SECRET_ACCESS_KEY="AKIA1234567890abcdef"
# # # RUN apt-get update && apt-get install -y gcc openssh-server
# # # RUN curl http://example.com/install.sh | sh
# # # RUN chmod 777 /app/run.sh
# # # EXPOSE 2375
# # # CMD ["/app/run.sh"]
# # # """
# # #     },
# # #     {
# # #         "name": "Scenario 2: Typosquatted Base Image Dockerfile (ubunntu)",
# # #         "type": "dockerfile",
# # #         "content": """
# # # FROM ubunntu:22.04
# # # USER appuser
# # # CMD ["python", "app.py"]
# # # """
# # #     },
# # #     {
# # #         "name": "Scenario 3: Vulnerable Compose File (Privileged + Sock Mount)",
# # #         "type": "compose",
# # #         "content": """
# # # version: '3.8'
# # # services:
# # #   web:
# # #     image: nginx:latest
# # #     ports:
# # #       - "80:80"
# # #   agent:
# # #     image: custom-agent:latest
# # #     privileged: true
# # #     volumes:
# # #       - /var/run/docker.sock:/var/run/docker.sock
# # #       - /etc:/etc
# # #     network_mode: host
# # #     ports:
# # #       - "5432:5432"
# # #     environment:
# # #       - DB_PASSWORD=SuperSecretPass123!
# # # """
# # #     },
# # #     {
# # #         "name": "Scenario 4: Clean Multi-stage Hardened Dockerfile",
# # #         "type": "dockerfile",
# # #         "content": """
# # # FROM python:3.11-slim-bookworm AS builder
# # # WORKDIR /app
# # # COPY requirements.txt .
# # # RUN pip install --no-cache-dir -r requirements.txt

# # # FROM python:3.11-slim-bookworm
# # # WORKDIR /app
# # # RUN groupadd -r app && useradd -r -g app appuser
# # # COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
# # # COPY . .
# # # USER appuser
# # # HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health || exit 1
# # # CMD ["python", "app.py"]
# # # """
# # #     }
# # # ]

# # # def run_benchmark():
# # #     hadolint = HadolintEngine()
# # #     trivy_config = TrivyConfigEngine()
# # #     trivy_image = TrivyImageEngine(timeout_sec=5.0)
# # #     df_rules = DockerfileRulesEngine()
# # #     c_rules = ComposeRulesEngine()
# # #     img_checker = BaseImageChecker()
# # #     hardener = DockerfileHardener()

# # #     print("=" * 120)
# # #     print("      AI SUPPLY CHAIN GUARDIAN — DOCKER SECURITY AGENT BENCHMARK & PROVENANCE EVALUATION")
# # #     print("=" * 120)

# # #     total_hadolint = 0
# # #     total_trivy = 0
# # #     total_custom = 0
# # #     total_raw = 0
# # #     total_deduped = 0

# # #     for idx, fix in enumerate(BENCHMARK_FIXTURES, 1):
# # #         name = fix["name"]
# # #         content = fix["content"]
# # #         art_type = fix["type"]

# # #         print(f"\n--- {name} ---")

# # #         t0 = time.perf_counter()

# # #         # Timing tracking
# # #         t_parse = 0.0
# # #         t_hadolint = 0.0
# # #         t_trivy_cfg = 0.0
# # #         t_custom = 0.0
# # #         t_reg = 0.0

# # #         h_findings = []
# # #         t_findings = []
# # #         c_findings = []
# # #         exist_findings = []

# # #         if art_type == "dockerfile":
# # #             tp_start = time.perf_counter()
# # #             parser = DockerfileParser(content)
# # #             t_parse = (time.perf_counter() - tp_start) * 1000.0

# # #             th_start = time.perf_counter()
# # #             h_findings = hadolint.analyze(content)
# # #             t_hadolint = (time.perf_counter() - th_start) * 1000.0

# # #             tt_start = time.perf_counter()
# # #             t_findings = trivy_config.analyze(content, is_compose=False)
# # #             t_trivy_cfg = (time.perf_counter() - tt_start) * 1000.0

# # #             tc_start = time.perf_counter()
# # #             c_findings = df_rules.evaluate(parser)
# # #             t_custom = (time.perf_counter() - tc_start) * 1000.0

# # #             tr_start = time.perf_counter()
# # #             for stage in parser.stages:
# # #                 ef = img_checker.check_image_exists(stage.base_image, stage.base_image_tag)
# # #                 exist_findings.extend(ef)
# # #             t_reg = (time.perf_counter() - tr_start) * 1000.0
# # #         else:
# # #             tp_start = time.perf_counter()
# # #             c_parser = ComposeParser(content)
# # #             t_parse = (time.perf_counter() - tp_start) * 1000.0

# # #             tt_start = time.perf_counter()
# # #             t_findings = trivy_config.analyze(content, is_compose=True)
# # #             t_trivy_cfg = (time.perf_counter() - tt_start) * 1000.0

# # #             tc_start = time.perf_counter()
# # #             c_findings = c_rules.evaluate(c_parser)
# # #             t_custom = (time.perf_counter() - tc_start) * 1000.0

# # #         raw_all = h_findings + t_findings + c_findings + exist_findings
# # #         deduped = FindingsNormalizer.normalize_and_deduplicate(raw_all)
# # #         score, status, max_sev = RiskScorer.calculate_score(deduped)

# # #         total_elapsed = (time.perf_counter() - t0) * 1000.0

# # #         total_hadolint += len(h_findings)
# # #         total_trivy += len(t_findings)
# # #         total_custom += len(c_findings)
# # #         total_raw += len(raw_all)
# # #         total_deduped += len(deduped)

# # #         print(f"  Stage Latency Breakdown : Parse={t_parse:.2f}ms | Hadolint={t_hadolint:.2f}ms | TrivyConfig={t_trivy_cfg:.2f}ms | CustomRules={t_custom:.2f}ms | RegistryCheck={t_reg:.2f}ms")
# # #         print(f"  Total Stage Execution   : {total_elapsed:.2f}ms")
# # #         print(f"  Finding Counts          : Raw = {len(raw_all)} -> Deduplicated = {len(deduped)} (Merged {len(raw_all) - len(deduped)} overlapping findings)")
# # #         print(f"  Score & Status          : {score}/100 ({status.upper()}) | Max Severity = {max_sev.upper()}")

# # #         print("\n  Detailed Deduplication Mapping (Sample Merges):")
# # #         for f in deduped:
# # #             if len(f.sources) > 1:
# # #                 print(f"    - [Line {f.line_number}] Canonical ID '{f.detector_id}' merged {len(f.sources)} sources: {f.sources}")

# # #     print("\n" + "=" * 120)
# # #     print("      COLD VS WARM TRIVY IMAGE CVE SCAN LATENCY BENCHMARK")
# # #     print("=" * 120)

# # #     test_img = "alpine:3.18.0"
# # #     cache_instance.set(f"trivy_image_cve:{test_img}", None)

# # #     t_cold0 = time.perf_counter()
# # #     cold_vulns = trivy_image.scan_image(test_img)
# # #     t_cold = (time.perf_counter() - t_cold0) * 1000.0

# # #     t_warm0 = time.perf_counter()
# # #     warm_vulns = trivy_image.scan_image(test_img)
# # #     t_warm = (time.perf_counter() - t_warm0) * 1000.0

# # #     print(f"  Image: {test_img}")
# # #     print(f"  Cold CVE Scan (Cache Miss) : {t_cold:.2f} ms")
# # #     print(f"  Warm CVE Scan (Cache Hit)  : {t_warm:.2f} ms")
# # #     print(f"  Performance Speedup Factor : {t_cold / max(t_warm, 0.001):.1f}x faster on warm hit")
# # #     print("=" * 120)

# # # if __name__ == "__main__":
# # #     run_benchmark()
# # import time
# # import asyncio
# # from app.main import analyze
# # from app.cache import cache_instance
# # from app.engines import TrivyImageEngine

# # BENCHMARK_FIXTURES = [
# #     {
# #         "name": "Scenario 1: LLM-Generated Bad Dockerfile (Root + Secrets + Untagged)",
# #         "type": "dockerfile",
# #         "content": """
# # FROM ubuntu:latest
# # ENV AWS_SECRET_ACCESS_KEY="AKIA1234567890abcdef"
# # RUN apt-get update && apt-get install -y gcc openssh-server
# # RUN curl http://example.com/install.sh | sh
# # RUN chmod 777 /app/run.sh
# # EXPOSE 2375
# # CMD ["/app/run.sh"]
# # """
# #     },
# #     {
# #         "name": "Scenario 2: Typosquatted Base Image Dockerfile (ubunntu)",
# #         "type": "dockerfile",
# #         "content": """
# # FROM ubunntu:22.04
# # USER appuser
# # CMD ["python", "app.py"]
# # """
# #     },
# #     {
# #         "name": "Scenario 3: Vulnerable Compose File (Privileged + Sock Mount)",
# #         "type": "compose",
# #         "content": """
# # version: '3.8'
# # services:
# #   web:
# #     image: nginx:latest
# #     ports:
# #       - "80:80"
# #   agent:
# #     image: custom-agent:latest
# #     privileged: true
# #     volumes:
# #       - /var/run/docker.sock:/var/run/docker.sock
# #       - /etc:/etc
# #     network_mode: host
# #     ports:
# #       - "5432:5432"
# #     environment:
# #       - DB_PASSWORD=SuperSecretPass123!
# # """
# #     },
# #     {
# #         "name": "Scenario 4: Clean Multi-stage Hardened Dockerfile",
# #         "type": "dockerfile",
# #         "content": """
# # FROM python:3.11-slim-bookworm AS builder
# # WORKDIR /app
# # COPY requirements.txt .
# # RUN pip install --no-cache-dir -r requirements.txt

# # FROM python:3.11-slim-bookworm
# # WORKDIR /app
# # RUN groupadd -r app && useradd -r -g app appuser
# # COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
# # COPY . .
# # USER appuser
# # HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health || exit 1
# # CMD ["python", "app.py"]
# # """
# #     }
# # ]


# # async def run_one(fixture: dict) -> None:
# #     payload = {
# #         "content": fixture["content"],
# #         "artifact_type": fixture["type"],
# #         "file_path": "docker-compose.yml" if fixture["type"] == "compose" else "Dockerfile",
# #         "options": {"enable_cve_scan": False, "enable_hardening": True},
# #     }

# #     wall_start = time.perf_counter()
# #     result = await analyze(payload)   # <-- calls the REAL production handler, real asyncio.gather concurrency
# #     wall_elapsed = (time.perf_counter() - wall_start) * 1000.0

# #     print(f"\n--- {fixture['name']} ---")
# #     tb = result.evidence.get("timing_breakdown_ms", {})
# #     print(f"  Reported Timing Breakdown : {tb}")
# #     print(f"  Measured Wall Clock       : {wall_elapsed:.2f}ms  (should track near the SLOWEST reported stage, not their sum)")
# #     print(f"  Finding Counts            : Raw = {result.evidence['raw_findings_count']} -> "
# #           f"Deduplicated = {result.evidence['deduplicated_count']} "
# #           f"(Merged {result.evidence['raw_findings_count'] - result.evidence['deduplicated_count']} findings)")
# #     print(f"  Score & Status            : {result.risk_score}/100 ({result.status.upper()}) | Max Severity = {result.severity.upper()}")

# #     print("\n  Full deduplicated findings:")
# #     for f in result.findings:
# #         tag = f" <- MERGED {f.sources}" if len(f.sources) > 1 else ""
# #         print(f"    - [Line {f.line_number}] {f.detector_id} ({f.severity}){tag}")


# # async def run_benchmark():
# #     print("=" * 120)
# #     print("      AI SUPPLY CHAIN GUARDIAN — DOCKER SECURITY AGENT BENCHMARK (via real /analyze handler)")
# #     print("=" * 120)

# #     for fixture in BENCHMARK_FIXTURES:
# #         await run_one(fixture)

# #     print("\n" + "=" * 120)
# #     print("      COLD VS WARM TRIVY IMAGE CVE SCAN LATENCY BENCHMARK")
# #     print("=" * 120)

# #     trivy_image = TrivyImageEngine(timeout_sec=5.0)
# #     test_img = "alpine:3.18.0"
# #     cache_instance.set(f"trivy_image_cve:{test_img}", None)

# #     t_cold0 = time.perf_counter()
# #     trivy_image.scan_image(test_img)
# #     t_cold = (time.perf_counter() - t_cold0) * 1000.0

# #     t_warm0 = time.perf_counter()
# #     trivy_image.scan_image(test_img)
# #     t_warm = (time.perf_counter() - t_warm0) * 1000.0

# #     print(f"  Image: {test_img}")
# #     print(f"  Cold CVE Scan (Cache Miss) : {t_cold:.2f} ms")
# #     print(f"  Warm CVE Scan (Cache Hit)  : {t_warm:.2f} ms")
# #     print(f"  Performance Speedup Factor : {t_cold / max(t_warm, 0.001):.1f}x faster on warm hit")
# #     print("=" * 120)


# # if __name__ == "__main__":
# #     asyncio.run(run_benchmark())
# import time
# import asyncio
# from app.main import analyze
# from app.cache import cache_instance
# from app.engines import TrivyImageEngine

# BENCHMARK_FIXTURES = [
#     {
#         "name": "Scenario 1: LLM-Generated Bad Dockerfile (Root + Secrets + Untagged)",
#         "type": "dockerfile",
#         "content": """
# FROM ubuntu:latest
# ENV AWS_SECRET_ACCESS_KEY="AKIA1234567890abcdef"
# RUN apt-get update && apt-get install -y gcc openssh-server
# RUN curl http://example.com/install.sh | sh
# RUN chmod 777 /app/run.sh
# EXPOSE 2375
# CMD ["/app/run.sh"]
# """
#     },
#     {
#         "name": "Scenario 2: Typosquatted Base Image Dockerfile (ubunntu)",
#         "type": "dockerfile",
#         "content": """
# FROM ubunntu:22.04
# USER appuser
# CMD ["python", "app.py"]
# """
#     },
#     {
#         "name": "Scenario 3: Vulnerable Compose File (Privileged + Sock Mount)",
#         "type": "compose",
#         "content": """
# version: '3.8'
# services:
#   web:
#     image: nginx:latest
#     ports:
#       - "80:80"
#   agent:
#     image: custom-agent:latest
#     privileged: true
#     volumes:
#       - /var/run/docker.sock:/var/run/docker.sock
#       - /etc:/etc
#     network_mode: host
#     ports:
#       - "5432:5432"
#     environment:
#       - DB_PASSWORD=SuperSecretPass123!
# """
#     },
#     {
#         "name": "Scenario 4: Clean Multi-stage Hardened Dockerfile",
#         "type": "dockerfile",
#         "content": """
# FROM python:3.11-slim-bookworm AS builder
# WORKDIR /app
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# FROM python:3.11-slim-bookworm
# WORKDIR /app
# RUN groupadd -r app && useradd -r -g app appuser
# COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
# COPY . .
# USER appuser
# HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health || exit 1
# CMD ["python", "app.py"]
# """
#     }
# ]


# async def run_one(fixture: dict) -> None:
#     payload = {
#         "content": fixture["content"],
#         "artifact_type": fixture["type"],
#         "file_path": "docker-compose.yml" if fixture["type"] == "compose" else "Dockerfile",
#         "options": {"enable_cve_scan": False, "enable_hardening": True},
#     }

#     wall_start = time.perf_counter()
#     # Calls the REAL production handler from main.py -- same asyncio.gather
#     # concurrency a live request goes through. This replaces the old approach
#     # of calling each engine directly and summing separately-timed blocks,
#     # which was mathematically guaranteed to equal a serial sum.
#     result = await analyze(payload)
#     wall_elapsed = (time.perf_counter() - wall_start) * 1000.0

#     print(f"\n--- {fixture['name']} ---")
#     tb = result.evidence.get("timing_breakdown_ms", {})
#     print(f"  Reported Timing Breakdown : {tb}")
#     print(f"  Measured Wall Clock       : {wall_elapsed:.2f}ms  "
#           f"(should track near the SLOWEST reported stage, not their sum)")
#     raw_count = result.evidence["raw_findings_count"]
#     dedup_count = result.evidence["deduplicated_count"]
#     print(f"  Finding Counts            : Raw = {raw_count} -> Deduplicated = {dedup_count} "
#           f"(Merged {raw_count - dedup_count} findings)")
#     print(f"  Score & Status            : {result.risk_score}/100 ({result.status.upper()}) "
#           f"| Max Severity = {result.severity.upper()}")

#     print("\n  Full deduplicated findings:")
#     for f in result.findings:
#         tag = f" <- MERGED {f.sources}" if len(f.sources) > 1 else ""
#         print(f"    - [Line {f.line_number}] {f.detector_id} ({f.severity}){tag}")


# async def run_benchmark():
#     print("=" * 120)
#     print("      AI SUPPLY CHAIN GUARDIAN — DOCKER SECURITY AGENT BENCHMARK (via real /analyze handler)")
#     print("=" * 120)

#     for fixture in BENCHMARK_FIXTURES:
#         await run_one(fixture)

#     print("\n" + "=" * 120)
#     print("      COLD VS WARM TRIVY IMAGE CVE SCAN LATENCY BENCHMARK")
#     print("=" * 120)

#     trivy_image = TrivyImageEngine(timeout_sec=5.0)
#     test_img = "alpine:3.18.0"
#     cache_instance.set(f"trivy_image_cve:{test_img}", None)

#     t_cold0 = time.perf_counter()
#     trivy_image.scan_image(test_img)
#     t_cold = (time.perf_counter() - t_cold0) * 1000.0

#     t_warm0 = time.perf_counter()
#     trivy_image.scan_image(test_img)
#     t_warm = (time.perf_counter() - t_warm0) * 1000.0

#     print(f"  Image: {test_img}")
#     print(f"  Cold CVE Scan (Cache Miss) : {t_cold:.2f} ms")
#     print(f"  Warm CVE Scan (Cache Hit)  : {t_warm:.2f} ms")
#     print(f"  Performance Speedup Factor : {t_cold / max(t_warm, 0.001):.1f}x faster on warm hit")
#     print("=" * 120)


# if __name__ == "__main__":
#     asyncio.run(run_benchmark())
import time
import asyncio
from app.main import analyze
from app.cache import cache_instance
from app.engines import TrivyImageEngine

BENCHMARK_FIXTURES = [
    {
        "name": "Scenario 1: LLM-Generated Bad Dockerfile (Root + Secrets + Untagged)",
        "type": "dockerfile",
        "content": """
FROM ubuntu:latest
ENV AWS_SECRET_ACCESS_KEY="AKIA1234567890abcdef"
RUN apt-get update && apt-get install -y gcc openssh-server
RUN curl http://example.com/install.sh | sh
RUN chmod 777 /app/run.sh
EXPOSE 2375
CMD ["/app/run.sh"]
"""
    },
    {
        "name": "Scenario 2: Typosquatted Base Image Dockerfile (ubunntu)",
        "type": "dockerfile",
        "content": """
FROM ubunntu:22.04
USER appuser
CMD ["python", "app.py"]
"""
    },
    {
        "name": "Scenario 3: Vulnerable Compose File (Privileged + Sock Mount)",
        "type": "compose",
        "content": """
version: '3.8'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
  agent:
    image: custom-agent:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/etc
    network_mode: host
    ports:
      - "5432:5432"
    environment:
      - DB_PASSWORD=SuperSecretPass123!
"""
    },
    {
        "name": "Scenario 4: Clean Multi-stage Hardened Dockerfile",
        "type": "dockerfile",
        "content": """
FROM python:3.11-slim-bookworm AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim-bookworm
WORKDIR /app
RUN groupadd -r app && useradd -r -g app appuser
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY . .
USER appuser
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health || exit 1
CMD ["python", "app.py"]
"""
    }
]


async def run_one(fixture: dict) -> None:
    payload = {
        "content": fixture["content"],
        "artifact_type": fixture["type"],
        "file_path": "docker-compose.yml" if fixture["type"] == "compose" else "Dockerfile",
        "options": {"enable_cve_scan": False, "enable_hardening": True},
    }

    wall_start = time.perf_counter()
    # Calls the REAL production handler from main.py -- same asyncio.gather
    # concurrency a live request goes through. This replaces the old approach
    # of calling each engine directly and summing separately-timed blocks,
    # which was mathematically guaranteed to equal a serial sum.
    result = await analyze(payload)
    wall_elapsed = (time.perf_counter() - wall_start) * 1000.0

    print(f"\n--- {fixture['name']} ---")
    tb = result.evidence.get("timing_breakdown_ms", {})
    print(f"  Reported Timing Breakdown : {tb}")
    print(f"  Measured Wall Clock       : {wall_elapsed:.2f}ms  "
          f"(should track near the SLOWEST reported stage, not their sum)")
    raw_count = result.evidence["raw_findings_count"]
    dedup_count = result.evidence["deduplicated_count"]
    print(f"  Finding Counts            : Raw = {raw_count} -> Deduplicated = {dedup_count} "
          f"(Merged {raw_count - dedup_count} findings)")
    print(f"  Score & Status            : {result.evidence['risk_score']}/100 ({result.status.upper()}) "
          f"| Max Severity = {result.evidence['severity'].upper()}")

    print("\n  Full deduplicated findings:")
    for f in result.findings:
        tag = f" <- MERGED {f.sources}" if len(f.sources) > 1 else ""
        print(f"    - [Line {f.line_number}] {f.detector_id} ({f.severity}){tag}")


async def run_benchmark():
    print("=" * 120)
    print("      AI SUPPLY CHAIN GUARDIAN — DOCKER SECURITY AGENT BENCHMARK (via real /analyze handler)")
    print("=" * 120)

    for fixture in BENCHMARK_FIXTURES:
        await run_one(fixture)

    print("\n" + "=" * 120)
    print("      COLD VS WARM TRIVY IMAGE CVE SCAN LATENCY BENCHMARK")
    print("=" * 120)

    trivy_image = TrivyImageEngine(timeout_sec=5.0)
    test_img = "alpine:3.18.0"
    cache_instance.set(f"trivy_image_cve:{test_img}", None)

    t_cold0 = time.perf_counter()
    trivy_image.scan_image(test_img)
    t_cold = (time.perf_counter() - t_cold0) * 1000.0

    t_warm0 = time.perf_counter()
    trivy_image.scan_image(test_img)
    t_warm = (time.perf_counter() - t_warm0) * 1000.0

    print(f"  Image: {test_img}")
    print(f"  Cold CVE Scan (Cache Miss) : {t_cold:.2f} ms")
    print(f"  Warm CVE Scan (Cache Hit)  : {t_warm:.2f} ms")
    print(f"  Performance Speedup Factor : {t_cold / max(t_warm, 0.001):.1f}x faster on warm hit")
    print("=" * 120)


if __name__ == "__main__":
    asyncio.run(run_benchmark())