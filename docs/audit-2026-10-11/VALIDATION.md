# Audit validation record

Run from each service directory with Python 3.12.3. These counts establish the stated local checks only, not live microservice deployment or scanner accuracy.

| Service | Command | Result |
|---|---|---|
| cipherguard | `python3 -m pytest tests -q --disable-warnings` | 5 passed |
| license_compliance | `python3 -m pytest tests -q --disable-warnings` | 13 passed |
| prompt_injection | `python3 -m pytest tests -q --disable-warnings` | 32 passed, 4 warnings; offline model environment enabled |
| trust_engine | `python3 -m pytest tests/test_routing.py tests/test_fusion.py tests/test_state.py -q --disable-warnings` | 106 passed |
| docker_security | `python3 -m pytest tests/test_scoring.py tests/test_normalize.py tests/test_parsers.py tests/test_rules.py tests/test_hardener.py -q --disable-warnings` | 8 passed |
| secret_detection | `python3 -m pytest tests/test_suppression.py tests/test_structural_context.py tests/test_vendor_signatures.py tests/test_entropy_scoring.py tests/test_status.py tests/test_integration_fixture.py -q --disable-warnings` | 15 passed |

Completed groups total: 179 passing cases. CipherGuard/License/Prompt full-run logs are included beside this file. Trust Engine full-run log records its collection failure due to missing fakeredis; it is not the successful subset's log.

Full per-service discovery runs were bounded at 120 seconds. Code Security, Docker Security, Secret Detection and Workflow did not finish within that limit. The full Trust Engine suite could not collect because fakeredis is missing. An additional Trust Engine API-plus-pure-suite invocation progressed beyond the pure tests but did not finish; it is not included in passing counts. Plain `pytest` initially could not import app in CipherGuard; the successful run used `python3 -m pytest` from its service directory.

Docker inspection: `docker ps --format '{{.Names}} {{.Status}}'` could not access `/var/run/docker.sock`, including the escalated attempt. No stack was started, stopped or rebuilt. No real .env values were printed.

Source checks: all 205 tracked files read for inventory; 127 Python files parsed with ast.parse, zero syntax errors. JSON snapshots were parsed. This does not validate external package dataset accuracy.

Local reproductions are captured in reproductions.txt. Additional probes established:

- 1 / 9 / 21 zero-risk CipherGuard low-severity findings at confidence 0.8 produce scores 97.6 / 78.4 / 49.6 with accept / review / reject.
- Workflow's handler returns stub for both a GitLab pipeline and malformed GitHub Actions YAML.

Application code was not modified; only audit artifacts were added.
