# Evaluation scope

These tools are development measurements, not an independently validated accuracy claim.

- `latency_benchmark.py` uses nearest-rank percentiles (`ceil(p*n/100)`), separates initial-response latency from time-to-final including polling/callbacks, and reports failed requests and incomplete finals. Warm-up is excluded; cold-start and concurrent-load measurements must be reported separately. The 3-second synchronous target is a target, not an achieved guarantee.
- `phase_a_schema_audit/audit.py` checks nested serialization preservation against detector endpoints. Isolated serializer tests do not substitute for this running-stack audit.
- `license_compliance_baseline/run_comparison.py` imports a subset of the pipeline. It omits the HTTP contract, orchestration, caching and service-level transitive pass. Its package sets are small demonstrations; results are not full-service accuracy estimates.
- `prompt_injection_baseline/run_comparison.py` compares a small authored set. Rebuff uses its heuristic component only and Vigil uses bundled YARA rules only. These adapted comparisons are not evaluations of the full products; model/backend versions and failed calls must accompany any published results.
- Historical output files and the original audit are preserved as dated evidence. They do not describe the current stack or prove current performance.

## Independently labeled corpus

Create labels by construction or human review, independent of detector outputs. Use grouped train/validation splits and a held-out set authored by someone outside training. No corpus labels or trained model are supplied by Checkpoint 2.

Example manifest structure (supply your own labels and paths):

```csv
sample_id,path,label,artifact_type
```

Run `python3 scripts/run_labeled_corpus.py manifest.csv --output mapping.csv --url http://localhost:8000` from the repository root. CSV/JSON/JSONL manifests are supported; artifact paths are relative to the manifest. Mapping rows preserve the supplied label and include `sample_id,request_id,label,scan_status,error`. Failed/unfinished scans are explicit and must not enter training as final examples.

Join successful mappings to the JSONL feature log on request_id. For asynchronous scans, use a callback-phase row in which no selected agent still has status pending; multiple files can produce several callback rows. Select a complete final row, not merely the last timestamp: simultaneous callbacks can append out of commit order. null means not run, never zero. Batch feature rows contain multiple files, and must not be treated as independent labeled examples without an explicit grouping/labeling strategy.
