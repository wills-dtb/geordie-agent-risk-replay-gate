# Agent Risk Replay Gate — a Geordie-adjacent engineering demonstration

**Status:** Independent, synthetic engineering exercise. **Not affiliated with Geordie AI.** No Geordie APIs, source code, customers, or proprietary data are used.

## Why this build exists

**Observed public problem:** Geordie AI's publicly described product helps enterprises discover, understand and govern AI-agent behavior, including runtime risk and remediation.

**Hypothesis, not a claim about Geordie's internal systems:** When agent integrations change, enterprises need an auditable *pre-deployment* way to replay known-good and known-bad tool-call traces and detect policy drift in CI. This tiny standalone gate demonstrates deterministic safety regression and evidence provenance alongside a runtime governance platform, not as a clone of it.

## Architecture

Synthetic agent traces (NDJSON) and an explicit JSON policy baseline pass through validation, duplicate suppression, an inspectable rules engine, and a CI-compatible JSON evidence report.

Four rules cover new tool scope, sensitive-data egress, privileged operations without recorded approval, and attempted writes after denial.

## Run it (Python 3.10+, zero third-party dependencies)

```bash
python -m unittest discover -s tests -v
python -m geordie_gate.cli --events examples/safe.jsonl --baseline examples/baseline.json --output safe-report.json
python -m geordie_gate.cli --events examples/risky.jsonl --baseline examples/baseline.json --output risky-report.json
```

Safe replay exits 0, risky replay exits 2, malformed input exits 1.

## Tradeoffs and limits

The project is deliberately offline and uses fictional events. It does not enforce runtime security or support real vendor schemas. Rules are deterministic and auditable but miss semantic misuse. A production system needs event provenance, causal ordering, authenticated integration adapters, tenant isolation, signed policies, approval verification, secure evidence storage and resilience SLAs.

## Scope

Built as a narrowly scoped 2–3-hour technical demonstration. Deliberately omitted: streaming ingestion, OpenTelemetry adapters, distributed ordering, multi-tenancy, dashboard, signed audit evidence and live enforcement.

## Founder discussion

How can agent governance platforms make enterprise rollout repeatable without creating excessive integration, deployment and review overhead?
