"""A small, inspectable, model-independent agent risk replay engine.

All data is synthetic. The policy is a demonstrator, not a security product.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REQUIRED = {"run_id", "event_id", "agent_id", "action", "tool", "resource", "environment"}


class InvalidEvent(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    run_id: str
    event_id: str
    agent_id: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for lineno, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise InvalidEvent(f"{path}:{lineno}: invalid JSON: {exc.msg}") from exc
        if not isinstance(event, dict):
            raise InvalidEvent(f"{path}:{lineno}: expected JSON object")
        missing = sorted(REQUIRED - set(event))
        if missing:
            raise InvalidEvent(f"{path}:{lineno}: missing {', '.join(missing)}")
        for key in REQUIRED:
            if not isinstance(event[key], str) or not event[key].strip():
                raise InvalidEvent(f"{path}:{lineno}: {key} must be a nonempty string")
        events.append(event)
    return events


def analyze(events: Iterable[dict[str, Any]], baseline: dict[str, Any]) -> dict[str, Any]:
    """Evaluate independent and cross-event rules, preserving input order.

    The baseline is an explicit allowlist. Unknown tool scopes trigger review,
    not automatic blocking; production would require identity and provenance.
    """
    allow = {str(agent): set(tools) for agent, tools in baseline.get("allowed_tools", {}).items()}
    approved_domains = set(baseline.get("approved_external_domains", []))
    findings: list[Finding] = []
    seen_events: set[tuple[str, str]] = set()
    denied: set[tuple[str, str, str]] = set()
    duplicates = 0
    processed = 0

    def add(rule: str, severity: str, e: dict[str, Any], evidence: str, recommendation: str) -> None:
        findings.append(Finding(rule, severity, e["run_id"], e["event_id"], e["agent_id"], evidence, recommendation))

    for e in events:
        key = (e["run_id"], e["event_id"])
        if key in seen_events:
            duplicates += 1
            continue
        seen_events.add(key)
        processed += 1
        run, agent, action, tool, resource = (e[k] for k in ("run_id", "agent_id", "action", "tool", "resource"))
        env = e["environment"].lower()
        approval = e.get("approval_id")
        decision = e.get("decision", "allowed")
        destination = e.get("destination_domain", "")
        classification = e.get("data_classification", "public")

        if env == "production" and tool not in allow.get(agent, set()):
            add("AGENT_NEW_TOOL_SCOPE", "medium", e, f"{agent} used non-baselined tool {tool}", "Review scope expansion and update signed baseline after approval")
        if action in {"export", "send"} and classification in {"confidential", "restricted"} and destination and destination not in approved_domains:
            add("SENSITIVE_DATA_EGRESS", "critical", e, f"{classification} data sent toward unapproved domain {destination}", "Deny egress, quarantine run, investigate destination")
        if env == "production" and action in {"grant_admin", "rotate_credentials", "delete_database"} and not approval:
            add("PRIVILEGED_ACTION_WITHOUT_APPROVAL", "high", e, f"production action {action} lacks approval_id", "Require verified human approval before execution")
        denied_key = (run, agent, resource)
        if decision == "denied":
            denied.add(denied_key)
        elif action in {"write", "delete", "export", "grant_admin", "delete_database"} and denied_key in denied:
            add("WRITE_AFTER_DENIAL", "high", e, f"mutation {action} followed a denied event for {resource}", "Stop run; inspect replay and tool enforcement")

    findings.sort(key=lambda f: (-SEVERITIES[f.severity], f.run_id, f.event_id, f.rule_id))
    return {"schema_version": "1.0", "events_processed": processed, "duplicate_events_ignored": duplicates,
            "finding_count": len(findings), "findings": [f.to_dict() for f in findings]}


def gate(report: dict[str, Any], threshold: str) -> bool:
    """True when report contains a finding at/above the fail threshold."""
    if threshold not in SEVERITIES:
        raise ValueError(f"unknown severity: {threshold}")
    return any(SEVERITIES[f["severity"]] >= SEVERITIES[threshold] for f in report["findings"])
