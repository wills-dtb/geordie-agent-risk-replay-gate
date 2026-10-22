"""Usage: python -m geordie_gate.cli --events ... --baseline ... --output ..."""
import argparse
import json
import sys
from pathlib import Path

from .core import InvalidEvent, analyze, gate, load_jsonl


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Replay AI-agent tool traces against a deterministic policy baseline")
    parser.add_argument("--events", required=True, help="NDJSON synthetic tool-call events")
    parser.add_argument("--baseline", required=True, help="JSON policy baseline")
    parser.add_argument("--output", default="risk-report.json", help="Report destination")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default="high")
    args = parser.parse_args(argv)
    try:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        if not isinstance(baseline, dict):
            raise ValueError("baseline must be a JSON object")
        report = analyze(load_jsonl(args.events), baseline)
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        failed = gate(report, args.fail_on)
        print(f"events={report['events_processed']} findings={report['finding_count']} gate={'FAIL' if failed else 'PASS'} report={args.output}")
        return 2 if failed else 0
    except (InvalidEvent, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
