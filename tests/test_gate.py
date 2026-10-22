import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from geordie_gate.core import InvalidEvent, analyze, gate, load_jsonl

ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "examples/baseline.json").read_text())


class GateTests(unittest.TestCase):
    def test_safe_trace(self):
        report = analyze(load_jsonl(ROOT / "examples/safe.jsonl"), BASELINE)
        self.assertEqual(report["finding_count"], 0)
        self.assertFalse(gate(report, "medium"))

    def test_risky_trace(self):
        report = analyze(load_jsonl(ROOT / "examples/risky.jsonl"), BASELINE)
        rules = {f["rule_id"] for f in report["findings"]}
        self.assertEqual(rules, {"AGENT_NEW_TOOL_SCOPE", "SENSITIVE_DATA_EGRESS", "PRIVILEGED_ACTION_WITHOUT_APPROVAL", "WRITE_AFTER_DENIAL"})
        self.assertEqual(report["duplicate_events_ignored"], 1)
        self.assertTrue(gate(report, "high"))

    def test_run_isolation(self):
        events = [
            dict(run_id="r1", event_id="e1", agent_id="support-agent", action="read", tool="crm.read", resource="x", environment="production", decision="denied"),
            dict(run_id="r2", event_id="e1", agent_id="support-agent", action="write", tool="tickets.update", resource="x", environment="production", decision="allowed")]
        self.assertEqual(analyze(events, BASELINE)["finding_count"], 0)

    def test_approved_privileged_action(self):
        event = dict(run_id="r1", event_id="e1", agent_id="ops-agent", action="grant_admin", tool="cloud.admin", resource="prod/iam", environment="production", approval_id="human-123")
        self.assertFalse(gate(analyze([event], BASELINE), "high"))

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.jsonl"
            path.write_text('{"foo":1}\n')
            with self.assertRaisesRegex(InvalidEvent, "missing"):
                load_jsonl(path)

    def test_duplicate_event(self):
        event = dict(run_id="r1", event_id="e1", agent_id="support-agent", action="read", tool="crm.read", resource="x", environment="production")
        report = analyze([event, event], BASELINE)
        self.assertEqual(report["events_processed"], 1)
        self.assertEqual(report["duplicate_events_ignored"], 1)

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "report.json")
            for fixture, expected in [("safe", 0), ("risky", 2)]:
                proc = subprocess.run([sys.executable, "-m", "geordie_gate.cli", "--events", str(ROOT / f"examples/{fixture}.jsonl"), "--baseline", str(ROOT / "examples/baseline.json"), "--output", out], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(proc.returncode, expected, proc.stderr)
                self.assertTrue(Path(out).exists())

    def test_critical_threshold(self):
        report = analyze(load_jsonl(ROOT / "examples/risky.jsonl"), BASELINE)
        self.assertTrue(gate(report, "critical"))


if __name__ == "__main__":
    unittest.main()
