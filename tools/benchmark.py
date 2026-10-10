"""Measure the reviewer's precision and recall against a labelled project.

    python tools/benchmark.py benchmarks/sample_project.labels.json
    python tools/benchmark.py my-labels.json --ai          # include AI triage

Labels file:
{
  "project": "../tests/fixtures/sample_project",      # relative to the labels file
  "expected": [                                         # real issues the reviewer should find
    {"file": "app.py", "line": 6, "category": "secrets", "note": "hardcoded password"}
  ],
  "not_issues": [                                       # optional: things that must NOT count
    {"file": "tests/test_app.py", "line": 3, "category": "secrets"}
  ]
}

A finding matches a label when the file and category agree and the lines are
within 3 of each other. Only findings that count towards the verdict are scored,
and by default only MEDIUM and above (what the dashboard shows first).

  precision = real issues found / everything reported   (how much of the output is noise)
  recall    = real issues found / real issues labelled  (how much is missed)
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.orchestrator import CodeReviewOrchestrator  # noqa: E402

LINE_TOLERANCE = 3


def matches(finding: Dict, label: Dict) -> bool:
    return (finding["file_path"] == label["file"] and finding["category"] == label["category"]
            and abs(int(finding["line"]) - int(label.get("line", 0))) <= LINE_TOLERANCE)


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def score(findings: List[Dict], expected: List[Dict], not_issues: List[Dict], min_severity: str = "MEDIUM") -> Dict:
    floor = SEVERITY_RANK[min_severity]
    counted = [f for f in findings if f["is_new"] and not f["suppressed"] and not f["ai_dismissed"]
               and SEVERITY_RANK[f.get("ai_severity") or f["severity"]] >= floor]
    true_pos = [f for f in counted if any(matches(f, e) for e in expected)]
    found = [e for e in expected if any(matches(f, e) for f in counted)]
    missed = [e for e in expected if e not in found]
    false_pos = [f for f in counted if f not in true_pos]
    leaked = [n for n in not_issues if any(matches(f, n) for f in false_pos)]
    precision = len(true_pos) / len(counted) if counted else 1.0
    recall = len(found) / len(expected) if expected else 1.0
    per_tool: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0})
    for f in counted:
        for tool in f.get("tools") or [f["tool"]]:
            per_tool[tool]["tp" if f in true_pos else "fp"] += 1
    return {"precision": precision, "recall": recall, "reported": len(counted), "true_positives": len(true_pos),
            "false_positives": false_pos, "missed": missed, "not_issues_reported": leaked, "per_tool": dict(per_tool)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("labels")
    parser.add_argument("--ai", action="store_true", help="run AI triage too (needs an API key)")
    parser.add_argument("--all-severities", action="store_true",
                        help="score LOW and INFO findings too (by default only MEDIUM and above, as the dashboard shows)")
    parser.add_argument("--min-precision", type=float, default=0.0, help="exit 1 if precision is below this")
    parser.add_argument("--min-recall", type=float, default=0.0, help="exit 1 if recall is below this")
    args = parser.parse_args(argv)

    labels_path = Path(args.labels).resolve()
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    project = (labels_path.parent / labels["project"]).resolve()
    result = CodeReviewOrchestrator(str(project), use_ai=args.ai, base_ref="").run_full_review().to_dict()
    s = score(result["findings"], labels.get("expected", []), labels.get("not_issues", []),
              "INFO" if args.all_severities else "MEDIUM")

    print(f"Project:   {project}")
    print(f"Precision: {s['precision']:.0%}  ({s['true_positives']} of {s['reported']} reported findings are real)")
    print(f"Recall:    {s['recall']:.0%}  ({len(labels.get('expected', [])) - len(s['missed'])} of {len(labels.get('expected', []))} labelled issues found)")
    print("\nPer tool (true / false positives):")
    for tool, c in sorted(s["per_tool"].items()):
        print(f"  {tool:<20} {c['tp']:>3} / {c['fp']:<3}")
    if s["missed"]:
        print("\nMissed (check which tool should have caught these, and whether it ran):")
        for m in s["missed"]:
            print(f"  {m['file']}:{m.get('line')}  [{m['category']}] {m.get('note', '')}")
    if s["false_positives"]:
        print("\nNoise (reported but not labelled as real):")
        for f in s["false_positives"]:
            print(f"  {f['file_path']}:{f['line']}  [{f['category']}] {', '.join(f['tools'])} {f['rule_id']}: {f['message'][:80]}")
    if s["not_issues_reported"]:
        print("\nKnown non-issues that were reported:")
        for n in s["not_issues_reported"]:
            print(f"  {n['file']}:{n.get('line')}  [{n['category']}]")
    skipped = [sc for sc in result["scans"] if sc["status"] != "ran" and not sc.get("not_applicable")]
    if skipped:
        print("\nTools that didn't run (recall is limited by these):")
        for sc in skipped:
            print(f"  {sc['tool']}: {sc['message']}")
    ok = s["precision"] >= args.min_precision and s["recall"] >= args.min_recall
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
