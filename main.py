"""Command-line entry point.

    python main.py path/to/project                 review the whole project
    python main.py path/to/project --base main     review only changes since main
    python main.py path/to/project --json out.json --no-ai

Exit code: 0 for PASS or WARN, 1 for FAIL, 2 for errors (use --strict to fail on WARN too).
The dashboard is started separately:  uvicorn app.web_dashboard:app --reload
"""
from __future__ import annotations

import argparse
import json
import sys

from app.core.orchestrator import CodeReviewOrchestrator, clone_github_repo  # noqa: F401 (re-exported)

ICONS = {"passed": "PASS", "failed": "FAIL", "skipped": "SKIP"}


def print_report(result) -> None:
    print()
    print(f"Verdict: {result.verdict}  ({result.verdict_reason})")
    h = result.health
    print(f"Health:  {h['score']}/100, grade {h['grade']}  ({h['density']} weighted findings per 1,000 lines)")
    print()
    print("Gates:")
    for g in result.gates:
        actual = f" {g.actual}" if g.actual else ""
        detail = f" - {g.details}" if g.details else ""
        print(f"  [{ICONS[g.status.value]}] {g.name:<28}{actual}{detail}  ({g.severity})")
    counted = [f for f in result.findings if f.counts]
    print()
    print(f"Findings: {len(counted)} counted, {len(result.findings) - len(counted)} suppressed/dismissed/baseline")
    for f in counted[:25]:
        sev = f.effective_severity.value
        print(f"  {sev:<8} {f.file_path}:{f.line}  [{', '.join(f.tools)}] {f.rule_id}: {f.message[:110]}")
    if len(counted) > 25:
        print(f"  ... {len(counted) - 25} more (use --json to see all)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the code reviewer on a folder.")
    parser.add_argument("path", help="project folder to review")
    parser.add_argument("--base", default=None, help="git ref to compare against; only changed lines are reviewed")
    parser.add_argument("--json", dest="json_out", help="write the full result to this JSON file")
    parser.add_argument("--no-ai", action="store_true", help="skip the AI triage")
    parser.add_argument("--strict", action="store_true", help="exit 1 on WARN as well as FAIL")
    parser.add_argument("--quiet", action="store_true", help="don't print scanner progress")
    args = parser.parse_args(argv)

    def progress(event):
        if args.quiet:
            return
        if event.get("tool"):
            if event.get("status") != "running" or event.get("tool") == "AI triage":
                print(f"  {event['tool']:<18} {event.get('status', ''):<8} {event.get('message', '')}", file=sys.stderr)
        elif event.get("message"):
            print(f"- {event['message']}", file=sys.stderr)

    try:
        result = CodeReviewOrchestrator(args.path, base_ref=args.base, use_ai=not args.no_ai,
                                        progress=progress).run_full_review()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print_report(result)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2)
        print(f"\nFull result written to {args.json_out}")
    if result.verdict == "FAIL" or (args.strict and result.verdict == "WARN"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
