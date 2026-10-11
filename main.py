"""Command line: AI code review of a project, or of its changes since a branch.

    python main.py C:\\path\\to\\project --base main      changes since main
    python main.py C:\\path\\to\\project                  the whole project
    python main.py C:\\path\\to\\project --base pm-dev --json review.json

Exit code: 0 when the review passes or has only comments, 1 when changes are
requested (use --strict to also fail on comments), 2 on errors.
The dashboard is started separately:  python -m uvicorn app.web_dashboard:app --reload
"""
from __future__ import annotations

import argparse
import json
import sys

from app.core.orchestrator import CodeReviewOrchestrator


def print_report(result) -> None:
    print()
    print(f"{result.verdict_label}: {result.verdict_reason}")
    s = result.stats
    scope = f"changes since {result.base_ref}" if result.base_ref else "whole project"
    print(f"{s['files_reviewed']} files reviewed ({scope}, {s['lines_added']} lines) with {result.model}")
    if result.summary:
        print()
        print(result.summary)
    active = [f for f in result.findings if f.counts]
    print()
    print(f"Issues: {len(active)}" + (f" ({s['ignored']} ignored)" if s.get("ignored") else ""))
    for f in active:
        print(f"  {f.severity.value:<8} {f.file_path}:{f.line}  [{f.category}] {f.title}")
    failed = [f for f in result.files if f.status == "error"]
    for f in failed:
        print(f"  couldn't review {f.path}: {f.message}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="AI code review of a project, or of its changes since a branch.")
    parser.add_argument("path", help="project folder (a git repository)")
    parser.add_argument("--base", default=None,
                        help="branch to compare with, e.g. main. Without it (and no base_ref in reviewer.yml) the whole project is reviewed")
    parser.add_argument("--json", dest="json_out", help="write the full result to this JSON file")
    parser.add_argument("--strict", action="store_true", help="exit 1 on medium issues as well")
    parser.add_argument("--quiet", action="store_true", help="don't print progress")
    args = parser.parse_args(argv)

    def progress(event):
        if args.quiet:
            return
        if event.get("tool") and event.get("status") != "running":
            extra = f"{event.get('findings', 0)} issues" if event.get("status") == "reviewed" else event.get("message", "")
            print(f"  {event['status']:<9} {event['tool']}  {extra}", file=sys.stderr)
        elif not event.get("tool") and event.get("message"):
            print(f"- {event['message']}", file=sys.stderr)

    try:
        result = CodeReviewOrchestrator(args.path, base_ref=args.base, progress=progress).run_full_review()
    except (ValueError, RuntimeError) as exc:
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
