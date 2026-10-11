"""Compare a review with the previous one: which issues are new, still open or fixed."""
from __future__ import annotations

from typing import Any, Dict, Optional


def _counts(finding: Dict[str, Any]) -> bool:
    return not finding.get("suppressed")


def compare_results(current: Dict[str, Any], previous: Optional[Dict[str, Any]],
                    previous_scan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Mark each current issue as new or not, and list the previous issues that are gone.

    An issue only counts as fixed when its file was reviewed again this time, so a review
    of a few selected files doesn't report everything else as fixed."""
    out = dict(current)
    findings = [dict(f) for f in current.get("findings") or []]
    if not previous or "files" not in previous:
        for f in findings:
            f["is_new"] = None
        out["findings"] = findings
        out["comparison"] = None
        return out

    before = {f.get("fingerprint") for f in previous.get("findings") or [] if f.get("fingerprint")}
    now = {f.get("fingerprint") for f in findings}
    reviewed_now = {f["path"] for f in current.get("files") or [] if f.get("status") == "reviewed"}
    for f in findings:
        f["is_new"] = f.get("fingerprint") not in before
    fixed = [
        {k: f.get(k) for k in ("fingerprint", "file_path", "line", "severity", "category", "title")}
        for f in previous.get("findings") or []
        if _counts(f) and f.get("fingerprint") not in now and f.get("file_path") in reviewed_now
    ]
    out["findings"] = findings
    out["comparison"] = {
        "previous_scan_id": (previous_scan or {}).get("id"),
        "previous_finished_at": (previous_scan or {}).get("finished_at") or previous.get("finished_at"),
        "previous_verdict": previous.get("verdict"),
        "previous_issues": sum(1 for f in previous.get("findings") or [] if _counts(f)),
        "fixed": fixed,
    }
    return out
