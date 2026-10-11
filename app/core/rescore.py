"""Re-apply ignores to a stored result and recompute the verdict, without calling the AI again."""
from __future__ import annotations

from typing import Any, Dict

from app.core.findings import apply_user_suppressions, counts_by_severity, decide_verdict, sort_findings
from app.core.models import Finding


def rescore(result: Dict[str, Any], suppressions: Dict[str, str]) -> Dict[str, Any]:
    findings = [Finding(**f) for f in result.get("findings", [])]
    apply_user_suppressions(findings, suppressions)
    findings = sort_findings(findings)
    out = dict(result)
    out["findings"] = [f.model_dump(mode="json") for f in findings]
    out["verdict"], out["verdict_label"], out["verdict_reason"] = decide_verdict(findings)
    stats = dict(out.get("stats") or {})
    stats["issues"] = sum(1 for f in findings if f.counts)
    stats["ignored"] = sum(1 for f in findings if f.suppressed)
    stats["by_severity"] = counts_by_severity(findings)
    out["stats"] = stats
    return out
