"""Re-evaluate a stored result after the user suppresses findings or changes the baseline,
without running the scanners again."""
from __future__ import annotations

from typing import Any, Dict, Optional, Set

from app.config import load_config
from app.core.gates import decide_verdict, evaluate_gates, health_score
from app.core.models import Finding, ScanResult

USER_PREFIXES = ("marked false positive", "ignored")


def rescore(result: Dict[str, Any], suppressions: Dict[str, str], baseline: Optional[Set[str]],
            project_root: Optional[str] = None) -> Dict[str, Any]:
    findings = [Finding(**f) for f in result.get("findings", [])]
    scans = [ScanResult(**{k: v for k, v in s.items() if k != "finding_count"}) for s in result.get("scans", [])]
    for f in findings:
        # user suppressions are re-applied from scratch; inline ones stay
        if f.suppressed and f.suppressed.startswith(USER_PREFIXES):
            f.suppressed = None
        if not f.suppressed and f.fingerprint in suppressions:
            f.suppressed = suppressions[f.fingerprint]
        f.is_new = not (baseline and f.fingerprint in baseline)
    cfg = load_config(project_root)
    diff_mode = bool(result.get("base_ref"))
    gates = evaluate_gates(findings, scans, cfg, diff_mode=diff_mode)
    verdict, reason = decide_verdict(gates, cfg)
    source_lines = int((result.get("stats") or {}).get("source_lines") or 0)
    out = dict(result)
    out["findings"] = [f.model_dump(mode="json") for f in findings]
    out["gates"] = [g.model_dump(mode="json") for g in gates]
    out["verdict"], out["verdict_reason"] = verdict, reason
    out["health"] = health_score(findings, source_lines, verdict)
    stats = dict(out.get("stats") or {})
    stats.update({
        "findings_counted": sum(1 for f in findings if f.counts),
        "suppressed": sum(1 for f in findings if f.suppressed),
        "baseline": sum(1 for f in findings if not f.is_new),
    })
    out["stats"] = stats
    return out
