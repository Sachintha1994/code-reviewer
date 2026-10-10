from __future__ import annotations

from typing import Dict, List, Optional

import requests

from app.core.models import Category, Finding, Severity
from app.scanners.base import ScanContext, Scanner

GH_SEVERITY = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "error": Severity.HIGH,
               "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM, "warning": Severity.MEDIUM,
               "low": Severity.LOW, "note": Severity.LOW}


class GitHubSecurityScanner(Scanner):
    """Open Dependabot and code-scanning (CodeQL) alerts. repo format: owner/repo."""

    name = "GitHub Advanced Security"
    category = "external"

    def __init__(self, settings: Optional[Dict[str, str]]):
        self.settings = settings or {}

    def applies(self, ctx: ScanContext):
        if not (self.settings.get("token") and self.settings.get("repo")):
            return "GitHub Advanced Security not configured"
        return None

    def _get(self, path: str) -> List[Dict]:
        resp = requests.get(
            f"https://api.github.com/repos/{self.settings['repo']}/{path}",
            headers={"Authorization": f"Bearer {self.settings['token']}", "Accept": "application/vnd.github+json"},
            params={"state": "open", "per_page": "100"}, timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"GitHub {path} returned {resp.status_code}")
        return resp.json()

    def scan(self, ctx: ScanContext):
        findings: List[Finding] = []
        errors = []
        try:
            for alert in self._get("dependabot/alerts"):
                adv = alert.get("security_advisory") or {}
                dep = alert.get("dependency") or {}
                findings.append(Finding(
                    tool="Dependabot", rule_id=adv.get("cve_id") or adv.get("ghsa_id") or "advisory",
                    file_path=dep.get("manifest_path", ""), line=0, category=Category.DEPENDENCIES,
                    message=f"{(dep.get('package') or {}).get('name', '?')}: {adv.get('summary', '')}",
                    severity=GH_SEVERITY.get(str(adv.get("severity", "low")).lower(), Severity.LOW),
                    url=alert.get("html_url"),
                ))
        except (RuntimeError, requests.RequestException) as exc:
            errors.append(str(exc))
        try:
            for alert in self._get("code-scanning/alerts"):
                rule = alert.get("rule") or {}
                loc = (alert.get("most_recent_instance") or {}).get("location") or {}
                sev = rule.get("security_severity_level") or rule.get("severity") or "low"
                findings.append(Finding(
                    tool="CodeQL", rule_id=rule.get("id", "unknown"), file_path=loc.get("path", ""),
                    line=int(loc.get("start_line") or 0), category=Category.SAST,
                    message=rule.get("description", "Code scanning alert"),
                    severity=GH_SEVERITY.get(str(sev).lower(), Severity.LOW), url=alert.get("html_url"),
                ))
        except (RuntimeError, requests.RequestException) as exc:
            errors.append(str(exc))
        if errors and not findings:
            return self.error("; ".join(errors))
        return self.ran(findings, "; ".join(errors))
