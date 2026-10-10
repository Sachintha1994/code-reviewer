from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from app.core.models import Category, Finding, Severity
from app.scanners.base import ScanContext, Scanner

SONAR_SEVERITY = {
    "BLOCKER": Severity.CRITICAL, "CRITICAL": Severity.HIGH, "MAJOR": Severity.MEDIUM,
    "MINOR": Severity.LOW, "INFO": Severity.INFO,
    # newer "software quality" impact severities
    "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
}
SONAR_CATEGORY = {"VULNERABILITY": Category.SAST, "SECURITY_HOTSPOT": Category.SAST, "BUG": Category.LINT,
                  "CODE_SMELL": Category.LINT}


class SonarQubeClient:
    def __init__(self, host: str, token: str, timeout: int = 30):
        self.host = host.rstrip("/")
        self.auth = (token, "")
        self.timeout = timeout

    def _get(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        resp = requests.get(f"{self.host}{path}", auth=self.auth, params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def test_connection(self, project_key: str) -> Dict[str, Any]:
        try:
            status = self.get_quality_gate_status(project_key)
            return {"ok": True, "status": status.get("status", "UNKNOWN")}
        except requests.RequestException as exc:
            return {"ok": False, "error": str(exc)}

    def get_quality_gate_status(self, project_key: str) -> Dict[str, Any]:
        return self._get("/api/qualitygates/project_status", {"projectKey": project_key}).get("projectStatus", {})

    def get_issues(self, project_key: str, max_issues: int = 1000) -> List[Finding]:
        findings: List[Finding] = []
        page = 1
        while len(findings) < max_issues:
            data = self._get("/api/issues/search", {"componentKeys": project_key, "resolved": "false",
                                                    "ps": 500, "p": page})
            issues = data.get("issues", [])
            findings.extend(self._to_finding(issue, project_key) for issue in issues)
            total = (data.get("paging") or {}).get("total", data.get("total", 0))
            if not issues or page * 500 >= total:
                break
            page += 1
        return findings[:max_issues]

    @staticmethod
    def _to_finding(issue: Dict[str, Any], project_key: str) -> Finding:
        component = issue.get("component", "")
        path = component.split(":", 1)[1] if component.startswith(f"{project_key}:") else component
        return Finding(
            tool="SonarQube", rule_id=issue.get("rule", "unknown"), file_path=path,
            line=int(issue.get("line") or 0), message=issue.get("message", ""),
            severity=SONAR_SEVERITY.get(str(issue.get("severity", "INFO")).upper(), Severity.INFO),
            category=SONAR_CATEGORY.get(issue.get("type", ""), Category.EXTERNAL),
        )


class SonarQubeScanner(Scanner):
    name = "SonarQube"
    category = "external"

    def __init__(self, settings: Optional[Dict[str, str]]):
        self.settings = settings or {}

    def applies(self, ctx: ScanContext):
        if not all(self.settings.get(k) for k in ("host", "token", "project_key")):
            return "SonarQube not configured for this project"
        return None

    def scan(self, ctx: ScanContext):
        client = SonarQubeClient(self.settings["host"], self.settings["token"])
        key = self.settings["project_key"]
        try:
            status = client.get_quality_gate_status(key)
            issues = client.get_issues(key)
        except requests.RequestException as exc:
            return self.error(f"SonarQube request failed: {exc}")
        return self.ran(issues, quality_gate=status.get("status", "UNKNOWN"),
                        conditions=status.get("conditions", []))
