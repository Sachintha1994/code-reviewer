from __future__ import annotations

from typing import Dict, Optional

import requests

from app.scanners.base import ScanContext, Scanner


class CodecovScanner(Scanner):
    """Reads overall coverage from Codecov (repo format: github/owner/repo)."""

    name = "Codecov"
    category = "tests"

    def __init__(self, settings: Optional[Dict[str, str]]):
        self.settings = settings or {}

    def applies(self, ctx: ScanContext):
        if not (self.settings.get("token") and self.settings.get("repo")):
            return "Codecov not configured"
        return None

    def scan(self, ctx: ScanContext):
        resp = requests.get(
            f"https://codecov.io/api/v2/{self.settings['repo']}",
            headers={"Authorization": f"Bearer {self.settings['token']}", "Accept": "application/json"},
            timeout=30,
        )
        if resp.status_code != 200:
            return self.error(f"Codecov API returned {resp.status_code}")
        totals = ((resp.json().get("totals")) or (resp.json().get("commit") or {}).get("totals") or {})
        coverage = totals.get("coverage")
        if coverage is None:
            return self.error("Codecov returned no coverage total")
        return self.ran([], coverage_overall=round(float(coverage), 1))
