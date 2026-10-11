from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]

    @classmethod
    def parse(cls, value: Any, default: Optional["Severity"] = None) -> "Severity":
        try:
            return cls(str(value).upper().strip())
        except ValueError:
            return default or cls.LOW


CATEGORIES = ("bug", "security", "performance", "reliability", "maintainability", "testing", "style")


class Finding(BaseModel):
    """One issue the AI found in the changed code."""
    file_path: str                            # relative to the project root, forward slashes
    line: int
    end_line: Optional[int] = None
    severity: Severity
    category: str = "bug"
    title: str
    explanation: str = ""
    confidence: float = 0.5
    fix: Optional[str] = None                 # replacement for lines line..end_line
    context: Optional[str] = None             # the original code those lines (plus a little around them)
    context_start: Optional[int] = None
    language: Optional[str] = None
    fingerprint: str = ""
    suppressed: Optional[str] = None          # reason, when ignored inline or by a user

    @property
    def counts(self) -> bool:
        return not self.suppressed


class FileReview(BaseModel):
    path: str
    status: str                               # reviewed | skipped | error
    message: str = ""
    lines_added: int = 0
    issues: int = 0
    chunks: int = 0
    cached: bool = False


class ReviewResult(BaseModel):
    target: str
    base_ref: str                             # empty for a whole-project review
    verdict: str                              # PASS | WARN | FAIL
    verdict_label: str                        # Looks good | Approve with comments | Changes requested
    verdict_reason: str
    summary: str = ""
    model: str = ""
    findings: List[Finding]
    files: List[FileReview]
    stats: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")
