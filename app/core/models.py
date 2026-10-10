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

    def lower(self, steps: int = 1) -> "Severity":
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order[max(0, self.rank - steps)]

    @classmethod
    def parse(cls, value: Any, default: Optional["Severity"] = None) -> "Severity":
        try:
            return cls(str(value).upper().strip())
        except ValueError:
            return default or cls.INFO


class Category(str, Enum):
    BUILD = "build"
    TESTS = "tests"
    SECRETS = "secrets"
    SAST = "sast"
    DEPENDENCIES = "dependencies"
    LINT = "lint"
    TYPES = "types"
    COMPLEXITY = "complexity"
    SIZE = "size"
    DUPLICATION = "duplication"
    DEBUG = "debug"
    AI = "ai"
    EXTERNAL = "external"


class Finding(BaseModel):
    tool: str = Field(..., description="Tool that reported the issue")
    rule_id: str = Field(..., description="Rule or check identifier, e.g. F821, B608, CVE-2024-1234")
    file_path: str = Field(..., description="Path relative to the project root, forward slashes")
    line: int = 0
    column: Optional[int] = None
    end_line: Optional[int] = None
    message: str
    severity: Severity
    category: Category = Category.LINT
    code_snippet: Optional[str] = None
    confidence: Optional[str] = None          # scanner's own confidence, if it reports one
    url: Optional[str] = None                 # rule documentation
    tools: List[str] = Field(default_factory=list)  # every tool that reported it (after de-duplication)
    fingerprint: str = ""
    is_new: bool = True                       # False when the finding is in the project's baseline
    suppressed: Optional[str] = None          # reason, when ignored inline or by a user
    # Source shown to the AI and in the dashboard
    context: Optional[str] = None
    context_start: Optional[int] = None
    language: Optional[str] = None
    # AI triage
    ai_verdict: Optional[str] = None          # TRUE_POSITIVE | FALSE_POSITIVE | UNSURE
    ai_confidence: Optional[float] = None
    ai_severity: Optional[Severity] = None
    ai_explanation: Optional[str] = None
    ai_fix: Optional[str] = None
    ai_dismissed: bool = False
    extra: Dict[str, Any] = Field(default_factory=dict)

    @property
    def effective_severity(self) -> Severity:
        return self.ai_severity or self.severity

    @property
    def counts(self) -> bool:
        """Whether the finding takes part in gates and the score."""
        return self.is_new and not self.suppressed and not self.ai_dismissed


class ScanStatus(str, Enum):
    RAN = "ran"
    SKIPPED = "skipped"
    ERROR = "error"


class ScanResult(BaseModel):
    tool: str
    category: str
    status: ScanStatus
    message: str = ""
    findings: List[Finding] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    duration_seconds: float = 0.0
    not_applicable: bool = False          # skipped because the project doesn't need it (not a missing tool)


class GateStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class GateResult(BaseModel):
    key: str
    name: str
    status: GateStatus
    severity: str                         # blocker | warn
    actual: Optional[str] = None
    threshold: Optional[str] = None
    details: str = ""
    tools: List[str] = Field(default_factory=list)
    not_applicable: bool = False
    top_files: List[Dict[str, Any]] = Field(default_factory=list)


class ReviewResult(BaseModel):
    target: str
    verdict: str
    verdict_reason: str
    health: Dict[str, Any]
    gates: List[GateResult]
    findings: List[Finding]
    scans: List[ScanResult]
    languages: List[str] = Field(default_factory=list)
    base_ref: Optional[str] = None
    stats: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump(mode="json")
        # Each scan's findings are already in the top-level list; keep only the count.
        for scan in data["scans"]:
            scan["finding_count"] = len(scan.pop("findings", []))
        return data
