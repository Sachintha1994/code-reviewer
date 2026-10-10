"""AI review: triages scanner findings (true or false positive) and reviews
changed files for issues scanners can't see.

API keys come from the environment (or a .env file), never from code:
  GROQ_API_KEY / OPENAI_API_KEY / LLM_API_KEY, LLM_PROVIDER, LLM_MODEL, LLM_BASE_URL
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.core.context import extract_context, numbered
from app.core.models import Category, Finding, Severity
from app.scanners.base import LANGUAGE_BY_EXT, read_lines

PROVIDERS = {
    # provider: (base_url, api key env var, default model)
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", "llama-3.3-70b-versatile"),
    "openai": (None, "OPENAI_API_KEY", "gpt-4o-mini"),
    "ollama": ("http://localhost:11434/v1", None, "qwen2.5-coder:7b"),
}
SKIP_CATEGORIES = {Category.DEPENDENCIES, Category.EXTERNAL, Category.SIZE, Category.DUPLICATION,
                   Category.TESTS, Category.DEBUG, Category.AI}
VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNSURE"}

TRIAGE_SYSTEM = (
    "You are a senior application-security and code-quality reviewer. You judge whether a static-analysis "
    "finding is a real problem in the code shown. Be precise and conservative: answer FALSE_POSITIVE only when "
    "the code clearly shows the problem cannot happen (for example the input is a constant, already validated, "
    "or the code is test-only). Reply with a single JSON object and nothing else."
)
TRIAGE_TEMPLATE = """Finding
- tool: {tool}
- rule: {rule}
- scanner severity: {severity}
- message: {message}
- file: {path} ({language})
- flagged line: {line} (marked with >>)

Code (lines {start}-{end}):
```
{code}
```

Return JSON with exactly these keys:
{{
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "UNSURE",
  "confidence": number between 0 and 1,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"  (real production risk in this code),
  "explanation": "2-4 sentences: why this is or isn't a real problem, and what could go wrong",
  "fix": "the corrected version of lines {start}-{end} exactly as they should read, same indentation, no line numbers or >> markers; empty string if no change is needed"
}}"""

FILE_REVIEW_SYSTEM = (
    "You are a senior engineer reviewing a code change. Look only for problems a linter or security scanner "
    "would miss: logic errors, missing authorization or input validation, broken error handling, race "
    "conditions, resource leaks, incorrect edge cases. Ignore style and formatting. Report only issues on "
    "changed lines (marked +). Reply with a single JSON object and nothing else."
)
FILE_REVIEW_TEMPLATE = """File: {path} ({language})
Lines starting with + were added or changed.
```
{code}
```

Return JSON: {{"issues": [{{"line": number, "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW", "title": "short title",
"explanation": "1-3 sentences", "confidence": number between 0 and 1}}]}}. Return {{"issues": []}} if the change looks correct."""


def parse_json_object(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise


def strip_fences(code: str) -> str:
    code = (code or "").strip("\n")
    m = re.match(r"^```[\w+-]*\n(.*?)\n?```$", code.strip(), re.DOTALL)
    return m.group(1) if m else code


def parse_triage(data: Dict[str, Any]) -> Dict[str, Any]:
    verdict = str(data.get("verdict", "UNSURE")).upper().strip()
    if verdict not in VERDICTS:
        verdict = "UNSURE"
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
    except (TypeError, ValueError):
        confidence = 0.5
    severity = Severity.parse(data.get("severity"), None) if data.get("severity") else None
    return {"verdict": verdict, "confidence": confidence, "severity": severity,
            "explanation": str(data.get("explanation", "")).strip(), "fix": strip_fences(str(data.get("fix") or ""))}


class AIReviewer:
    def __init__(self, cfg: Dict[str, Any], cache_get: Optional[Callable[[str], Optional[str]]] = None,
                 cache_set: Optional[Callable[[str, str], None]] = None):
        self.cfg = cfg.get("ai") or {}
        self.cache_get = cache_get or (lambda key: None)
        self.cache_set = cache_set or (lambda key, value: None)
        self.provider, self.model, self.base_url, self.api_key, self.reason = self._resolve()
        self._client = None

    # -- setup -------------------------------------------------------------- #
    def _resolve(self) -> Tuple[Optional[str], str, Optional[str], Optional[str], str]:
        if not self.cfg.get("enabled", True):
            return None, "", None, None, "AI review disabled in config"
        provider = (self.cfg.get("provider") or os.getenv("LLM_PROVIDER") or "").lower().strip()
        if not provider:
            if os.getenv("GROQ_API_KEY"):
                provider = "groq"
            elif os.getenv("OPENAI_API_KEY"):
                provider = "openai"
            elif os.getenv("LLM_API_KEY") and os.getenv("LLM_BASE_URL"):
                provider = "openai"
            else:
                return None, "", None, None, "no AI provider configured (set GROQ_API_KEY or OPENAI_API_KEY in .env)"
        if provider not in PROVIDERS:
            return None, "", None, None, f"unknown AI provider {provider!r}"
        default_url, key_env, default_model = PROVIDERS[provider]
        api_key = os.getenv("LLM_API_KEY") or (os.getenv(key_env) if key_env else None)
        if provider == "ollama":
            api_key = api_key or "ollama"
        if not api_key:
            return None, "", None, None, f"{key_env} is not set"
        model = self.cfg.get("model") or os.getenv("LLM_MODEL") or default_model
        base_url = os.getenv("LLM_BASE_URL") or default_url
        return provider, model, base_url, api_key, ""

    @property
    def available(self) -> bool:
        return self.provider is not None

    def _get_client(self):
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise RuntimeError("the openai package is not installed") from exc
            self._client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=120, max_retries=2)
        return self._client

    # -- calls --------------------------------------------------------------- #
    def complete_json(self, system: str, user: str) -> Dict[str, Any]:
        key = hashlib.sha256(f"{self.provider}|{self.model}|{system}|{user}".encode()).hexdigest()
        cached = self.cache_get(key)
        if cached:
            return {**json.loads(cached), "_cached": True}
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        client = self._get_client()
        try:
            resp = client.chat.completions.create(model=self.model, messages=messages, temperature=0.1,
                                                  response_format={"type": "json_object"})
        except Exception as exc:  # some servers don't support response_format
            if "response_format" not in str(exc).lower() and "json" not in str(exc).lower():
                raise
            resp = client.chat.completions.create(model=self.model, messages=messages, temperature=0.1)
        data = parse_json_object(resp.choices[0].message.content or "")
        self.cache_set(key, json.dumps(data))
        return data

    # -- finding triage ------------------------------------------------------- #
    def select(self, findings: List[Finding]) -> List[Finding]:
        min_sev = Severity.parse(self.cfg.get("min_severity", "MEDIUM"), Severity.MEDIUM)
        chosen = [f for f in findings if f.counts and f.line > 0 and f.category not in SKIP_CATEGORIES
                  and f.severity.rank >= min_sev.rank]
        chosen.sort(key=lambda f: -f.severity.rank)
        return chosen[: int(self.cfg.get("max_findings", 40))]

    def triage_one(self, finding: Finding, root: Path) -> None:
        if not finding.context:
            finding.context, finding.context_start = extract_context(root, finding, int(self.cfg.get("context_lines", 20)))
        if not finding.context:
            return
        start = finding.context_start or 1
        end = start + len(finding.context.splitlines()) - 1
        prompt = TRIAGE_TEMPLATE.format(
            tool=finding.tool, rule=finding.rule_id, severity=finding.severity.value, message=finding.message,
            path=finding.file_path, language=finding.language or "unknown", line=finding.line, start=start, end=end,
            code=numbered(finding.context, start, finding.line),
        )
        result = parse_triage(self.complete_json(TRIAGE_SYSTEM, prompt))
        finding.ai_verdict = result["verdict"]
        finding.ai_confidence = result["confidence"]
        finding.ai_explanation = result["explanation"]
        fix = result["fix"]
        finding.ai_fix = fix if fix and fix.strip() != finding.context.strip() else None
        sure = result["confidence"] >= float(self.cfg.get("override_confidence", 0.8))
        if result["severity"] and sure and result["verdict"] != "FALSE_POSITIVE" and result["severity"] != finding.severity:
            finding.ai_severity = result["severity"]
        if (result["verdict"] == "FALSE_POSITIVE" and self.cfg.get("dismiss_false_positives", True)
                and result["confidence"] >= float(self.cfg.get("dismiss_confidence", 0.8))):
            finding.ai_dismissed = True

    def triage(self, findings: List[Finding], root: Path, progress: Callable[[Dict], None] = lambda e: None) -> Dict[str, Any]:
        selected = self.select(findings)
        errors: List[str] = []
        done = 0
        workers = max(1, int(self.cfg.get("max_workers", 4)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.triage_one, f, root): f for f in selected}
            for fut in as_completed(futures):
                done += 1
                try:
                    fut.result()
                except Exception as exc:
                    errors.append(f"{futures[fut].file_path}:{futures[fut].line}: {exc}")
                progress({"tool": "AI triage", "category": "ai", "status": "running",
                          "message": f"{done}/{len(selected)} findings"})
        return {"analysed": len(selected) - len(errors), "selected": len(selected), "errors": errors[:10],
                "false_positives": sum(1 for f in selected if f.ai_verdict == "FALSE_POSITIVE"),
                "dismissed": sum(1 for f in selected if f.ai_dismissed)}

    # -- whole-file review of changes ---------------------------------------- #
    def review_changes(self, root: Path, added: Dict[str, Dict[int, str]]) -> Tuple[List[Finding], List[str]]:
        max_lines = int(self.cfg.get("file_review_max_lines", 400))
        candidates = [p for p in added if LANGUAGE_BY_EXT.get(Path(p).suffix.lower())][:10]
        findings: List[Finding] = []
        errors: List[str] = []
        for rel in candidates:
            lines = read_lines(root / rel)
            if not lines or len(lines) > max_lines:
                continue
            changed = added[rel]
            listing = "\n".join(f"{'+' if i in changed else ' '}{i:5d} | {t}" for i, t in enumerate(lines, 1))
            language = LANGUAGE_BY_EXT.get(Path(rel).suffix.lower(), "unknown")
            try:
                data = self.complete_json(FILE_REVIEW_SYSTEM, FILE_REVIEW_TEMPLATE.format(path=rel, language=language, code=listing))
            except Exception as exc:
                errors.append(f"{rel}: {exc}")
                continue
            for issue in data.get("issues") or []:
                try:
                    line = int(issue.get("line") or 0)
                except (TypeError, ValueError):
                    continue
                if line not in changed:
                    continue
                findings.append(Finding(
                    tool="AI review", rule_id="ai-review", file_path=rel, line=line,
                    message=str(issue.get("title") or "Possible problem"), category=Category.AI,
                    severity=Severity.parse(issue.get("severity"), Severity.LOW),
                    ai_explanation=str(issue.get("explanation") or ""), language=language,
                    confidence=f"{float(issue.get('confidence') or 0.5):.2f}",
                ))
        return findings, errors
