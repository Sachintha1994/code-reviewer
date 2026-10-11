"""AI review of changed code.

Each changed file is sent with its changed lines marked; the AI returns issues
as JSON. Keys come from the environment or .env, never from code:
  GEMINI_API_KEY / GROQ_API_KEY / OPENAI_API_KEY / LLM_API_KEY, LLM_PROVIDER, LLM_MODEL, LLM_BASE_URL
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from app.core.files import language_of, mask_secrets, read_lines
from app.core.models import CATEGORIES, Finding, Severity

PROVIDERS = {
    # provider: (base_url, api key env var, default model)
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY", "gemini-3.8-flash"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", "llama-3.3-70b-versatile"),
    "openai": (None, "OPENAI_API_KEY", "gpt-4o-mini"),
    "ollama": ("http://localhost:11434/v1", None, "qwen2.5-coder:7b"),
}

REVIEW_SYSTEM = (
    "You are a senior software engineer doing a careful code review of a change. Review only the lines "
    "marked + (added or changed); unmarked lines are context. Report real problems a strong reviewer would "
    "block or comment on, with the exact line. Do not report formatting, naming taste, or things you cannot "
    "see in the code shown. If the change looks correct, return no issues. Reply with one JSON object only."
)

REVIEW_TEMPLATE = """{intro}
{part}Lines starting with + are the ones to review; other lines are context. "..." separates sections that are not next to each other.

```
{code}
```

Look for:
{focus}

Return JSON:
{{"issues": [{{
  "line": <first line number of the problem>,
  "end_line": <last line number of the problem>,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "category": one of {categories},
  "title": "short description, under 80 characters",
  "explanation": "1-3 sentences: what goes wrong, when, and why it matters",
  "confidence": <0 to 1, how sure you are this is a real problem>,
  "fix": "the corrected code for lines line..end_line exactly as they should read, same indentation, no line numbers or + signs; empty string if the fix isn't a local code change"
}}]}}
Severity guide: CRITICAL = security hole or data loss; HIGH = bug that will hit users; MEDIUM = likely problem or risky code; LOW = minor improvement."""

SUMMARY_SYSTEM = "You summarise code changes for a reviewer. Plain, specific, no marketing language. Reply with one JSON object only."
SUMMARY_TEMPLATE = """{heading}:
{files}

Excerpts of the code:
```
{excerpt}
```

Issues found by the review:
{issues}

Return JSON: {{"summary": "2-4 sentences: {ask}, and the main risks a reviewer should look at"}}"""


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #

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


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.5) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# Building what the AI sees
# --------------------------------------------------------------------------- #

def build_chunks(total_lines: int, changed: Set[int], whole_file_up_to: int, context: int,
                 max_lines: int) -> List[List[int]]:
    """Line numbers to send, split into requests. Small files go whole; larger ones as
    windows of `context` lines around the changes, packed into requests of `max_lines`."""
    if not changed or total_lines == 0:
        return []
    if total_lines <= whole_file_up_to:
        return [list(range(1, total_lines + 1))]
    windows: List[Tuple[int, int]] = []
    for n in sorted(changed):
        lo, hi = max(1, n - context), min(total_lines, n + context)
        if windows and lo <= windows[-1][1] + 1:
            windows[-1] = (windows[-1][0], max(windows[-1][1], hi))
        else:
            windows.append((lo, hi))
    chunks: List[List[int]] = []
    current: List[int] = []
    for lo, hi in windows:
        # a single window bigger than a request is split
        for start in range(lo, hi + 1, max_lines):
            piece = list(range(start, min(hi, start + max_lines - 1) + 1))
            if current and len(current) + len(piece) > max_lines:
                chunks.append(current)
                current = []
            current.extend(piece)
    if current:
        chunks.append(current)
    return chunks


def render_chunk(lines: List[str], numbers: List[int], changed: Set[int]) -> str:
    out = []
    previous = None
    for n in numbers:
        if previous is not None and n != previous + 1:
            out.append("   ...")
        mark = "+" if n in changed else " "
        out.append(f"{mark}{n:5d} | {mask_secrets(lines[n - 1])}")
        previous = n
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Reviewer
# --------------------------------------------------------------------------- #

class AIReviewer:
    def __init__(self, cfg: Dict[str, Any], cache_get: Optional[Callable[[str], Optional[str]]] = None,
                 cache_set: Optional[Callable[[str, str], None]] = None):
        self.cfg = cfg.get("ai") or {}
        self.cache_get = cache_get or (lambda key: None)
        self.cache_set = cache_set or (lambda key, value: None)
        self.provider, self.model, self.base_url, self.api_key, self.reason = self._resolve()
        self._client = None
        self._json_mode = True   # turned off if the provider rejects response_format

    def _resolve(self) -> Tuple[Optional[str], str, Optional[str], Optional[str], str]:
        provider = (self.cfg.get("provider") or os.getenv("LLM_PROVIDER") or "").lower().strip()
        if not provider:
            if os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"):
                provider = "gemini"
            elif os.getenv("GROQ_API_KEY"):
                provider = "groq"
            elif os.getenv("OPENAI_API_KEY") or (os.getenv("LLM_API_KEY") and os.getenv("LLM_BASE_URL")):
                provider = "openai"
            else:
                return None, "", None, None, "no AI key configured: add GEMINI_API_KEY (or GROQ_API_KEY / OPENAI_API_KEY) to the .env file"
        if provider not in PROVIDERS:
            return None, "", None, None, f"unknown AI provider {provider!r} (use gemini, groq, openai or ollama)"
        default_url, key_env, default_model = PROVIDERS[provider]
        api_key = os.getenv("LLM_API_KEY") or (os.getenv(key_env) if key_env else None)
        if provider == "gemini":
            api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if provider == "ollama":
            api_key = api_key or "ollama"
        if not api_key:
            return None, "", None, None, f"{key_env} is not set in .env"
        model = self.cfg.get("model") or os.getenv("LLM_MODEL") or default_model
        return provider, model, os.getenv("LLM_BASE_URL") or default_url, api_key, ""

    @property
    def available(self) -> bool:
        return self.provider is not None

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.model}" if self.available else ""

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=180, max_retries=3)
        return self._client

    def complete_json(self, system: str, user: str) -> Tuple[Dict[str, Any], bool]:
        """Returns (parsed JSON, came_from_cache)."""
        key = hashlib.sha256(f"{self.provider}|{self.model}|{system}|{user}".encode()).hexdigest()
        cached = self.cache_get(key)
        if cached:
            return json.loads(cached), True
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        client = self._get_client()
        resp = None
        if self._json_mode:
            try:
                resp = client.chat.completions.create(model=self.model, messages=messages, temperature=0.1,
                                                      response_format={"type": "json_object"})
            except Exception as exc:
                # Some providers reject JSON mode with a 400; the prompt already asks for JSON only.
                text = str(exc).lower()
                if getattr(exc, "status_code", None) not in (400, 422) and "response_format" not in text and "json" not in text:
                    raise
                self._json_mode = False
        if resp is None:
            resp = client.chat.completions.create(model=self.model, messages=messages, temperature=0.1)
        data = parse_json_object(resp.choices[0].message.content or "")
        self.cache_set(key, json.dumps(data))
        return data, False

    # -- one file ------------------------------------------------------------- #
    def review_file(self, root: Path, rel: str, changed: Set[int], base_ref: str) -> Tuple[List[Finding], int, bool]:
        """Review one changed file. Returns (issues, number of requests, all from cache)."""
        lines = read_lines(root / rel)
        chunks = build_chunks(len(lines), {n for n in changed if 1 <= n <= len(lines)},
                              int(self.cfg.get("whole_file_up_to", 400)), int(self.cfg.get("context_lines", 25)),
                              int(self.cfg.get("max_lines_per_request", 600)))
        language = language_of(rel) or "text"
        focus = "\n".join(f"- {item}" for item in (self.cfg.get("focus") or ["bugs", "security problems"]))
        findings: List[Finding] = []
        all_cached = True
        for i, numbers in enumerate(chunks):
            part = f"Part {i + 1} of {len(chunks)} of this file. " if len(chunks) > 1 else ""
            intro = (f"Change: {rel} ({language}), compared with {base_ref}." if base_ref else
                     f"File: {rel} ({language}). Whole-file review of existing code: every line is in scope.")
            prompt = REVIEW_TEMPLATE.format(intro=intro, part=part,
                                            code=render_chunk(lines, numbers, changed), focus=focus,
                                            categories=" | ".join(f'"{c}"' for c in CATEGORIES))
            data, cached = self.complete_json(REVIEW_SYSTEM, prompt)
            all_cached = all_cached and cached
            findings.extend(self._to_findings(data, rel, lines, set(numbers), changed, language))
        return findings, len(chunks), all_cached and bool(chunks)

    def _to_findings(self, data: Dict[str, Any], rel: str, lines: List[str], shown: Set[int],
                     changed: Set[int], language: str) -> List[Finding]:
        out = []
        min_conf = float(self.cfg.get("min_confidence", 0.5))
        for issue in data.get("issues") or []:
            if not isinstance(issue, dict):
                continue
            line = _int(issue.get("line"))
            end = max(line, _int(issue.get("end_line"), line))
            confidence = _float(issue.get("confidence"))
            # keep issues that touch a changed line the AI was actually shown
            if line not in shown or not any(line <= n <= end for n in changed) or confidence < min_conf:
                continue
            end = min(end, len(lines))
            category = str(issue.get("category", "bug")).lower().strip()
            fix = strip_fences(str(issue.get("fix") or "")).rstrip()
            original = "\n".join(lines[line - 1:end])
            out.append(Finding(
                file_path=rel, line=line, end_line=end,
                severity=Severity.parse(issue.get("severity"), Severity.LOW),
                category=category if category in CATEGORIES else "bug",
                title=str(issue.get("title") or "Possible problem").strip()[:200],
                explanation=str(issue.get("explanation") or "").strip(),
                confidence=confidence, language=language,
                fix=fix if fix and fix.strip() != original.strip() else None,
            ))
        return out

    # -- whole change ----------------------------------------------------------- #
    def summarize(self, base_ref: str, added: Dict[str, Dict[int, str]], findings: List[Finding]) -> str:
        files = "\n".join(f"- {p} (+{len(lines)} lines)" for p, lines in list(added.items())[:80])
        excerpt_lines: List[str] = []
        for path, lines in added.items():
            excerpt_lines.append(f"# {path}")
            excerpt_lines.extend(mask_secrets(text) for _, text in sorted(lines.items())[:40])
            if len(excerpt_lines) > 300:
                break
        issues = "\n".join(f"- {f.severity.value} {f.file_path}:{f.line} {f.title}" for f in findings[:40]) or "- none"
        data, _ = self.complete_json(SUMMARY_SYSTEM, SUMMARY_TEMPLATE.format(
            heading=f"Files changed (compared with {base_ref})" if base_ref else "Files reviewed (whole project)",
            ask="what this change does" if base_ref else "what this code does",
            files=files, excerpt="\n".join(excerpt_lines[:300]), issues=issues))
        return str(data.get("summary") or "").strip()
