"""Security scanners: Semgrep and Bandit (SAST), secrets, and Trivy (dependency CVEs)."""
from __future__ import annotations

import json
import math
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import List, Optional

from app.core.models import Category, Finding, Severity
from app.scanners.base import (
    TEXT_EXTS, ScanContext, Scanner, ToolMissing, chunks, exclude_patterns, find_tool, is_excluded,
    mask_line, mask_secret, read_lines, run_tool, source_line, to_rel,
)

# --------------------------------------------------------------------------- #
# Semgrep
# --------------------------------------------------------------------------- #

SEMGREP_LANGUAGE_PACKS = {
    "python": "p/python", "javascript": "p/javascript", "typescript": "p/typescript", "java": "p/java",
    "csharp": "p/csharp", "go": "p/golang", "ruby": "p/ruby", "php": "p/php", "kotlin": "p/kotlin",
    "rust": "p/rust", "scala": "p/scala", "swift": "p/swift", "c": "p/c", "cpp": "p/c",
}
SEMGREP_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW,
                    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
# Semgrep returns this instead of the code when you aren't logged in.
SEMGREP_PLACEHOLDER = "requires login"


def parse_semgrep(output: str, root: Path, drop_low_confidence: bool = True) -> List[Finding]:
    data = json.loads(output or "{}")
    findings = []
    for res in data.get("results", []):
        extra = res.get("extra") or {}
        meta = extra.get("metadata") or {}
        check_id = res.get("check_id", "unknown")
        severity = SEMGREP_SEVERITY.get(str(extra.get("severity", "INFO")).upper(), Severity.LOW)
        confidence = str(meta.get("confidence") or "").upper() or None
        if confidence == "LOW":
            if drop_low_confidence:
                continue
            severity = severity.lower()
        rel = to_rel(res.get("path", ""), root)
        line = int((res.get("start") or {}).get("line") or 0)
        snippet = extra.get("lines") or ""
        if not snippet.strip() or snippet.strip() == SEMGREP_PLACEHOLDER:
            snippet = source_line(root, rel, line)
        is_secret = ".secrets." in check_id or "secret" in str(meta.get("subcategory", "")).lower()
        refs = meta.get("references") or []
        findings.append(Finding(
            tool="Semgrep", rule_id=check_id, file_path=rel, line=line,
            column=(res.get("start") or {}).get("col"), end_line=(res.get("end") or {}).get("line"),
            message=extra.get("message", "").strip(), severity=Severity.HIGH if is_secret else severity,
            category=Category.SECRETS if is_secret else Category.SAST,
            code_snippet=mask_line(snippet) if is_secret else snippet.strip(),
            confidence=confidence, url=(meta.get("source") or (refs[0] if refs else None)),
            extra={"cwe": meta.get("cwe"), "owasp": meta.get("owasp")},
        ))
    return findings


class SemgrepScanner(Scanner):
    name = "Semgrep"
    category = "sast"

    def scan(self, ctx: ScanContext):
        semgrep = find_tool("semgrep", ctx.config, python_module="semgrep")
        cfg = ctx.config.get("semgrep") or {}
        configs = list(cfg.get("configs") or [])
        for lang in ctx.languages:
            pack = SEMGREP_LANGUAGE_PACKS.get(lang)
            if pack and pack not in configs:
                configs.append(pack)
        cmd = semgrep + ["scan", "--json", "--quiet", "--metrics", "off", "--timeout", "30"]
        for c in configs:
            cmd += ["--config", c]
        for pattern in exclude_patterns(ctx.root, ctx.config):
            cmd += ["--exclude", pattern]
        cmd.append(".")
        proc = run_tool(cmd, ctx.root, timeout=int(cfg.get("timeout_seconds", 900)),
                        env={"SEMGREP_SEND_METRICS": "off"})
        if not proc.stdout.strip().startswith("{"):
            return self.error(proc.stderr or f"semgrep exited with {proc.returncode}")
        findings = parse_semgrep(proc.stdout, ctx.root, bool(cfg.get("drop_low_confidence", True)))
        return self.ran(findings, f"rulesets: {', '.join(configs)}")


# --------------------------------------------------------------------------- #
# Bandit
# --------------------------------------------------------------------------- #

def parse_bandit(output: str, root: Path, drop_low_confidence: bool = True) -> List[Finding]:
    data = json.loads(output or "{}")
    findings = []
    for res in data.get("results", []):
        severity = Severity.parse(res.get("issue_severity"), Severity.LOW)
        confidence = str(res.get("issue_confidence") or "").upper() or None
        if confidence == "LOW":
            if drop_low_confidence:
                continue
            severity = severity.lower()
        cwe = (res.get("issue_cwe") or {}).get("id")
        findings.append(Finding(
            tool="Bandit", rule_id=f"{res.get('test_id')}:{res.get('test_name')}",
            file_path=to_rel(res.get("filename", ""), root), line=int(res.get("line_number") or 0),
            column=res.get("col_offset"), end_line=(res.get("line_range") or [None])[-1],
            message=res.get("issue_text", ""), severity=severity, category=Category.SAST,
            code_snippet=None, confidence=confidence, url=res.get("more_info"),
            extra={"cwe": f"CWE-{cwe}" if cwe else None},
        ))
    return findings


class BanditScanner(Scanner):
    name = "Bandit"
    category = "sast"
    languages = ("python",)

    def scan(self, ctx: ScanContext):
        bandit = find_tool("bandit", ctx.config, python_module="bandit")
        cfg = ctx.config.get("bandit") or {}
        skip = ",".join(cfg.get("skip") or [])
        files = ctx.files_for("python")
        findings: List[Finding] = []
        for batch in chunks(files):
            cmd = bandit + ["-f", "json", "-q"] + (["--skip", skip] if skip else []) + list(batch)
            proc = run_tool(cmd, ctx.root)
            if not proc.stdout.strip().startswith("{"):
                return self.error(proc.stderr or f"bandit exited with {proc.returncode}")
            findings.extend(parse_bandit(proc.stdout, ctx.root, bool(cfg.get("drop_low_confidence", True))))
        return self.ran(findings, f"{len(files)} files")


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #

def is_test_path(rel: str, patterns: List[str]) -> bool:
    parts = [p.lower() for p in re.split(r"[\\/]", rel)]
    stem = Path(rel).stem.lower()
    return any(p in patterns for p in parts) or stem.startswith("test_") or stem.endswith(("_test", ".test", ".spec"))


def parse_gitleaks(output: str, root: Path, test_patterns: List[str]) -> List[Finding]:
    findings = []
    for leak in json.loads(output or "[]") or []:
        rel = to_rel(leak.get("File", ""), root)
        test_data = is_test_path(rel, test_patterns)
        match = leak.get("Match") or ""
        secret = leak.get("Secret") or ""
        shown = match.replace(secret, mask_secret(secret)) if secret and secret != "REDACTED" else match
        findings.append(Finding(
            tool="Gitleaks", rule_id=leak.get("RuleID", "secret"), file_path=rel,
            line=int(leak.get("StartLine") or 0), end_line=leak.get("EndLine"),
            message=f"{leak.get('Description') or 'Secret'} committed to the code",
            severity=Severity.LOW if test_data else Severity.HIGH, category=Category.SECRETS,
            code_snippet=mask_line(shown), confidence="LOW" if test_data else "HIGH",
            extra={"entropy": leak.get("Entropy"), "test_data": test_data},
        ))
    return findings


# Built-in fallback: provider-specific formats plus high-entropy assignments.
PROVIDER_PATTERNS = {
    "aws-access-key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "gitlab-token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe-live-key": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "groq-api-key": re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"),
    "openai-api-key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b"),
    "anthropic-api-key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"),
    "private-key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}
GENERIC_ASSIGNMENT = re.compile(
    r"""(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?key|private[_-]?key|auth|credential)s?[A-Za-z0-9_.-]*)\s*[:=]\s*(['"])([^'"\s]{8,})\2"""
)
PLACEHOLDER = re.compile(
    r"(?i)^(x+|\*+|changeme|change_me|password|secret|example|sample|dummy|test|testing|placeholder|todo|none|null|"
    r"your[_-].*|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|.*example.*|.*here)$"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def builtin_secret_scan(root: Path, files: List[str], test_patterns: List[str]) -> List[Finding]:
    findings = []
    for rel in files:
        suffix = Path(rel).suffix.lower()
        if suffix not in TEXT_EXTS and not Path(rel).name.startswith(".env"):
            continue
        test_data = is_test_path(rel, test_patterns)
        for no, line in enumerate(read_lines(root / rel), 1):
            if len(line) > 1000:
                continue
            hit: Optional[tuple] = None
            for rule, pattern in PROVIDER_PATTERNS.items():
                if pattern.search(line):
                    hit = (rule, Severity.HIGH, "HIGH")
                    break
            if not hit:
                m = GENERIC_ASSIGNMENT.search(line)
                if m:
                    value = m.group(3)
                    if not PLACEHOLDER.match(value) and shannon_entropy(value) >= 3.5:
                        hit = ("generic-secret", Severity.HIGH, "MEDIUM")
            if not hit:
                continue
            rule, sev, conf = hit
            if test_data:
                sev, conf = Severity.LOW, "LOW"
            findings.append(Finding(
                tool="SecretPatterns", rule_id=rule, file_path=rel, line=no,
                message=f"Possible {rule.replace('-', ' ')} committed to the code",
                severity=sev, category=Category.SECRETS, code_snippet=mask_line(line.strip()),
                confidence=conf, extra={"test_data": test_data},
            ))
    return findings


class SecretsScanner(Scanner):
    name = "Gitleaks"
    category = "secrets"

    def scan(self, ctx: ScanContext):
        test_patterns = list((ctx.config.get("secrets") or {}).get("test_path_patterns") or [])
        try:
            gitleaks = find_tool("gitleaks", ctx.config)
        except ToolMissing:
            self.name = "SecretPatterns"
            findings = builtin_secret_scan(ctx.root, ctx.files, test_patterns)
            return self.ran(findings, "gitleaks not installed; used built-in patterns (less accurate)")
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "gitleaks.json")
            common = ["--report-format", "json", "--report-path", report, "--redact", "--no-banner", "--exit-code", "0"]
            proc = run_tool(gitleaks + ["dir", "."] + common, ctx.root)
            if proc.returncode != 0 and "unknown command" in (proc.stderr + proc.stdout).lower():
                proc = run_tool(gitleaks + ["detect", "--source", ".", "--no-git"] + common, ctx.root)
            if not os.path.isfile(report):
                return self.error(proc.stderr or f"gitleaks exited with {proc.returncode}")
            with open(report, encoding="utf-8") as fh:
                raw = fh.read()
        patterns = exclude_patterns(ctx.root, ctx.config)
        findings = [f for f in parse_gitleaks(raw, ctx.root, test_patterns) if not is_excluded(f.file_path, patterns)]
        return self.ran(findings)


# --------------------------------------------------------------------------- #
# Trivy (dependency CVEs)
# --------------------------------------------------------------------------- #

def _manifest_line(root: Path, target: str, package: str) -> int:
    needle = re.compile(rf"(^|[\"'\s/]){re.escape(package)}([\"'\s=<>~!@:\[]|$)", re.IGNORECASE)
    for no, line in enumerate(read_lines(root / target), 1):
        if needle.search(line):
            return no
    return 0


def parse_trivy(output: str, root: Path) -> List[Finding]:
    data = json.loads(output or "{}")
    findings = []
    for block in data.get("Results") or []:
        target = to_rel(block.get("Target", ""), root)
        for vuln in block.get("Vulnerabilities") or []:
            sev_raw = str(vuln.get("Severity", "UNKNOWN")).upper()
            severity = Severity.parse(sev_raw, Severity.INFO)
            pkg = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion") or ""
            title = vuln.get("Title") or vuln.get("Description", "")[:160]
            fix_text = f"upgrade to {fixed}" if fixed else "no fixed version yet"
            findings.append(Finding(
                tool="Trivy", rule_id=vuln.get("VulnerabilityID", "unknown"), file_path=target,
                line=_manifest_line(root, target, pkg), category=Category.DEPENDENCIES, severity=severity,
                message=f"{pkg} {installed}: {title} ({fix_text})", url=vuln.get("PrimaryURL"),
                extra={"package": pkg, "installed": installed, "fixed": fixed},
            ))
    return findings


class TrivyScanner(Scanner):
    name = "Trivy"
    category = "dependencies"

    def scan(self, ctx: ScanContext):
        trivy = find_tool("trivy", ctx.config)
        cmd = trivy + ["fs", "--format", "json", "--scanners", "vuln", "--quiet", "--timeout", "15m"]
        for pattern in exclude_patterns(ctx.root, ctx.config):
            pat = pattern.strip("/").replace("\\", "/")
            # Only skip folders: file patterns (e.g. *.lock, package-lock.json) are
            # exactly the lockfiles Trivy needs to read.
            if "." in pat.lstrip(".") and "/" not in pat:
                continue
            cmd += ["--skip-dirs", f"**/{pat}"]
        cmd.append(".")
        proc = run_tool(cmd, ctx.root, timeout=1200)
        if not proc.stdout.strip().startswith("{"):
            return self.error(proc.stderr or f"trivy exited with {proc.returncode}")
        findings = parse_trivy(proc.stdout, ctx.root)
        return self.ran(findings)
