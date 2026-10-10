# Quality Gates for the Code Reviewer Application

A tiered set of pass/fail checks the reviewer runs against a project or a change set. Each gate returns a result, and the overall verdict is:

- **FAIL**: at least one *blocker* gate failed
- **WARN**: no blockers failed, but at least one *warn* gate failed
- **PASS**: all enabled gates passed

**Guiding principles**

1. Security and correctness gates **block**; maintainability gates **warn**.
2. Hold **new/changed code** to stricter thresholds than legacy code ("Clean as You Code").
3. A missing tool is a **skipped** gate, never a silent pass. Report it clearly.

---

## 1. Gate Summary

| # | Gate | Threshold | Severity | Tools |
|---|------|-----------|----------|-------|
| 1 | Build / compile | Succeeds, no errors | Blocker | `dotnet build`, `mvn compile`, `tsc`, `python -m compileall` |
| 2 | Tests | 100% pass | Blocker | pytest, JUnit, xUnit, Jest |
| 3 | Coverage (new code) | >= 80% | Blocker | coverage.py, JaCoCo, Coverlet, c8 |
| 4 | Coverage (overall) | >= 70% | Warn | same as above |
| 5 | Secrets | 0 findings | Blocker | gitleaks, trufflehog |
| 6 | SAST | 0 high / critical | Blocker | Semgrep, Bandit, SonarQube |
| 7 | Dependency CVEs | 0 high / critical | Blocker | Trivy, `pip-audit`, `npm audit`, OWASP Dependency-Check |
| 8 | Lint | 0 errors | Blocker | Ruff, ESLint, Checkstyle, Roslyn analyzers |
| 9 | Type check | 0 errors | Blocker | mypy, pyright, `tsc --noEmit` |
| 10 | Complexity | <= 15 per function (fail > 25) | Warn / Blocker | Lizard, Radon |
| 11 | Duplication | < 5% | Warn | jscpd |
| 12 | Function / file size | <= 60 lines / <= 500 lines | Warn | Lizard |
| 13 | Debug leftovers | 0 in new code | Warn | Semgrep or regex |
| 14 | Diff size | <= 400 changed lines | Warn | `git diff --shortstat` |
| 15 | Source changed without tests | None | Warn | git diff analysis |

---

## 2. Gate Details

### Correctness

**Build / compile**
- Must succeed with no errors. Treat compiler warnings as errors where practical.
- Commands: `dotnet build`, `mvn -q compile`, `npx tsc --noEmit`, `python -m compileall .`

**Tests**
- All tests must pass (100% pass rate).
- Commands: `pytest`, `mvn test`, `dotnet test`, `npm test`

**Coverage**
- New/changed code: at least 80% (blocker).
- Overall: at least 70% (warning).
- Tools: coverage.py, JaCoCo, Coverlet, c8/nyc

**Type check**
- Zero type errors.
- Commands: `mypy .`, `pyright`, `npx tsc --noEmit`

### Security

**Secrets**
- No API keys, passwords, or tokens committed.
- Command: `gitleaks detect --report-format json --report-path -`

**SAST (static analysis)**
- No high or critical findings.
- Commands: `semgrep --config auto --json`, `bandit -r . -f json`

**Dependency vulnerabilities**
- No known high or critical CVEs.
- Commands: `trivy fs --format json .`, `pip-audit -f json`, `npm audit --json`

### Maintainability

**Lint / format**
- Zero lint errors; formatting consistent.
- Tools: Ruff + Black (Python), ESLint + Prettier (JS/TS), Checkstyle (Java), `dotnet format` (C#)

**Complexity**
- Warn when a function exceeds 15; fail above 25.
- Command: `lizard -C 15 .`

**Duplication**
- Keep duplicated code under 5%.
- Command: `npx jscpd . --reporters json`

**Function / file size**
- Functions up to 60 lines, files up to 500 lines.

### Change Hygiene

**Debug leftovers**
- No `console.log`, `print`, `debugger`, or stray `TODO`/`FIXME` in newly added lines.

**Diff size**
- Warn above 400 changed lines. Large diffs are hard to review well.

**Tests with source changes**
- If source files changed but no test files did, warn.

---

## 3. Configuration File

Keep all thresholds in a single file so each project can tune them.

```yaml
# quality-gates.yml
gates:
  build:        { enabled: true, severity: blocker }
  tests:        { enabled: true, severity: blocker, min_pass_rate: 100 }
  coverage:
    new_code:   { min: 80, severity: blocker }
    overall:    { min: 70, severity: warn }
  secrets:      { max_findings: 0, severity: blocker }
  sast:         { max_high: 0, max_critical: 0, severity: blocker }
  dependencies: { max_high: 0, max_critical: 0, severity: blocker }
  lint:         { max_errors: 0, severity: blocker }
  types:        { max_errors: 0, severity: blocker }
  complexity:   { warn_over: 15, fail_over: 25 }
  duplication:  { max_percent: 5, severity: warn }
  size:         { max_function_lines: 60, max_file_lines: 500, severity: warn }
  diff:         { max_changed_lines: 400, severity: warn }
  debug_leftovers: { severity: warn }
```

---

## 4. Runner Skeleton (Python)

Each gate is a function that runs a CLI tool, parses its output, and returns `{name, passed, details, severity}`.

```python
import subprocess, json, yaml

def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def gate_secrets(cfg):
    code, out, _ = run(["gitleaks", "detect", "--report-format", "json",
                        "--report-path", "-", "--no-banner"])
    findings = json.loads(out or "[]")
    ok = len(findings) <= cfg["max_findings"]
    return {"name": "secrets", "passed": ok,
            "details": f"{len(findings)} found",
            "severity": cfg["severity"]}

GATES = {"secrets": gate_secrets}  # add one function per gate

def evaluate(path="quality-gates.yml"):
    cfg = yaml.safe_load(open(path))["gates"]
    results = [fn(cfg[name]) for name, fn in GATES.items()
               if cfg[name].get("enabled", True)]
    blockers = [r for r in results if not r["passed"] and r["severity"] == "blocker"]
    warnings = [r for r in results if not r["passed"] and r["severity"] == "warn"]
    verdict = "FAIL" if blockers else ("WARN" if warnings else "PASS")
    return verdict, results
```

---

## 5. Implementation Tips

- **Auto-detect the language** from marker files (`pom.xml`, `*.csproj`, `package.json`, `pyproject.toml`) and choose the matching tool per gate.
- **Run fast gates first** (secrets, lint, types), then tests, then slow scans. Offer a fail-fast mode.
- **Gate on changed files** using `git diff --name-only <base>` so legacy code does not block new work.
- **Report per gate**: pass/fail, count, and the top 5 offending files with line numbers, not just a verdict.
- **Support a baseline file** so existing issues are ignored and only new ones fail.
- **Mark missing tools as skipped**, and say so in the report.
- **Use pre-commit hooks** to run the cheap gates before code reaches the reviewer.

---

## 6. Suggested Rollout

1. **Phase 1 (core):** build, tests, secrets, lint.
2. **Phase 2 (security):** SAST, dependency CVEs, type checks.
3. **Phase 3 (quality):** coverage, complexity, duplication, size.
4. **Phase 4 (hygiene):** diff size, debug leftovers, tests-with-source check, baseline support.
