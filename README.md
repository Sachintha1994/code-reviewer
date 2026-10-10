# Code Reviewer

Runs security, quality and dependency checks on a codebase, asks an AI to weed out
false positives, and gives one verdict: **PASS**, **WARN** or **FAIL**. Results are
shown in a web dashboard, exported as PDF, or printed on the command line for CI.

The gates and thresholds follow [QUALITY_GATES.md](QUALITY_GATES.md) and are set in
[quality-gates.yml](quality-gates.yml).

## Quick start (Windows)

```powershell
cd "C:\Users\<you>\Desktop\Code reviewer"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env          # then add GROQ_API_KEY or OPENAI_API_KEY (optional)

uvicorn app.web_dashboard:app --reload
```

Open http://127.0.0.1:8000, click **Add project**, pick a folder or GitHub URL, then **Run scan**.

From the command line:

```powershell
python main.py C:\path\to\project                  # whole project
python main.py C:\path\to\project --base main      # only code changed since main
python main.py C:\path\to\project --json result.json --no-ai
```

The command exits with 1 on FAIL (add `--strict` to fail on WARN too), so it can gate a CI job or a pre-commit hook.

## What it checks

| Gate | Tool | Blocks? |
|---|---|---|
| Build | Maven (Java), Python compiler, `tsc` | yes |
| Tests, coverage | Maven + JaCoCo, pytest + pytest-cov, Codecov | yes (new code ≥ 80%), warn (overall ≥ 70%) |
| Secrets | gitleaks (built-in patterns if missing) | yes |
| SAST | Semgrep, Bandit | yes, on high/critical |
| Dependency CVEs | Trivy (turned off by default: see `disabled_scanners`) | yes, on high/critical |
| Lint | PMD (Java), Ruff (Flake8 fallback), ESLint | yes, on real bugs only; style issues don't block |
| Type check | mypy (Java and TypeScript are checked by their compilers) | yes |
| Complexity | Lizard (Radon fallback) | warn over 15, block over 25 |
| Duplication | jscpd | warn over 5% |
| Function/file size | Lizard | warn |
| Debug leftovers, diff size, tests with source | git diff | warn (needs `--base`) |
| SonarQube | SonarQube API | yes, if configured |

**A tool that isn't installed is shown as skipped, never as a pass.** A skipped blocker gate
keeps the verdict at WARN, because nothing proved that part of the code is safe. The
dashboard's **Installed tools** panel shows what's available.

### Installing the external tools

- **Semgrep:** `pip install semgrep`. Native Windows support is still limited; if it fails,
  run the reviewer inside WSL.
- **gitleaks** and **Trivy:** download the Windows release and put `gitleaks.exe` and
  `trivy.exe` next to `main.py`, or anywhere on PATH, or set `tools.trivy` / `tools.gitleaks`
  in `quality-gates.yml`. Trivy downloads its vulnerability database on first run.
- **jscpd:** needs Node.js, then `npm install -g jscpd`.
- **Java projects:** Maven and a JDK on PATH (or an `mvnw` wrapper in the project). One Maven
  run compiles the code, runs the tests and measures coverage with JaCoCo, without changing
  the project's `pom.xml`. For lint, download PMD 7 from https://pmd.github.io, unzip it and
  add its `bin` folder to PATH (or set `tools.pmd` in `quality-gates.yml`).
- **Turning a scanner off:** list it in `disabled_scanners` in `quality-gates.yml`.

## How it keeps results accurate

- **Real rule codes and severities.** `F821` (undefined name) blocks; `E501` (long line) doesn't.
- **Excluded folders.** `venv`, `node_modules`, build output, vendored code and similar are
  never scanned. Add more to `exclude` in `quality-gates.yml` or a `.reviewerignore` file in
  the project.
- **De-duplication.** When Semgrep and Bandit (or Ruff and mypy) report the same problem, it's
  shown once, listing both tools.
- **Scanner confidence.** Low-confidence Semgrep and Bandit results are dropped by default.
- **Secrets are masked** in the dashboard, the PDF and anything sent to the AI.
- **Inline ignores.** Add `# reviewer: ignore` (or `# reviewer: ignore[rule-or-category] reason`)
  on the line or the line above.
- **False positives and ignores** marked in the dashboard are remembered per project and the
  verdict is recalculated straight away.
- **Baseline.** *Set baseline* treats today's findings as known debt so only new issues count.
- **Changed code only.** Give a base branch (`--base main`, or in the project settings) to
  review just the lines that changed.
- **AI triage.** Each medium-or-worse finding is sent with its surrounding function. The AI
  answers true or false positive, with a confidence, an explanation and a fix. Confident false
  positives (≥ 0.8 by default) move to a separate list and stop counting. The scanner's
  severity only changes when the AI is confident. With a base branch, changed files also get a
  whole-file AI review for logic bugs scanners can't see. Results are cached, so re-scans are
  cheap.
- **Health score** is based on weighted findings per 1,000 lines, so large healthy projects
  aren't punished for their size. FAIL caps it at 69 and WARN at 89.

## Measuring accuracy

`tools/benchmark.py` runs the reviewer on a project whose real issues you've labelled, and
reports precision (how much of the output is real) and recall (how much it catches):

```powershell
python tools/benchmark.py benchmarks/sample_project.labels.json
```

To build a stronger benchmark, label findings in deliberately vulnerable apps such as
OWASP Juice Shop, DVWA or PyGoat, and in a couple of clean projects of your own. Rerun the
benchmark after changing rules or thresholds.

## Tests

```powershell
pytest
```

## Configuration

Everything is in `quality-gates.yml`: gate thresholds and which gates block, excluded folders,
Semgrep rulesets, AI settings (provider, model, confidence thresholds) and the folders the
dashboard may scan (`server.allowed_roots`, your home folder by default). A project can override
any value with its own `quality-gates.yml` in its root.

API keys only come from environment variables or `.env`, never from code.

## Project layout

```
main.py                    command line
quality-gates.yml          gates, thresholds, excludes, AI settings
app/web_dashboard.py       FastAPI app and API
app/web/                   dashboard page, styles and script (no CDN needed)
app/core/orchestrator.py   runs scanners, merges findings, evaluates gates
app/core/gates.py          gates, verdict, health score
app/core/findings.py       excludes, de-duplication, ignores, baseline, diff filter
app/core/llm_analyzer.py   AI triage and file review
app/core/storage.py        SQLite: projects, scan history, ignores, baselines, AI cache
app/scanners/              one module per family of tools
app/reports/pdf_report.py  PDF export
tools/benchmark.py         precision and recall
tests/                     unit and end-to-end tests
```

Data (database, cloned repos, PDFs) is stored in `data/`.
