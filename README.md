# AI Code Reviewer

An AI code reviewer. Give it a project and, optionally, a base branch (for example `main` or
`pm-dev`):

- **With a branch**, it reviews only the code changed since that branch, the way a senior
  engineer reviews a pull request.
- **Without a branch**, it reviews the whole project.

Each file goes to the AI (Gemini, Groq, OpenAI or a local Ollama model) with the lines to
review marked, and the dashboard shows the issues it finds with an explanation and a suggested fix.

## Quick start (Windows)

```powershell
cd "C:\Users\<you>\Desktop\Code reviewer"
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
copy .env.example .env        # then add GEMINI_API_KEY (or GROQ_API_KEY / OPENAI_API_KEY)

python -m uvicorn app.web_dashboard:app --reload
```

Open http://127.0.0.1:8000, click **Add project**, choose a folder (and a branch to compare
with, if you want to review only changes), then click **Run review**.

From the command line:

```powershell
python main.py C:\path\to\project --base main      # changes since main
python main.py C:\path\to\project                  # the whole project
python main.py C:\path\to\project --base pm-dev --json review.json
```

It exits with 1 when changes are requested (add `--strict` to also fail on medium issues),
so it can run in CI or a pre-commit hook.

## What it does

1. Finds the code to review: everything changed since the base branch (`git diff`, including
   uncommitted and new files), or every source and config file when no branch is set.
   Whole-project reviews are capped at `ai.max_files` files per run (80 by default).
2. Sends each changed source or config file to the AI. Files up to 400 lines go whole; larger
   files go as the changed sections with 25 lines around them. Changed lines are marked so the
   AI reviews only those and uses the rest as context.
3. Keeps issues that point at a changed line and that the AI is reasonably sure of
   (`min_confidence`), and removes duplicates.
4. Writes a short summary of the whole change, and a verdict:
   - **Changes requested:** at least one critical or high-severity issue.
   - **Approve with comments:** medium issues only.
   - **Looks good:** nothing, or only minor suggestions.

Secrets that look real (API keys, tokens, random-looking passwords) are masked before any code
is sent to the AI. Results are cached, so re-reviewing an unchanged file costs nothing.

## Handling issues

- **False positive** or **Ignore** in the dashboard: remembered for the project, and the
  verdict updates straight away.
- `// reviewer: ignore <reason>` (any comment style) on the line, or the line above, ignores
  an issue in the code itself.

## Settings

`reviewer.yml` holds the AI provider and model (Gemini, Groq, OpenAI or a local Ollama model; set `ai.model` to switch models, e.g. a Gemini Pro model for deeper reviews), what the AI should look for (`ai.focus`, edit
it to match your team's standards), size limits, excluded folders and the folders the dashboard
may open. A project can override any value with its own `reviewer.yml` in its root, and
exclude files with a `.reviewerignore`.

API keys only come from `.env` or environment variables, never from code.

## Tests

```powershell
python -m pytest
```

## Project layout

```
main.py                    command line
reviewer.yml               AI settings, focus areas, limits, excludes
app/web_dashboard.py       FastAPI app and API
app/web/                   dashboard page, styles and script (works offline)
app/core/orchestrator.py   finds changes, runs the AI review, builds the result
app/core/ai_review.py      prompts, chunking, provider setup
app/core/findings.py       duplicates, ignores, fingerprints, verdict
app/core/diff.py           git diff parsing
app/core/storage.py        SQLite: projects, review history, ignored issues, AI cache
app/reports/pdf_report.py  PDF export
tests/                     tests (the AI is replaced by a fake)
```
