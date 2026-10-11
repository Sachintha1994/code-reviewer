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

Open http://127.0.0.1:8000, click **Add project** and pick a source:

- **Local git repo:** a folder on your computer, plus a branch to compare with if you want to
  review only the changes.
- **GitHub URL:** the repository is cloned first.
- **ZIP file:** upload a ZIP of the code; the whole project inside it is reviewed. Use
  **Settings → Upload a new version** to review an updated ZIP later.

Then click **Run review**.

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
2. Sends the changed source and config files to the AI. Files up to 400 lines go whole; larger
   files go as the changed sections with 25 lines around them. Changed lines are marked so the
   AI reviews only those and uses the rest as context. Small files are packed together into one
   request (up to `ai.max_lines_per_request` lines; by default 2500 for Gemini), so even a large
   project needs only a few dozen requests.
3. Keeps issues that point at a changed line and that the AI is reasonably sure of
   (`min_confidence`), and removes duplicates.
4. Writes a short summary of the whole change, and a verdict:
   - **Changes requested:** at least one critical or high-severity issue.
   - **Approve with comments:** medium issues only.
   - **Looks good:** nothing, or only minor suggestions.

### Rate limits and quotas (429 errors)

Free API tiers allow few requests (Gemini's free tier allows about 20 requests a day per model).
When the provider asks the reviewer to wait a few seconds, it waits and carries on. When the
quota is used up, the review stops, keeps everything reviewed so far, and lists the rest as
skipped with "AI quota reached". Run the review again after the quota resets: files already
reviewed come from the cache, so it continues where it stopped. To review big projects in one
go, enable billing for your key in Google AI Studio, or raise `ai.max_lines_per_request` so each
request carries more code.

Secrets that look real (API keys, tokens, random-looking passwords) are masked before any code
is sent to the AI. Results are cached, so re-reviewing an unchanged file costs nothing.

## Dashboard

- **Since the previous review:** every review is compared with the one before it. Issues are
  marked *new*, the card shows how many were fixed (click to list them), and *New only* filters
  the list. An issue only counts as fixed when its file was reviewed again.
- **Issues over time:** a chart of every review; click a point to open that review.
- **Choose folders and files:** in the menu next to **Run review**, pick folders or files in a
  tree and see how many files, lines and AI requests the review will take before starting it.
  The menu also estimates the requests for a full or branch review.
- **Export:** PDF, Markdown (paste into a pull request), CSV (opens in Excel), JSON, or a patch
  with every suggested fix (`git apply --3way review_fixes.patch`). Fixes whose code has changed
  since the review are left out.
- **AI settings** (sidebar): provider, model, focus areas, confidence, request size, parallel
  requests, limits and excluded files, with a button to test the connection. Saved to
  `data/settings.yml` on top of `reviewer.yml`; API keys stay in `.env`.
- **AI requests in the last 24 hours** (sidebar): set `daily_request_limit` (e.g. 20 for
  Gemini's free tier) to see it as a meter. Estimates warn when a review needs more than what's left.
- **Review rules per project** (Project settings): extra things the AI should check and extra
  files to skip, for that project only.

## Handling issues

- **False positive** or **Ignore** in the dashboard: remembered for the project, and the
  verdict updates straight away.
- `// reviewer: ignore <reason>` (any comment style) on the line, or the line above, ignores
  an issue in the code itself.

## Settings

ZIP uploads are checked before unpacking: paths that escape the folder, symlinks, more than
50,000 files or more than 1 GB unpacked are refused (limits in `reviewer.yml` under `uploads`).

`reviewer.yml` holds the defaults (the dashboard's AI settings page saves changes to
`data/settings.yml`, which overrides them). It sets the AI provider and model (Gemini, Groq, OpenAI or a local Ollama model; set `ai.model` to switch models, e.g. a Gemini Pro model for deeper reviews), what the AI should look for (`ai.focus`, edit
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
app/core/compare.py        new and fixed issues since the previous review
app/core/diff.py           git diff parsing
app/core/uploads.py        safe ZIP extraction
app/core/storage.py        SQLite: projects, review history, ignored issues, AI cache
app/reports/pdf_report.py  PDF export
app/reports/exports.py     CSV, Markdown, JSON and patch exports
tests/                     tests (the AI is replaced by a fake)
```
