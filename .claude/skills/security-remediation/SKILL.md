---
name: security-remediation
description: >-
  Run the my-serveur security scanners (SAST / DAST / SCA / secrets / IAC / licenses / pipeline)
  over this project, collect and dedup the findings, triage them by risk and ease
  of remediation into a report, then open one segmented PR per vulnerability to
  ease developer review. Dependency bumps include code + test impact analysis;
  secrets are reported only, never committed. Use when the user asks to scan,
  triage, prioritize, or remediate security findings, or run a security review.
---

# Security scan → triage → segmented remediation PRs

Drives the `my-serveur` MCP server (`http://127.0.0.1:8000/mcp/`) end-to-end:
**scan → normalize → dedup → triage → report → one PR per fix.**

## Scope (read the argument)

Map the user's request to a scan set. Default to `static` if unspecified; ask
only if genuinely ambiguous.

- `static` → one `static_scan` call. Covers SCA + secrets + SAST + **IaC** +
  **license** + pipeline over a local directory. No running app needed.
- `dynamic` → one `dynamic_scan` call. **Requires a running target URL.** If no
  app is running, start the `dast/` app first (`node dast/app.js`) and use its
  URL. Ask for the target URL if not obvious.
- `both` → `static_scan` + `dynamic_scan`.
- Category words (`sast`, `sca`, `secrets`, `iac`, `license`, `dast`,
  `pipeline`) → call just that category's individual tool(s) below.

The MCP tools are deferred — load schemas with ToolSearch
(`select:mcp__my-serveur__...`) before calling. `PROJECT_DIR` is the repo root
(`/media/workspace/projects/security/guinea-pig`).

### Prefer the aggregate tools
`static_scan(project_dir)` and `dynamic_scan(target_url)` run **all** scanners
for that mode, then collect + **deduplicate server-side**, returning one flat
JSON report: `summary` (counts, `severity_totals`), `tools` (per-tool
status/skip/error), and `findings` (`{rule, rules[], severity, message,
location, tools[], occurrences}`, severity lowercase, already deduped by
location+message). CodeQL's language is auto-detected. This is the default scan
path — one call instead of orchestrating eleven tools.

### Individual tools (for a single category, or to re-scan/verify one fix)

| Category | Tool(s) | Arg | Format |
|---|---|---|---|
| SAST | `sast_opengrep_scan`, `sast_codeql_scan` (one language/call: python, javascript, typescript, java, csharp, cpp, ruby) | `project_dir` (+`language` for codeql) | SARIF |
| SCA | `sca_trivy_scan`, `sca_osv_scanner_scan` | `project_dir` | SARIF |
| IaC | `iac_trivy_misconfig_scan` (Terraform, k8s, Dockerfile, Helm…) | `project_dir` | SARIF |
| License | `license_trivy_scan` (restricted/non-compliant licenses) | `project_dir` | SARIF |
| Secret | `secret_gitleaks_scan`, `secret_nosey_parker_scan`, `secret_titus_scan` | `project_dir` | SARIF |
| DAST | `dast_nuclei_scan`, `dast_zaproxy_scan` | `target_url` | SARIF/JSON |
| Pipeline | `pipeline_plumber_scan` | `project_dir` | SARIF |

There is **no fix/auto-remediate tool** — apply dependency bumps and code fixes
yourself (see §5). ZAP is skipped automatically if its Docker image isn't local.

## Workflow

### 1. Scan
Call `static_scan` and/or `dynamic_scan` (or the individual tools for a single
category). **Outputs are large.** When a result exceeds the token limit the
harness saves it to a file and returns the path — that's expected. Get every
scanner's raw output onto disk under `reports/raw/` so the normalizer can read it:
- If the harness already saved it to a file, note that path.
- If it returned inline, Write the raw text to `reports/raw/<tool>.json`.

### 2. Normalize + dedup
The aggregate tools already dedup server-side, so for a single `static_scan`
you can largely read its `findings` directly. Still run the bundled script — it
gives one consistent table across aggregate **and** individual SARIF outputs,
maps severity to Critical/High/Medium/Low/Info, drops `node_modules`/`vendor`
noise, and re-dedups when you mix sources:

```bash
python3 .claude/skills/security-remediation/scripts/normalize_findings.py \
  reports/raw/*.json /path/to/any/harness-saved-result.txt \
  --markdown > reports/findings.json
```

It understands the aggregate report schema, SARIF, and the MCP
`{result:[{text}]}` wrapper. `--markdown` prints a table to stderr for a quick
look. Do **not** hand-parse the 200k-char blobs — use the script.

### 3. Triage
Read `references/triage.md` and score each finding by **risk** (severity ×
exposure) and **ease** (trivial → hard). Flag obvious test fixtures. Sort by
risk desc, then ease asc (high-risk quick-wins first).

### 4. Report
Write `reports/security-report.md`: summary stats (totals by category/severity),
then the prioritized table, then a per-finding section (location, risk
rationale, proposed remediation, ease). **Secrets: redact values** (prefix +
length only). Show the report to the user before opening any PRs.

### 5. Segmented PRs (one reviewable unit each)
Follow the segmentation table in `references/triage.md`. For each non-secret
finding, in priority order:

1. Branch off `main`: `git switch -c security/<category>-<slug> main`.
2. Apply the fix (there is no auto-fix tool — do it by hand):
   - **SCA bump** → edit the manifest + lockfile to the fixed version. If the
     bump crosses a breaking API change, inspect call sites + changelog, update
     the code, and update/add tests.
   - **IaC** → fix the misconfig in the Terraform/k8s/Dockerfile/Helm source
     (e.g. drop a privileged flag, add encryption, scope permissions).
   - **SAST/DAST/pipeline** → minimal targeted fix + a regression test that
     fails before and passes after.
3. **Verify**: re-run the relevant **individual** scanner on the patched tree
   (and project tests). Confirm the finding clears; if it can't be verified, say so.
4. Commit; open the PR with `gh pr create` (body = finding, risk, fix,
   verification, residual risk). One finding (or one identical-fix group) per PR.

**Secrets** get no PR — they stay in the report with rotation guidance (§5 of
triage.md). **License** findings are report-only by default: flag the
offending dependency + license class and propose a swap/exception rather than
auto-changing dependencies (§4 of triage.md).

### Guardrails
- Pushing branches / opening PRs is outward-facing: **confirm with the user**
  before the first `git push` / `gh pr create`, and confirm the batch size if
  there are many findings.
- If there's no git remote / `gh` is unavailable, create the local branches +
  commits and list them for the user instead of failing.
- Never commit, log, or print a full secret value. Never rewrite git history
  without explicit confirmation.
- Re-running a scanner to verify a fix is normal and expected.
