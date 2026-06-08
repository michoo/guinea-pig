# Triage & PR-segmentation policy

Load this when scoring findings and deciding how to split the remediation PRs.

## 1. Risk score (severity × exposure)

Start from the normalized `severity` (Critical/High/Medium/Low — derived from
SARIF `security-severity` CVSS or `level`), then adjust for **exposure**:

| Factor | Bumps risk up | Bumps risk down |
|---|---|---|
| Reachability | Internet-facing / untrusted input path | Dead code, test fixture, example |
| Data sensitivity | Auth, crypto, PII, RCE, SQLi, deserialization | Cosmetic / informational |
| Corroboration | Same `group` (file:line) flagged by 2+ scanners | Single low-confidence rule |

Note when a finding is clearly an intentional test fixture (this repo is a
deliberately-vulnerable sample) — call it out, do **not** silently treat it as
production-critical, but still list it.

## 2. Ease of remediation

| Ease | Looks like |
|---|---|
| **Trivial** | SCA version bump with no API change; config one-liner |
| **Easy** | Localized code fix (parameterize query, escape output, set flag) |
| **Moderate** | Version bump **with** breaking API change → code + test updates |
| **Hard** | Architectural change, cross-cutting refactor, needs design decision |

## 3. Priority order (what to PR first)

Sort by **risk desc, then ease asc** → high-risk quick-wins lead. Produce the
report in this order and create PRs in this order.

## 4. PR segmentation rules

One reviewable unit per PR. Branch off `main` (not the working branch).
Branch name: `security/<category>-<short-slug>` (e.g. `security/sca-lodash-cve`).

| Finding type | PR content | Notes |
|---|---|---|
| **SAST code vuln** | The minimal code fix + a regression test that fails before / passes after | One PR per finding, or per group of identical-rule+identical-fix occurrences (state the grouping in the PR body). |
| **SCA version bump (no API change)** | Hand-edit the manifest + lockfile to the fixed version (no auto-fix tool exists) | One PR per package. |
| **SCA version bump (API change)** | Bump + updated call sites + updated/added tests | Inspect changelog/usage first; document the breaking change and the migration in the PR body. |
| **IaC misconfig** | Fix the Terraform/k8s/Dockerfile/Helm source (drop privileged flag, add encryption, scope perms) | One PR per misconfig (or per identical-policy group across files). |
| **DAST finding** | Code/config fix for the root cause (header, validation, auth) | One PR per distinct root cause, not per URL. |
| **Pipeline (plumber)** | Workflow YAML fix (pin action SHA, scope token, etc.) | One PR per workflow concern. |
| **License** | **Report only by default.** Name the dependency + license class; propose a compliant swap or a documented exception | Don't auto-swap dependencies — that's a licensing/legal call for the user. Only open a PR if the user approves a specific swap. |
| **Secret** | **NO code PR.** Report only. | Never create a branch/commit that still contains the secret. See §5. |

Each PR body must contain: the finding (scanner, rule, location), why it's a
risk, what the fix does, how it was verified (test/scan), and any residual risk.

## 5. Secrets — report only, never auto-remediate in a PR

- List each secret: file, line, type, scanner. **Redact the value** — show only
  a short prefix + length (e.g. `AKIA…EXAMPLE (20 chars)`).
- Recommend: rotate/revoke at the provider, remove from the working tree, and
  scrub history (`git filter-repo` / BFG) — but do not perform history rewrites
  or push without explicit user confirmation.
- Do **not** open a PR whose diff contains the secret, and do not echo full
  secret values into reports, commit messages, or PR bodies.

## 6. Verification before opening a PR

- SCA: re-run the relevant SCA scanner on the patched tree; confirm the CVE is gone.
- SAST/DAST: re-run the scanner (or the added test) to confirm the finding clears.
- Always run the project's existing tests if present. If a fix can't be verified,
  say so in the PR body rather than claiming it works.
