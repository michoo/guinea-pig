# Fixture inventory (recap)

A scanner test bed: intentionally-vulnerable fixtures, **one CWE per directory**,
each with a remediated counterpart, plus a running web service for DAST.

## Layout

```
static/CWE-<n>/<language>/vulnerable.<ext>   # the vulnerable fixture (ground truth = CWE-<n>)
static/CWE-<n>/<language>/patched.<ext>      # the remediation of that fixture (negative)
static/CWE-798/catalogue/<provider>/*.txt    # per-rule secret examples (positives)
static/CWE-798/false-positives/*             # benign code that resembles a rule (negatives)
dynamic/                                     # a running Express service for DAST (see dynamic/README.md)
```

`<language>` is one of: java, c, cpp, csharp, python, javascript (→ **SAST**);
terraform, ansible, kubernetes (→ **IAC**); github, gitlab (→ **PIPELINE**);
env, ini, conf, pem (→ **SECRET**). Hard-coded-credential CWEs are tagged both
SAST and SECRET.

## Totals

| Kind | Scanner type | Count |
|---|---|--:|
| positive (static) | SAST | 64 |
| positive (static) | IAC | 16 (terraform 7, ansible 5, kubernetes 4) |
| positive (static) | PIPELINE | 15 (github 8, gitlab 7 — CI files expand to one finding per CWE) |
| positive (static) | SECRET | 11 (env, ini, conf, pem + hard-coded-cred source files) |
| positive (static) | SCA | 4 manifests (python, ruby, node, java) → `pipeline/sca/` |
| positive (dynamic) | DAST | 8 endpoints → `dynamic/` |
| **positives** | | **111** (103 static + 8 dynamic) |
| positive (secret catalogue) | SECRET | **1028** per-rule examples → `static/CWE-798/catalogue/` |
| negative (remediation) | — | 91 `patched.*` siblings (expect no finding) |
| negative (look-alike) | — | 21 benign files → `static/CWE-798/false-positives/` |
| **negatives** | | **112** |

Every static `vulnerable.*` has a `patched.*` sibling (91 / 91). The full
machine-readable ground truth — positives (`findings` + `secret_catalogue`) and
negatives (`false_positives`) — is `reports/vulnerabilities.json` (run
`reports/build_report.py`). `benchmark/run.py` scores scanners against it for
**detection coverage** and **false positives**.

## SAST coverage matrix (CWE × language)

`X` = a `vulnerable`/`patched` pair exists for that CWE in that language.

| CWE | Name | java | c | cpp | csharp | python | javascript |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| CWE-22 | Path Traversal | X | · | · | X | X | X |
| CWE-78 | OS Command Injection | X | X | X | X | X | X |
| CWE-79 | Cross-site Scripting | X | · | · | · | X | X |
| CWE-89 | SQL Injection | X | · | · | X | X | X |
| CWE-90 | LDAP Injection | X | · | · | · | · | · |
| CWE-94 | Code Injection | · | · | · | X | X | X |
| CWE-120 | Classic Buffer Overflow | · | X | X | · | · | · |
| CWE-121 | Stack Buffer Overflow | · | · | X | · | · | · |
| CWE-134 | Uncontrolled Format String | · | X | X | · | · | · |
| CWE-190 | Integer Overflow | · | X | X | · | · | · |
| CWE-242 | Dangerous Function (gets) | · | X | · | · | · | · |
| CWE-295 | Improper Cert Validation | X | · | · | · | X | · |
| CWE-327 | Broken Crypto Algorithm | X | · | · | X | X | X |
| CWE-330 | Insufficiently Random Values | X | · | · | X | X | · |
| CWE-338 | Weak PRNG | · | · | · | · | · | X |
| CWE-367 | TOCTOU Race Condition | · | · | X | · | · | · |
| CWE-377 | Insecure Temporary File | · | · | · | · | X | · |
| CWE-401 | Memory Leak | · | X | · | · | · | · |
| CWE-415 | Double Free | · | X | X | · | · | · |
| CWE-416 | Use After Free | · | X | X | · | · | · |
| CWE-476 | NULL Pointer Dereference | · | X | X | · | · | · |
| CWE-502 | Untrusted Deserialization | X | · | · | X | X | X |
| CWE-601 | Open Redirect | · | · | · | X | · | X |
| CWE-611 | XXE | X | · | · | X | X | · |
| CWE-787 | Out-of-bounds Write | · | X | · | · | · | · |
| CWE-798 | Hard-coded Credentials | X | · | · | X | X | X |
| CWE-918 | SSRF | · | · | · | · | X | · |
| CWE-1321 | Prototype Pollution | · | · | · | · | · | X |

Per-language: java 11 · c 10 · cpp 9 · csharp 10 · python 13 · javascript 11.

## IaC fixtures

- **Terraform** (`static/CWE-{732,284,311,200,319,798,778}/terraform/`): IAM
  wildcard, open security group, unencrypted storage, public S3 ACL, cleartext
  transport, hard-coded provider creds, insufficient logging.
- **Ansible** (`static/CWE-{78,256,319,732,798}/ansible/`): shell injection,
  plaintext password, `validate_certs: no`, `mode: '0777'`, hard-coded creds.
- **Kubernetes** (`static/CWE-{284,250,653,668}/kubernetes/`): host Docker
  socket, privilege escalation, host namespaces, host `/etc` mount.

## Pipeline fixtures

- **GitHub Actions** (`static/CWE-{829,94,250,494}/github/`): unpinned action
  tags, script injection via `${{ github.event.* }}`, `permissions: write-all`,
  `curl | bash`.
- **GitLab CI** (`static/CWE-{829,94,494}/gitlab/`): mutable `:latest` image,
  unsafe variable interpolation, `curl | sh`.

## Secret fixtures

`static/CWE-798/{env,ini,conf}/` (hard-coded secrets in config) and
`static/CWE-321/pem/` (committed private key). Detectable by secret scanners
(gitleaks, titus, nosey_parker, kingfisher, betterleaks, trivy).

### Secret catalogue (`static/CWE-798/catalogue/`)

**1028 example files across 587 providers** — one per detection rule, built from
the regex configs of kingfisher, titus, noseyparker, gitleaks and betterleaks
(in `../secret-rules`). Same rule across scanners is merged into one entry; each
file carries the example secret plus a header listing the scanners/ids that fire
on it. These are CWE-798 **positives** — they measure secret-scanner recall at
scale. See `static/CWE-798/catalogue/README.md`.

### False positives (`static/CWE-798/false-positives/`)

**21 benign files** that *resemble* a secret rule but must NOT be flagged: git
SHA pins, SRI / npm integrity hashes, AWS/Stripe documented example keys, the
jwt.io demo token, UUIDs, `.env.example` placeholders, bcrypt hashes, public
SSH/PGP keys, etc. These are **negatives** — they measure precision. See
`static/CWE-798/false-positives/README.md`.

## Supply-chain & CI (`pipeline/`)

Whole-file fixtures for tools that need realistic names / repo structure
(complement the per-CWE snippets in `static/`):

- **SCA** (`pipeline/sca/`): `python/Pipfile` (Django 3.0.1), `ruby/Gemfile`
  (rails 6.1.4), `node/package.json` (lodash/minimist/express/axios/node-serialize),
  `java/pom.xml` (log4j-core 2.14.1 Log4Shell, jackson, spring-web, snakeyaml).
  Expected: **CWE-1395**, detectable by trivy / osv-scanner.
- **CI/CD** (`pipeline/ci/`): `gitlab/.gitlab-ci.yml` (CWE-829/494/94/532) and
  `github/.github/workflows/ci.yml` (CWE-250/829/94/494) at their canonical paths,
  detectable by plumber / poutine / opengrep.

See `pipeline/README.md`.

## Dynamic (DAST) target

`dynamic/` is a running Express service; each route is annotated with its CWE in
code and in `dynamic/openapi.yml`. 8 endpoints: CWE-79, CWE-89 (×2), CWE-78,
CWE-22, CWE-601, CWE-918, CWE-1004. See `dynamic/README.md`.

## How to extend

1. Add `static/CWE-<n>/<language>/vulnerable.<ext>` with the standard English
   header (CWE id, name, one-line description, vulnerable sink) **and** a
   `patched.<ext>` sibling.
2. If the CWE is new, add it to `CWE_INFO` in `reports/build_report.py`.
3. To add a secret example, drop a file under `static/CWE-798/catalogue/<provider>/`;
   to add a benign look-alike, drop a file (with `Resembles:` / `Why benign:`
   header) under `static/CWE-798/false-positives/`.
4. Run `python3 reports/build_report.py` to refresh the ground truth.
5. The benchmark picks it up automatically (it reads `reports/vulnerabilities.json`).
