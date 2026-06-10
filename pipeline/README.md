# pipeline/ — supply-chain (SCA) & CI/CD fixtures

This directory holds **whole-file** fixtures meant to be evaluated by tools that
need realistic file names / repository structure, rather than the per-CWE
snippets in `static/`:

- **`sca/`** — dependency manifests pinned to versions with known CVEs
  (CWE-1395 / CWE-1104). Real manifest names so SCA tools detect them:
  - `sca/python/Pipfile` + `Pipfile.lock` — Django 3.0.1
  - `sca/ruby/Gemfile` — rails 6.1.4, devise
  - `sca/node/package.json` — lodash 4.17.4, minimist 1.2.0, express 4.16.0, axios 0.21.0, node-serialize 0.0.4
  - `sca/java/pom.xml` — log4j-core 2.14.1 (Log4Shell), jackson-databind 2.12.3, spring-web 5.3.8, snakeyaml 1.28
- **`ci/`** — full CI/CD config files at their canonical paths so CI scanners
  (plumber / poutine) recognize them:
  - `ci/gitlab/.gitlab-ci.yml` — CWE-829 (`:latest` image), CWE-494 (`curl|sh`), CWE-94 (`eval $VAR`), CWE-532 (secret echoed)
  - `ci/github/.github/workflows/ci.yml` — CWE-250 (`write-all`), CWE-829 (mutable action tags), CWE-94 (PR-title script injection on `pull_request_target`), CWE-494 (`curl|bash`)

> `static/CWE-829/{github,gitlab}/` contains the same weaknesses as isolated,
> opengrep-detectable snippets. `pipeline/ci/` contains realistic files for
> repo-level scanners like plumber. Both are catalogued.

## Scanning

```bash
# SCA (dependency CVEs)
trivy fs pipeline/sca
osv-scanner --recursive pipeline/sca

# CI/CD security
plumber ...            # point it at pipeline/ci/github or pipeline/ci/gitlab (a git repo)
opengrep --config auto pipeline/ci
```

Expected findings per file are recorded in `reports/vulnerabilities.json`
(`scanner_types`: `SCA` for `sca/`, `PIPELINE` for `ci/`).
