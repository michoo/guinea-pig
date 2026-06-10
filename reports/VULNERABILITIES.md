# Structured vulnerability catalog — documentation

Documents `reports/vulnerabilities.json` and how to keep it current.

> The catalog is **generated**, not hand-written. `reports/build_report.py` walks
> the fixtures and derives every entry. Re-run it after adding/removing fixtures:
>
> ```bash
> python3 reports/build_report.py
> ```

## Layout the generator reads

```
static/CWE-<n>/<language>/vulnerable.<ext>   # vulnerable fixture (CWE = directory)  → positive
static/CWE-<n>/<language>/patched.<ext>      # its remediation                       → negative
static/CWE-798/catalogue/<provider>/*.txt    # per-rule secret examples              → positives (summarized)
static/CWE-798/false-positives/*             # benign code that resembles a rule     → negatives
dynamic/openapi.yml                          # DAST target; x-cwe per path            → positive (endpoint-graded)
```

## File structure

```jsonc
{
  "schema_version": "4.0",
  "report":           { ... },          // metadata + field glossary
  "summary":          { ... },          // counts: positives, negatives, catalogue, by_*
  "findings":         [ { ... }, ... ], // POSITIVES — one entry per vulnerable fixture
  "false_positives":  [ { ... }, ... ], // NEGATIVES — patched.* + look-alikes (expect no finding)
  "secret_catalogue": { ... }           // summary of static/CWE-798/catalogue/ (expanded by the benchmark)
}
```

This file is the **ground truth** consumed by `benchmark/run.py`: positives must
be detected, negatives must stay clean.

### `finding`
| Field | Description |
|---|---|
| `id` | `GP-<SCANNER>-<NNN>` (e.g. `GP-SAST-007`, `GP-DAST-002`) |
| `analysis` | `static` (source code) or `dynamic` (running service / DAST) |
| `scanner_types` | families able to detect it: `SAST`, `IAC`, `PIPELINE`, `SECRET`, `DAST` (a list — e.g. hard-coded creds are `["SAST","SECRET"]`) |
| `language` | folder under `static/CWE-<n>/` (e.g. `python`, `terraform`, `github`, `env`); `http` for dynamic |
| `cwe` | `[{ "id": "CWE-89", "name": "…" }]` |
| `title` | `CWE-<n>: <name>` |
| `severity` | from the CWE severity map in the generator |
| `location` | `{ file, start_line, snippet }` (dynamic entries also carry `endpoint`) |
| `patched` | path to the remediated sibling (static only; `null` for dynamic) |
| `description` | one-line description from the file header / OpenAPI `x-vuln` |
| `expected_cwe` | **ground truth** CWE for `benchmark/run.py` |
| `status` | `open` |

### `false_positives[]` (negatives)
| Field | Description |
|---|---|
| `id` | `FP-<NNN>` |
| `kind` | `remediation` (a `patched.*` file) or `lookalike` (benign code resembling a rule) |
| `expect` | always `no-finding` — a report here is a benchmark **false positive** |
| `scanner_types` | the family that would scan this file type (informational) |
| `file` | path that must stay clean |
| `resembles` / `reason` | which rule it mimics and why it's benign |

### `secret_catalogue`
`{ dir, expected_cwe, scanner_types, files, providers, note, entries[] }`. Every
per-rule secret example is enumerated in `entries[]`:
`{ id: SEC-NNNN, provider, rule, name, file, detected_by:["scanner:rule-id", …],
examples }` — all CWE-798 positives. The benchmark also expands `dir` directly.

### `summary`
`positives`, `negatives`, `secret_catalogue_files`, `by_analysis`,
`by_scanner_type`, `by_severity`, `by_language`, `false_positives_by_kind` — all
recomputed by the generator so they stay consistent with the entries.

## CWE name / severity map & scanner mapping

`reports/build_report.py` holds:
- `CWE_INFO` — canonical CWE name + default severity (add new CWEs here);
- `LANG_SCANNER` — language → scanner type;
- `SECRET_ALSO` — CWEs that a secret scanner also catches in source.

## Update procedure

1. Add `static/CWE-<n>/<language>/vulnerable.<ext>` (+ `patched.<ext>`), with header:
   ```
   <comment> CWE-<n>: <CWE official name>
   <comment> <one-sentence description>
   <comment> Vulnerable sink: <the exact function/pattern>
   ```
2. For a new DAST case, add a path to `dynamic/app.js` and `dynamic/openapi.yml`
   (with `x-cwe:` and `x-vuln:`).
3. If the CWE is new, add it to `CWE_INFO`.
4. To add a secret example, drop a file under `static/CWE-798/catalogue/<provider>/`;
   to add a benign look-alike, drop a file (with a `Resembles:` / `Why benign:`
   header) under `static/CWE-798/false-positives/`.
5. Run `python3 reports/build_report.py`; optionally refresh `reports/INVENTORY.md`.
6. The benchmark needs no change — it reads `reports/vulnerabilities.json`.

## Related files

- `reports/vulnerabilities.json` — the generated catalog (ground truth).
- `reports/build_report.py` — the generator (single source of truth).
- `reports/INVENTORY.md` — human recap (CWE × language matrix, totals).
- `static/CWE-798/catalogue/` & `static/CWE-798/false-positives/` — the secret
  examples and benign look-alikes (each with its own `README.md`).
- `benchmark/` — scores scanners against this ground truth (coverage + false positives).

```bash
python3 -c "import json; d=json.load(open('reports/vulnerabilities.json')); \
print(d['summary']['positives'], 'positives,', d['summary']['negatives'], 'negatives,', \
d['summary']['secret_catalogue_files'], 'catalogue files')"
```
