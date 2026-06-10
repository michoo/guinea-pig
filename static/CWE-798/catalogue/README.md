# CWE-798 — Secret Catalogue

Detectable-secret examples, one file per rule, built from the regex configs of every
scanner in `/media/workspace/projects/security/secret-rules`:

| Scanner | Version | Config | Rules |
|---|---|---|---|
| kingfisher | v1.102.0 | one `.yml` per provider | 954 |
| titus | v1.2.2 | one `.yml` per provider | 499 |
| noseyparker | v0.24.0 | one `.yml` per provider | 189 |
| betterleaks | v1.4.1 | single `betterleaks.toml` | 305 |
| gitleaks | v8.30.1 | single `gitleaks.toml` | 222 |

## Layout

```
catalogue/
  <provider>/<rule>.txt        one file per distinct rule (e.g. anthropic/anthropic.1.txt)
  _regex-scanner-only/<id>.txt  rules that exist only in the gitleaks/betterleaks configs
```

**1028 files across 586 providers.**

## How rules were grouped

The same secret type is detected by several scanners under near-identical rule ids
(`kingfisher.anthropic.1`, `np.anthropic.1`, …). Rules are merged into one catalogue
entry per `(provider, normalized-id)`, where the normalized id drops the scanner
prefix (`kingfisher.` / `np.`). Each file's header lists every scanner + rule id that
fires on it. The single-file regex scanners (gitleaks, betterleaks) are matched to the
provider and listed under *Related provider rules*.

## Content of each file

- A header comment: rule name, provider, the scanners/ids that detect it, and the regex.
- One or more example secrets.

Examples come straight from the scanners' own test corpora (`examples:` in the YAML
rules); the 14 entries under `_regex-scanner-only/` are synthesized to match the regex
and verified with Python `re`. **All values are fake — placeholders that match the
detection regex but are not live credentials — and are safe to commit.**

See `../false-positives/` for the companion set: benign source code that *looks* like
these rules but must not be flagged.
