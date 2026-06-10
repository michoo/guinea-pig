#!/usr/bin/env python3
"""Generate the structured vulnerability catalog from the fixtures.

Single source of truth for ``reports/vulnerabilities.json``. Layout:

    static/CWE-<n>/<language>/vulnerable.<ext>   # the vulnerable fixture
    static/CWE-<n>/<language>/patched.<ext>      # its remediation
    dynamic/openapi.yml                          # DAST target, x-cwe per path

The CWE is encoded in the directory name and the language in its subfolder, so
the catalog is derived mechanically. Re-run after adding/removing fixtures:

    python3 reports/build_report.py
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CWE_RE = re.compile(r"CWE-(\d+)")

# language (folder) -> scanner type(s) able to detect it
LANG_SCANNER = {
    "java": "SAST", "c": "SAST", "cpp": "SAST", "csharp": "SAST",
    "python": "SAST", "javascript": "SAST",
    "terraform": "IAC", "ansible": "IAC", "kubernetes": "IAC",
    "github": "PIPELINE", "gitlab": "PIPELINE",
    "env": "SECRET", "ini": "SECRET", "conf": "SECRET", "pem": "SECRET",
}
# CWEs that a SECRET scanner also catches even when they appear in source code
SECRET_ALSO = {"CWE-798", "CWE-321", "CWE-259", "CWE-256"}

CWE_INFO = {
    "CWE-22":   ("Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", "High"),
    "CWE-78":   ("Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)", "Critical"),
    "CWE-79":   ("Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)", "High"),
    "CWE-89":   ("Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)", "Critical"),
    "CWE-90":   ("Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)", "High"),
    "CWE-94":   ("Improper Control of Generation of Code (Code Injection)", "Critical"),
    "CWE-120":  ("Buffer Copy without Checking Size of Input (Classic Buffer Overflow)", "High"),
    "CWE-121":  ("Stack-based Buffer Overflow", "High"),
    "CWE-134":  ("Use of Externally-Controlled Format String", "High"),
    "CWE-190":  ("Integer Overflow or Wraparound", "Medium"),
    "CWE-200":  ("Exposure of Sensitive Information to an Unauthorized Actor", "Medium"),
    "CWE-209":  ("Generation of Error Message Containing Sensitive Information", "Low"),
    "CWE-242":  ("Use of Inherently Dangerous Function", "High"),
    "CWE-250":  ("Execution with Unnecessary Privileges", "Medium"),
    "CWE-256":  ("Plaintext Storage of a Password", "Medium"),
    "CWE-284":  ("Improper Access Control", "High"),
    "CWE-295":  ("Improper Certificate Validation", "High"),
    "CWE-311":  ("Missing Encryption of Sensitive Data", "High"),
    "CWE-319":  ("Cleartext Transmission of Sensitive Information", "High"),
    "CWE-321":  ("Use of Hard-coded Cryptographic Key", "High"),
    "CWE-327":  ("Use of a Broken or Risky Cryptographic Algorithm", "Medium"),
    "CWE-330":  ("Use of Insufficiently Random Values", "Medium"),
    "CWE-338":  ("Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)", "Medium"),
    "CWE-367":  ("Time-of-check Time-of-use (TOCTOU) Race Condition", "Medium"),
    "CWE-377":  ("Insecure Temporary File", "Medium"),
    "CWE-401":  ("Missing Release of Memory after Effective Lifetime (Memory Leak)", "Low"),
    "CWE-415":  ("Double Free", "High"),
    "CWE-416":  ("Use After Free", "High"),
    "CWE-476":  ("NULL Pointer Dereference", "Medium"),
    "CWE-494":  ("Download of Code Without Integrity Check", "High"),
    "CWE-502":  ("Deserialization of Untrusted Data", "Critical"),
    "CWE-601":  ("URL Redirection to Untrusted Site (Open Redirect)", "Medium"),
    "CWE-611":  ("Improper Restriction of XML External Entity Reference (XXE)", "High"),
    "CWE-614":  ("Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", "Low"),
    "CWE-653":  ("Improper Isolation or Compartmentalization", "High"),
    "CWE-668":  ("Exposure of Resource to Wrong Sphere", "High"),
    "CWE-732":  ("Incorrect Permission Assignment for Critical Resource", "High"),
    "CWE-778":  ("Insufficient Logging", "Low"),
    "CWE-787":  ("Out-of-bounds Write", "High"),
    "CWE-798":  ("Use of Hard-coded Credentials", "High"),
    "CWE-918":  ("Server-Side Request Forgery (SSRF)", "High"),
    "CWE-942":  ("Permissive Cross-domain Policy with Untrusted Domains", "Medium"),
    "CWE-1004": ("Sensitive Cookie Without 'HttpOnly' Flag", "Low"),
    "CWE-1321": ("Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)", "High"),
    "CWE-532":  ("Insertion of Sensitive Information into Log File", "Medium"),
    "CWE-1395": ("Dependency on Vulnerable Third-Party Component", "High"),
}

# SCA manifests (whole files; not CWE-named). language = ecosystem.
SCA_MANIFESTS = {
    "pipeline/sca/python/Pipfile": "python",
    "pipeline/sca/ruby/Gemfile": "ruby",
    "pipeline/sca/node/package.json": "node",
    "pipeline/sca/java/pom.xml": "java",
}


def strip_comment(line: str) -> str:
    s = line.strip()
    for m in ("/*", "*/", "<!--", "-->", "//", "#", ";"):
        s = s.replace(m, "")
    return s.strip(" *\t")


def parse_header(path: Path) -> dict:
    name = description = sink = ""
    try:
        lines = [strip_comment(l) for l in path.read_text(encoding="utf-8", errors="replace").splitlines()[:8]]
    except OSError:
        lines = []
    for i, c in enumerate(lines):
        if CWE_RE.search(c) and ":" in c and not name:
            name = c.split(":", 1)[1].strip()
            for nxt in lines[i + 1:]:
                if nxt and "sink" not in nxt.lower() and not description:
                    description = nxt
                    break
        if "sink" in c.lower() and not sink:
            sink = c.split(":", 1)[1].strip() if ":" in c else c
    return {"name": name, "description": description, "sink": sink}


def static_findings() -> list[dict]:
    findings = []
    counters: Counter[str] = Counter()
    base = REPO / "static"
    for vuln in sorted(base.rglob("vulnerable.*")):
        rel_parts = vuln.relative_to(base).parts  # (CWE-<n>, <language>, vulnerable.<ext>)
        if len(rel_parts) != 3:
            continue
        cwe_dir, language = rel_parts[0], rel_parts[1]
        m = CWE_RE.search(cwe_dir)
        if not m:
            continue
        cwe = f"CWE-{m.group(1)}"
        canonical, severity = CWE_INFO.get(cwe, ("", "Medium"))
        hdr = parse_header(vuln)
        scanners = [LANG_SCANNER.get(language, "SAST")]
        if cwe in SECRET_ALSO and "SECRET" not in scanners:
            scanners.append("SECRET")
        family = scanners[0].lower()
        counters[family] += 1
        patched = vuln.with_name(f"patched{vuln.suffix}")
        findings.append({
            "id": f"GP-{scanners[0]}-{counters[family]:03d}",
            "analysis": "static",
            "scanner_types": scanners,
            "language": language,
            "cwe": [{"id": cwe, "name": canonical or hdr["name"]}],
            "title": f"{cwe}: {hdr['name'] or canonical}",
            "severity": severity,
            "location": {"file": str(vuln.relative_to(REPO)), "start_line": 1, "snippet": hdr["sink"]},
            "patched": str(patched.relative_to(REPO)) if patched.exists() else None,
            "description": hdr["description"],
            "expected_cwe": cwe,
            "status": "open",
        })
    return findings


def dynamic_findings() -> list[dict]:
    """Parse dynamic/openapi.yml for x-cwe annotations (no yaml dependency)."""
    spec = REPO / "dynamic" / "openapi.yml"
    if not spec.is_file():
        return []
    findings = []
    n = 0
    current_path = None
    pending = {}
    for raw in spec.read_text(encoding="utf-8").splitlines():
        # path keys are indented by 2 spaces under "paths:"
        mp = re.match(r"^  (/[^:]*):\s*$", raw)
        if mp:
            current_path = mp.group(1)
            pending = {}
            continue
        if current_path is None:
            continue
        s = raw.strip()
        if s.startswith("x-cwe:"):
            pending["cwe"] = s.split(":", 1)[1].strip()
        elif s.startswith("x-vuln:"):
            pending["vuln"] = s.split(":", 1)[1].strip()
        elif s.startswith("summary:"):
            pending["summary"] = s.split(":", 1)[1].strip()
        # flush when we have a cwe and hit the next path or a responses line
        if pending.get("cwe") and (s.startswith("responses:") or s.startswith("x-vuln:")):
            if pending.get("_done"):
                continue
        if pending.get("cwe") and pending.get("vuln") and not pending.get("_done"):
            cwe = pending["cwe"]
            canonical, severity = CWE_INFO.get(cwe, ("", "Medium"))
            n += 1
            findings.append({
                "id": f"GP-DAST-{n:03d}",
                "analysis": "dynamic",
                "scanner_types": ["DAST"],
                "language": "http",
                "cwe": [{"id": cwe, "name": canonical}],
                "title": f"{cwe}: {pending.get('summary', current_path)}",
                "severity": severity,
                "location": {"file": "dynamic/app.js", "endpoint": current_path, "start_line": 1, "snippet": ""},
                "patched": None,
                "description": pending["vuln"],
                "expected_cwe": cwe,
                "status": "open",
            })
            pending["_done"] = True
    return findings


def pipeline_findings() -> list[dict]:
    """Inventory pipeline/: SCA manifests (CWE-1395) and CI files (CWEs from
    their header comments)."""
    findings = []
    n_sca = n_ci = 0
    # SCA manifests
    for rel, eco in SCA_MANIFESTS.items():
        p = REPO / rel
        if not p.is_file():
            continue
        n_sca += 1
        name, sev = CWE_INFO["CWE-1395"]
        findings.append({
            "id": f"GP-SCA-{n_sca:03d}",
            "analysis": "static",
            "scanner_types": ["SCA"],
            "language": eco,
            "cwe": [{"id": "CWE-1395", "name": name}],
            "title": f"CWE-1395: vulnerable {eco} dependencies",
            "severity": sev,
            "location": {"file": rel, "start_line": 1, "snippet": ""},
            "patched": None,
            "description": f"Dependency manifest pinned to {eco} packages with known CVEs.",
            "expected_cwe": "CWE-1395",
            "status": "open",
        })
    # CI files — one finding per distinct CWE mentioned in the file's comments
    ci_base = REPO / "pipeline" / "ci"
    if ci_base.is_dir():
        for p in sorted(ci_base.rglob("*.yml")):
            text = p.read_text(encoding="utf-8", errors="replace")
            cwes = sorted({f"CWE-{m}" for m in CWE_RE.findall(text)}, key=lambda c: int(c.split("-")[1]))
            platform = "github" if ".github" in str(p) else "gitlab"
            for cwe in cwes:
                name, sev = CWE_INFO.get(cwe, ("", "Medium"))
                n_ci += 1
                findings.append({
                    "id": f"GP-PIPELINE-{100 + n_ci:03d}",
                    "analysis": "static",
                    "scanner_types": ["PIPELINE"],
                    "language": platform,
                    "cwe": [{"id": cwe, "name": name}],
                    "title": f"{cwe}: {name}",
                    "severity": sev,
                    "location": {"file": str(p.relative_to(REPO)), "start_line": 1, "snippet": ""},
                    "patched": None,
                    "description": f"Insecure CI/CD configuration ({platform}) exhibiting {cwe}.",
                    "expected_cwe": cwe,
                    "status": "open",
                })
    return findings


EXT_SCANNER = {  # negative file extension -> scanner family that would scan it
    ".java": "SAST", ".c": "SAST", ".cpp": "SAST", ".cs": "SAST",
    ".py": "SAST", ".js": "SAST", ".ts": "SAST", ".jsx": "SAST", ".tsx": "SAST",
    ".tf": "IAC", ".yml": "IAC", ".yaml": "IAC",
    ".env": "SECRET", ".ini": "SECRET", ".conf": "SECRET", ".pem": "SECRET",
}


def _clean_snippet(s: str) -> str:
    return s.strip().strip("*>` \t").replace("`", "").rstrip(".")


def _fp_header(path: Path) -> dict:
    """Best-effort: pull 'Resembles:' and the benign rationale from a lookalike
    header, across the various comment styles (#, //, /* */, <!-- -->, >, JSON note)."""
    try:
        blob = "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[:16])
    except OSError:
        return {"resembles": "", "reason": ""}
    def grab(label: str) -> str:
        m = re.search(rf"{label}\s*[:]?\s*(.+)", blob, re.IGNORECASE)
        return _clean_snippet(m.group(1)) if m else ""
    resembles = grab("Resembles")
    reason = grab("Why benign")
    if not reason:
        m = re.search(r'"_false_positive_note"\s*:\s*"([^"]+)"', blob)
        if m:
            note = m.group(1)
            reason = note
            if not resembles:
                rm = re.search(r"Resembles\s+(.+?)(?:\.|$)", note, re.IGNORECASE)
                if rm:
                    resembles = _clean_snippet(rm.group(1))
    return {"resembles": resembles, "reason": reason}


def false_positive_findings() -> list[dict]:
    """Negatives — files that must NOT produce a finding. Two kinds:

    - `remediation`: every `patched.<ext>` sibling (the fixed code).
    - `lookalike`:   benign source under static/CWE-798/false-positives/ that
                     merely resembles a detection rule.

    A scanner reporting on any of these is a FALSE POSITIVE in the benchmark."""
    negatives: list[dict] = []
    n = 0
    base = REPO / "static"
    for patched in sorted(base.rglob("patched.*")):
        parts = patched.relative_to(base).parts
        if len(parts) != 3:
            continue
        language = parts[1]
        n += 1
        negatives.append({
            "id": f"FP-{n:03d}",
            "kind": "remediation",
            "expect": "no-finding",
            "scanner_types": [LANG_SCANNER.get(language, "SAST")],
            "language": language,
            "file": str(patched.relative_to(REPO)),
            "resembles": f"the remediated form of {parts[0]} ({language})",
            "reason": "Remediated counterpart of the vulnerable fixture; should be clean.",
        })

    fp_dir = REPO / "static" / "CWE-798" / "false-positives"
    if fp_dir.is_dir():
        for p in sorted(fp_dir.iterdir()):
            if not p.is_file() or p.name == "README.md":
                continue
            n += 1
            hdr = _fp_header(p)
            negatives.append({
                "id": f"FP-{n:03d}",
                "kind": "lookalike",
                "expect": "no-finding",
                "scanner_types": [EXT_SCANNER.get(p.suffix, "SECRET")],
                "language": p.suffix.lstrip(".") or "txt",
                "file": str(p.relative_to(REPO)),
                "resembles": hdr["resembles"] or "a secret-detection rule",
                "reason": hdr["reason"] or "Benign code that only looks like a secret.",
            })
    return negatives


def _parse_catalogue_file(p: Path) -> tuple[str, list[str], int]:
    """From a catalogue file header pull (rule name, [scanner:id, ...], n_examples)."""
    name = ""
    detected: list[str] = []
    examples = 0
    section = None
    for l in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = l.rstrip()
        if s.startswith("# Catalogue entry"):
            name = s.split(":", 1)[1].strip() if ":" in s else name
            section = None
        elif "Detected by this rule" in s:
            section = "detect"
        elif section == "detect" and s.startswith("#   - "):
            parts = s[6:].split()
            if len(parts) >= 2:
                detected.append(f"{parts[0]}:{parts[-1]}")
        elif s.startswith("#"):
            if section == "detect":
                section = None
        elif s.strip():
            examples += 1
    return name, detected, examples


def secret_catalogue() -> dict:
    """Enumerate the per-rule secret examples under static/CWE-798/catalogue/.
    Each file is a CWE-798 positive for SECRET scanners; the benchmark also
    expands this directory file-by-file."""
    cat = REPO / "static" / "CWE-798" / "catalogue"
    if not cat.is_dir():
        return {}
    files = sorted(cat.rglob("*.txt"))
    providers = sorted({f.parent.name for f in files})
    entries = []
    for i, p in enumerate(files, 1):
        name, detected, n_ex = _parse_catalogue_file(p)
        entries.append({
            "id": f"SEC-{i:04d}",
            "expected_cwe": "CWE-798",
            "scanner_types": ["SECRET"],
            "provider": p.parent.name,
            "rule": p.stem,
            "name": name,
            "file": str(p.relative_to(REPO)),
            "detected_by": detected,
            "examples": n_ex,
        })
    return {
        "dir": str(cat.relative_to(REPO)),
        "expected_cwe": "CWE-798",
        "scanner_types": ["SECRET"],
        "files": len(files),
        "providers": len(providers),
        "note": "One example secret per rule, grouped across scanners (kingfisher, "
                "titus, noseyparker, gitleaks, betterleaks). Every entry is a positive "
                "the SECRET scanners are expected to flag. See catalogue/README.md.",
        "entries": entries,
    }


def main() -> None:
    findings = static_findings() + pipeline_findings() + dynamic_findings()
    negatives = false_positive_findings()
    catalogue = secret_catalogue()
    by_analysis = Counter(f["analysis"] for f in findings)
    by_scanner = Counter(t for f in findings for t in f["scanner_types"])
    by_sev = Counter(f["severity"] for f in findings)
    by_lang = Counter(f["language"] for f in findings)
    by_fp_kind = Counter(f["kind"] for f in negatives)
    report = {
        "schema_version": "4.0",
        "report": {
            "title": "guinea-pig — structured vulnerability catalog (ground truth)",
            "generated_by": "reports/build_report.py (derived from the fixtures)",
            "layout": "static/CWE-<n>/<language>/{vulnerable,patched}.<ext>  +  "
                      "static/CWE-798/{catalogue,false-positives}/  +  dynamic/ (DAST target)",
            "scope": "Intentionally-vulnerable fixtures plus their benign counterparts. "
                     "Positives (`findings` + `secret_catalogue`) are expected to be detected; "
                     "negatives (`false_positives`) are expected to stay clean. This file is the "
                     "ground truth consumed by benchmark/run.py.",
            "fields": {
                "analysis": "static (source code) or dynamic (running service / DAST)",
                "scanner_types": "scanner family/families able to detect it: SAST, IAC, PIPELINE, SECRET, DAST, SCA",
                "patched": "path to the remediated sibling file (static fixtures only)",
                "expected_cwe": "ground-truth CWE for benchmark/run.py",
                "false_positives[].kind": "remediation (a patched.* file) or lookalike (benign code resembling a rule)",
                "false_positives[].expect": "always 'no-finding' — a report here is a benchmark false positive",
                "secret_catalogue": "summary of static/CWE-798/catalogue/ — the benchmark expands it per-file",
            },
            "severity_scale": ["Critical", "High", "Medium", "Low", "Info"],
            "note": "Re-run reports/build_report.py after adding/removing fixtures.",
        },
        "summary": {
            "positives": len(findings),
            "negatives": len(negatives),
            "secret_catalogue_files": catalogue.get("files", 0),
            "by_analysis": dict(sorted(by_analysis.items())),
            "by_scanner_type": dict(sorted(by_scanner.items())),
            "by_severity": {k: by_sev.get(k, 0) for k in ["Critical", "High", "Medium", "Low", "Info"]},
            "by_language": dict(sorted(by_lang.items())),
            "false_positives_by_kind": dict(sorted(by_fp_kind.items())),
        },
        "findings": findings,
        "false_positives": negatives,
        "secret_catalogue": catalogue,
    }
    out = REPO / "reports" / "vulnerabilities.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out.relative_to(REPO)} — {len(findings)} positives "
          f"(static={by_analysis.get('static',0)}, dynamic={by_analysis.get('dynamic',0)}), "
          f"{len(negatives)} negatives ({dict(by_fp_kind)}), "
          f"{catalogue.get('files',0)} secret-catalogue files; "
          f"scanner types {dict(by_scanner)}")


if __name__ == "__main__":
    main()
