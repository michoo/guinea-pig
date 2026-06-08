#!/usr/bin/env python3
"""
Normalize + dedup security-scanner output into a single findings table.

Handles every shape the my-serveur MCP server emits:
  1. Aggregate report   ({"mode","summary","tools","findings":[...]}) from
     static_scan / dynamic_scan -- ALREADY deduped server-side.
  2. SARIF 2.1.0        ({"version":"2.1.0","runs":[...]}) from an individual tool.
  3. MCP wrapper        ({"result":[{"text":"<aggregate-or-sarif>"}]}) that the
     harness saves to disk when a result is too large to return inline.
  4. Plain scanner text -> kept as one raw finding-blob for manual review.

Output (stdout): JSON {"findings":[...], "stats":{...}}, deduped + severity-sorted.
Use --markdown to also print a triage table to stderr.

Dedup key:  (category, rule_id, normalized_path, start_line)
Group key:  (normalized_path, start_line) -> correlates the SAME spot flagged by
            different scanners. (The aggregate tools already merge by location+
            message; this re-dedup only matters when you mix individual SARIF
            files, or aggregate + individual, in one pass.)

This script makes NO judgement calls beyond severity mapping. Risk vs. ease
triage and PR segmentation are decided by the agent using references/triage.md.
"""
import argparse
import json
import os
import re
import sys

# Ordered (substring, category) -- MOST specific first so "trivy-misconfig" and
# "trivy-license" win over the bare "trivy" (which is SCA).
DRIVER_CATEGORY = [
    ("trivy-misconfig", "iac"), ("misconfig", "iac"), ("aquasecurity-tfsec", "iac"),
    ("trivy-license", "license"), ("license", "license"),
    ("opengrep", "sast"), ("semgrep", "sast"), ("codeql", "sast"),
    ("osv", "sca"), ("trivy", "sca"),
    ("gitleaks", "secret"), ("noseyparker", "secret"), ("nosey", "secret"), ("titus", "secret"),
    ("nuclei", "dast"), ("zaproxy", "dast"), ("zap", "dast"),
    ("plumber", "pipeline"),
]


def category_for(*hints):
    blob = " ".join(h.lower() for h in hints if h)
    for key, cat in DRIVER_CATEGORY:
        if key in blob:
            return cat
    return "unknown"


def cap_sev(sev):
    """Normalize any-case severity to Critical/High/Medium/Low/Info."""
    s = (sev or "").strip().lower()
    return {"critical": "Critical", "high": "High", "medium": "Medium",
            "moderate": "Medium", "low": "Low", "info": "Info",
            "informational": "Info", "unknown": "Medium", "": "Medium"}.get(s, sev.capitalize())


def severity_from_sarif(level, security_severity):
    """SARIF level + security-severity (CVSS 0-10) -> Critical/High/Medium/Low."""
    if security_severity is not None:
        try:
            s = float(security_severity)
            return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low"
        except (TypeError, ValueError):
            pass
    return {"error": "High", "warning": "Medium", "note": "Low", "none": "Low"}.get(
        (level or "").lower(), "Medium")


def norm_path(uri):
    if not uri:
        return ""
    p = uri.replace("file://", "")
    idx = p.find("/guinea-pig/")
    if idx != -1:
        p = p[idx + len("/guinea-pig/"):]
    return p


def split_location(location):
    """'path/file.py:42' -> ('path/file.py', 42); URLs/others -> (loc, None)."""
    loc = norm_path(location)
    m = re.search(r":(\d+)$", loc)
    if m and not loc.lower().startswith(("http://", "https://")):
        return loc[: m.start()], int(m.group(1))
    return loc, None


def _rules_index(run):
    idx = {}
    driver = run.get("tool", {}).get("driver", {})
    for r in driver.get("rules", []) or []:
        idx[r.get("id")] = r
    for ext in driver.get("extensions", []) or []:
        for r in ext.get("rules", []) or []:
            idx[r.get("id")] = r
    return idx


def parse_sarif(doc, hint):
    out = []
    for run in doc.get("runs", []) or []:
        driver = run.get("tool", {}).get("driver", {})
        driver_name = driver.get("name", "")
        category = category_for(driver_name, hint)
        ridx = _rules_index(run)
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id") or "?"
            rule = ridx.get(rule_id, {})
            sec_sev = (rule.get("properties", {}) or {}).get("security-severity")
            level = res.get("level") or (rule.get("defaultConfiguration", {}) or {}).get("level")
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri")
            line = (loc.get("region", {}) or {}).get("startLine")
            title = (rule.get("shortDescription", {}) or {}).get("text") or rule.get("name") or rule_id
            out.append({
                "scanner": driver_name or hint, "category": category, "rule_id": rule_id,
                "title": title, "severity": severity_from_sarif(level, sec_sev),
                "file": norm_path(uri), "start_line": line,
                "message": ((res.get("message", {}) or {}).get("text", "") or "").strip()[:300],
            })
    return out


def parse_aggregate(doc, hint):
    """Flat report from static_scan / dynamic_scan (already deduped)."""
    out = []
    mode_hint = doc.get("mode", "")
    for f in doc.get("findings", []) or []:
        tools = f.get("tools", []) or []
        rules = f.get("rules") or ([f["rule"]] if f.get("rule") else [])
        file, line = split_location(f.get("location", ""))
        out.append({
            "scanner": " + ".join(tools) if tools else hint,
            "category": category_for(*tools, mode_hint),
            "rule_id": f.get("rule") or (rules[0] if rules else "?"),
            "title": (rules[0] if rules else f.get("rule")) or "",
            "severity": cap_sev(f.get("severity", "medium")),
            "file": file, "start_line": line,
            "message": " ".join((f.get("message") or "").split())[:300],
        })
    return out


def parse_doc(doc, hint):
    if isinstance(doc, dict) and "runs" in doc:
        return parse_sarif(doc, hint)
    if isinstance(doc, dict) and "findings" in doc and ("summary" in doc or "mode" in doc):
        return parse_aggregate(doc, hint)
    return None  # not a shape we recognize


def load_one(path):
    with open(path, "r", errors="replace") as fh:
        raw = fh.read()
    hint = os.path.basename(path)
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return [_raw_blob(hint, raw)]
    # MCP wrapper { result: [ { text: "..." } ] }
    if isinstance(doc, dict) and "result" in doc and "runs" not in doc and "findings" not in doc:
        findings = []
        for item in doc.get("result", []) or []:
            text = item.get("text") if isinstance(item, dict) else None
            if not text:
                continue
            try:
                inner = json.loads(text)
            except json.JSONDecodeError:
                findings.append(_raw_blob(hint, text))
                continue
            parsed = parse_doc(inner, hint)
            findings += parsed if parsed is not None else []
        return findings
    parsed = parse_doc(doc, hint)
    return parsed if parsed is not None else []


def _raw_blob(hint, text):
    return {"scanner": hint, "category": category_for(hint), "rule_id": "RAW",
            "title": "Unparsed scanner text (review manually)", "severity": "Medium",
            "file": hint, "start_line": None, "message": (text or "").strip()[:300]}


def dedup(findings):
    seen = {}
    for f in findings:
        key = (f["category"], f["rule_id"], f["file"], f["start_line"])
        if key in seen:
            prev = seen[key]
            prev["scanner"] = " + ".join(sorted(set(prev["scanner"].split(" + ")) |
                                                set(f["scanner"].split(" + "))))
            continue
        f = dict(f)
        f["group"] = f"{f['file']}:{f['start_line']}"
        seen[key] = f
    return list(seen.values())


SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--markdown", action="store_true", help="also print a table to stderr")
    ap.add_argument("--exclude", default="node_modules,vendor,.git",
                    help="comma-list of path substrings to drop (default: %(default)s)")
    args = ap.parse_args()

    excludes = [e for e in args.exclude.split(",") if e]
    all_findings = []
    for path in args.files:
        if not os.path.exists(path):
            print(f"warn: missing {path}", file=sys.stderr)
            continue
        all_findings += load_one(path)

    kept = [f for f in all_findings if not any(e in (f["file"] or "") for e in excludes)]
    findings = dedup(kept)
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["category"], f["file"] or ""))

    stats = {"total_raw": len(all_findings), "excluded": len(all_findings) - len(kept),
             "after_dedup": len(findings), "by_category": {}, "by_severity": {}}
    for f in findings:
        stats["by_category"][f["category"]] = stats["by_category"].get(f["category"], 0) + 1
        stats["by_severity"][f["severity"]] = stats["by_severity"].get(f["severity"], 0) + 1

    print(json.dumps({"findings": findings, "stats": stats}, indent=2))

    if args.markdown:
        print("\n| # | Sev | Cat | Scanner | Location | Rule | Message |", file=sys.stderr)
        print("|--|--|--|--|--|--|--|", file=sys.stderr)
        for i, f in enumerate(findings, 1):
            loc = f["file"] + (f":{f['start_line']}" if f["start_line"] else "")
            print(f"| {i} | {f['severity']} | {f['category']} | {f['scanner']} | {loc} | "
                  f"{f['rule_id']} | {f['message'][:60].replace(chr(10), ' ')} |", file=sys.stderr)


if __name__ == "__main__":
    main()
