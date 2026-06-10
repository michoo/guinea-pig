#!/usr/bin/env python3
"""Scanner detection benchmark for the guinea-pig fixtures.

Ground truth is the structured catalog ``reports/vulnerabilities.json`` (generated
by ``reports/build_report.py`` from the fixture tree). It defines:

  * **positives** — ``findings`` that a scanner *should* report, plus the
    per-rule secret examples summarized under ``secret_catalogue`` (the whole
    ``static/CWE-798/catalogue/`` tree, expanded here file-by-file);
  * **negatives** — ``false_positives``: ``patched.*`` remediations and the
    benign look-alikes under ``static/CWE-798/false-positives/``, which a scanner
    should *not* report.

This harness:

  1. loads that ground truth,
  2. obtains scanner findings — by running the security_mcp CLI (``--mcp <path>``)
     or by parsing SARIF you already have (``--sarif-dir <dir>``),
  3. resolves every SARIF result to a fixture file,
  4. scores each scanner for **detection coverage** (recall over the positives it
     is applicable to) and **errors** — false positives on negatives, plus
     "noise" (findings on repo files that are not a known vulnerability),
  5. writes a coverage + error report (Markdown + JSON) under ``benchmark/results/``.

Per (scanner, positive fixture) where the scanner is *applicable* to the fixture:

    cwe   reported a finding on that file AND tagged the right CWE   (true positive)
    hit   reported a finding on that file, different/absent CWE      (true positive)
    miss  reported nothing on that file                             (false negative)

Per (scanner, negative file): a report there is a **false positive**.

Examples
--------
    # run the scanners via the sibling security_mcp project, then score
    python3 benchmark/run.py --mcp ../security_mcp --tools opengrep,trivy-misconfig

    # score SARIF you already produced (any *.sarif/*.json in the dir)
    python3 benchmark/run.py --sarif-dir /path/to/raw

    # just print the ground-truth inventory (no scanners needed)
    python3 benchmark/run.py --dry-run
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GROUND_TRUTH = REPO / "reports" / "vulnerabilities.json"
CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)

# Which scanner family is expected to cover which fixture category.
# Used as the denominator for a fair per-scanner recall, and to decide whether a
# finding on a positive is "the scanner doing its job".
APPLICABLE = {
    "opengrep":        {"sast", "iac", "pipeline"},
    "codeql":          {"sast"},
    "trivy-misconfig": {"iac"},
    "trivy":           {"iac", "secret", "sca"},
    "osv-scanner":     {"sca"},
    "gitleaks":        {"secret"},
    "nosey_parker":    {"secret"},
    "noseyparker":     {"secret"},
    "titus":           {"secret"},
    "kingfisher":      {"secret"},
    "betterleaks":     {"secret"},
    "plumber":         {"pipeline"},
    "nuclei":          {"dast"},
    "zaproxy":         {"dast"},
}
ALL_CATEGORIES = {"sast", "iac", "pipeline", "secret", "sca", "dast"}

# repo subtrees that count as "ours" for noise detection (a finding here that is
# neither a known positive nor a known negative is unexpected scanner noise).
REPO_FIXTURE_ROOTS = ("static/", "pipeline/", "dynamic/")
NOISE_IGNORE = ("node_modules/", ".git/", "benchmark/results/")


# --------------------------------------------------------------------------- #
# Ground truth
# --------------------------------------------------------------------------- #
def _cats(scanner_types) -> set[str]:
    return {str(t).lower() for t in (scanner_types or [])}


def load_ground_truth() -> dict:
    """Return {positives, catalogue, negatives} keyed by repo-relative path.

    positives[path] = {cwes:set, categories:set, source:'finding'|'catalogue'}
    negatives[path] = {kind, resembles, categories:set}
    DAST findings are file-less (graded by endpoint) and are excluded from the
    file-based scoring here; their count is surfaced in the report."""
    if not GROUND_TRUTH.is_file():
        sys.exit(f"Ground truth not found: {GROUND_TRUTH}\n"
                 f"Run `python3 reports/build_report.py` first.")
    doc = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))

    positives: dict[str, dict] = {}
    dast = 0
    dast_files: set[str] = set()
    for f in doc.get("findings", []):
        cats = _cats(f.get("scanner_types"))
        if cats == {"dast"} or f.get("analysis") == "dynamic":
            dast += 1
            df = (f.get("location") or {}).get("file")
            if df:
                dast_files.add(df)  # e.g. dynamic/app.js — graded by endpoint, not here
            continue
        rel = (f.get("location") or {}).get("file")
        if not rel:
            continue
        cwes = {c["id"] for c in f.get("cwe", []) if c.get("id")}
        if f.get("expected_cwe"):
            cwes.add(f["expected_cwe"])
        # several findings can share one file (e.g. a CI file with multiple CWEs):
        # merge their expected-CWE sets rather than overwrite.
        if rel in positives:
            positives[rel]["cwes"] |= cwes
            positives[rel]["categories"] |= cats
        else:
            positives[rel] = {"cwes": cwes, "categories": cats, "source": "finding"}

    # expand the secret catalogue directory, file by file
    catalogue: dict[str, dict] = {}
    cat = doc.get("secret_catalogue") or {}
    cat_dir = REPO / cat.get("dir", "static/CWE-798/catalogue")
    cat_cwe = cat.get("expected_cwe", "CWE-798")
    if cat_dir.is_dir():
        for p in sorted(cat_dir.rglob("*.txt")):
            rel = str(p.relative_to(REPO))
            catalogue[rel] = {"cwes": {cat_cwe}, "categories": {"secret"}, "source": "catalogue"}

    negatives: dict[str, dict] = {}
    for n in doc.get("false_positives", []):
        rel = n.get("file")
        if not rel:
            continue
        negatives[rel] = {
            "kind": n.get("kind", ""),
            "resembles": n.get("resembles", ""),
            "categories": _cats(n.get("scanner_types")),
        }
    return {"positives": positives, "catalogue": catalogue, "negatives": negatives,
            "dast": dast, "dast_files": dast_files}


# --------------------------------------------------------------------------- #
# SARIF parsing
# --------------------------------------------------------------------------- #
def _cwes_from_obj(*objs) -> set[str]:
    found: set[str] = set()
    for o in objs:
        if o is None:
            continue
        for n in CWE_RE.findall(json.dumps(o)):
            found.add(f"CWE-{n}")
    return found


def _norm_uri(uri: str) -> str:
    u = (uri or "").replace("file://", "")
    for root in REPO_FIXTURE_ROOTS:
        i = u.find("/" + root)
        if i != -1:
            return u[i + 1:]
        if u.startswith(root):
            return u
    return u.lstrip("/")


def parse_sarif(text: str):
    """Return a list of (normalized_uri, set_of_cwes) for every SARIF result."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(doc, dict) or "runs" not in doc:
        return []
    out = []
    for run in doc.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        for res in run.get("results", []):
            uri = ""
            for loc in res.get("locations", []) or []:
                uri = (loc.get("physicalLocation", {})
                          .get("artifactLocation", {}).get("uri", ""))
                if uri:
                    break
            rule = by_id.get(res.get("ruleId"))
            if rule is None and isinstance(res.get("ruleIndex"), int) and res["ruleIndex"] < len(rules):
                rule = rules[res["ruleIndex"]]
            cwes = _cwes_from_obj(res.get("ruleId"), res.get("message"), rule)
            out.append((_norm_uri(uri), cwes))
    return out


# --------------------------------------------------------------------------- #
# Obtaining findings
# --------------------------------------------------------------------------- #
def run_mcp(mcp: Path, target: Path, tools: list[str], language: str | None, out_dir: Path) -> Path | None:
    cli = mcp / "cli.py"
    if not cli.is_file():
        sys.exit(f"security_mcp CLI not found at {cli}")
    cmd = ["uv", "run", "python", "cli.py", str(target),
           "--tools", ",".join(tools), "--formats", "json", "--output-dir", str(out_dir)]
    if language:
        cmd += ["--language", language]
    print(f"  $ {' '.join(cmd)}  (cwd={mcp})")
    try:
        subprocess.run(cmd, cwd=mcp, check=False, timeout=3600)
    except FileNotFoundError:
        sys.exit("`uv` not found. Install uv or use --sarif-dir to score existing SARIF.")
    raw_dirs = sorted(glob.glob(str(out_dir / "scan_*_*" / "raw")))
    return Path(raw_dirs[-1]) if raw_dirs else None


def collect_sarif(sarif_dir: Path) -> dict[str, str]:
    out = {}
    for p in sorted(glob.glob(str(sarif_dir / "*.sarif"))) + sorted(glob.glob(str(sarif_dir / "*.json"))):
        out.setdefault(Path(p).stem, Path(p).read_text(encoding="utf-8", errors="replace"))
    return out


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def _resolver(known: set[str]):
    """Match a normalized SARIF uri to a known repo path by suffix, fast."""
    by_base: dict[str, list[str]] = defaultdict(list)
    for rel in known:
        by_base[os.path.basename(rel)].append(rel)
    def resolve(uri: str) -> str | None:
        cands = by_base.get(os.path.basename(uri))
        if not cands:
            return None
        # longest matching suffix wins
        best = None
        for rel in cands:
            if uri == rel or uri.endswith("/" + rel) or uri.endswith(rel):
                if best is None or len(rel) > len(best):
                    best = rel
        return best
    return resolve


def score(gt: dict, per_tool_hits: dict[str, list]) -> dict:
    """Match every scanner result against the FULL ground truth. A detection on
    any positive is credited regardless of the scanner's expected family — the
    `APPLICABLE` map only sets the *expected scope* (the recall denominator we
    consider fair), never which detections count."""
    positives, catalogue, negatives = gt["positives"], gt["catalogue"], gt["negatives"]
    dast_files = gt.get("dast_files", set())
    known = set(positives) | set(catalogue) | set(negatives)
    resolve = _resolver(known)

    report: dict[str, dict] = {}
    for tool, hits in per_tool_hits.items():
        scope = APPLICABLE.get(tool, ALL_CATEGORIES)
        # collapse findings to {repo_path: cwes} and a noise bucket
        by_file: dict[str, set[str]] = defaultdict(set)
        noise: list[str] = []
        for uri, cwes in hits:
            rel = resolve(uri)
            if rel:
                by_file[rel] |= cwes
            elif uri and any(uri.startswith(r) for r in REPO_FIXTURE_ROOTS) \
                    and uri not in dast_files \
                    and not any(seg in uri for seg in NOISE_IGNORE):
                noise.append(uri)

        def classify(rel, meta):
            if rel not in by_file:
                return "miss"
            return "cwe" if (by_file[rel] & meta["cwes"]) else "hit"

        # --- positives: detection status for EVERY fixture (ungated) ---
        core_status: dict[str, str] = {}
        by_category: dict[str, dict] = defaultdict(lambda: {"detected": 0, "cwe": 0, "total": 0})
        for rel, meta in positives.items():
            st = classify(rel, meta)
            core_status[rel] = st
            for c in meta["categories"]:
                bc = by_category[c]
                bc["total"] += 1
                bc["detected"] += st != "miss"
                bc["cwe"] += st == "cwe"

        cat_detected = cat_cwe = 0
        for rel, meta in catalogue.items():
            st = classify(rel, meta)
            bc = by_category["secret"]
            bc["total"] += 1
            bc["detected"] += st != "miss"
            bc["cwe"] += st == "cwe"
            cat_detected += st != "miss"
            cat_cwe += st == "cwe"

        # --- negatives: false positives ---
        fp = sorted(rel for rel in negatives if rel in by_file)

        report[tool] = {
            "expected_scope": sorted(scope),
            "core": core_status,                              # {path: cwe|hit|miss}
            "by_category": {k: dict(v) for k, v in sorted(by_category.items())},
            "catalogue": {"detected": cat_detected, "cwe": cat_cwe, "total": len(catalogue)},
            "false_positives": fp,
            "noise": sorted(set(noise)),
        }
    return report


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _recall(n, d):
    return f"{n/d:.0%}" if d else "n/a"


def render_markdown(gt, report, tools, meta) -> str:
    positives, catalogue, negatives = gt["positives"], gt["catalogue"], gt["negatives"]
    L = ["# Scanner detection benchmark\n"]
    L.append(f"- Generated: {meta['generated']}")
    L.append(f"- Source of findings: {meta['source']}")
    L.append(f"- Ground truth: `reports/vulnerabilities.json`")
    L.append(f"- Positives: {len(positives)} core fixtures + {len(catalogue)} secret-catalogue "
             f"files · Negatives: {len(negatives)} · DAST (endpoint-graded, excluded here): {gt['dast']}\n")

    total_pos = len(positives) + len(catalogue)

    def totals(r):
        """distinct positives detected (core + catalogue), and scope figures."""
        det = sum(1 for s in r["core"].values() if s != "miss") + r["catalogue"]["detected"]
        cwe = sum(1 for s in r["core"].values() if s == "cwe") + r["catalogue"]["cwe"]
        scope = set(r["expected_scope"])
        bc = r["by_category"]
        sd = sum(bc[c]["detected"] for c in scope if c in bc)
        st = sum(bc[c]["total"] for c in scope if c in bc)
        return det, cwe, sd, st

    # ---- coverage + error summary ----
    L.append("## Coverage & errors per scanner\n")
    L.append("Every scanner result is matched against the **full** ground truth; a detection "
             "on any fixture is credited regardless of the scanner's family. *Scope recall* is "
             "over the positives in the scanner's expected families (a fair denominator); *all "
             "positives* counts detections everywhere (incl. the secret catalogue). FP = reports "
             "on a `patched.*`/look-alike negative; noise = reports on repo files that aren't a "
             "known vuln; precision = TP / (TP + FP + noise).\n")
    L.append("| Scanner | Expected scope | Scope recall | All positives detected | False+ | Noise | Precision |")
    L.append("|---|---|--:|--:|--:|--:|--:|")
    for tool in tools:
        r = report[tool]
        det, cwe, sd, st = totals(r)
        fp = len(r["false_positives"])
        noise = len(r["noise"])
        prec = _recall(det, det + fp + noise)
        L.append(f"| {tool} | {','.join(r['expected_scope'])} | {sd}/{st} ({_recall(sd,st)}) "
                 f"| {det}/{total_pos} ({_recall(det,total_pos)}) | {fp} | {noise} | {prec} |")
    L.append("")

    # ---- per-category coverage (transparency: shows cross-family detections) ----
    cat_order = ["sast", "iac", "pipeline", "sca", "secret", "dast"]
    present = [c for c in cat_order if any(c in report[t]["by_category"] for t in tools)]
    L.append("## Coverage per category\n")
    L.append("`detected/total` positives per category. The **secret** row includes the "
             "1028-file catalogue, so any scanner that flags catalogue secrets shows up here "
             "even if secrets aren't its primary family.\n")
    L.append("| Category | total | " + " | ".join(tools) + " |")
    L.append("|---|--:|" + "|".join(["--:"] * len(tools)) + "|")
    for c in present:
        tot = next((report[t]["by_category"][c]["total"] for t in tools if c in report[t]["by_category"]), 0)
        cells = []
        for t in tools:
            bc = report[t]["by_category"].get(c)
            cells.append(f"{bc['detected']} ({_recall(bc['detected'],bc['total'])})" if bc else "·")
        L.append(f"| {c} | {tot} | " + " | ".join(cells) + " |")
    L.append("")

    # ---- secret catalogue coverage (any scanner that detected at least one) ----
    cat_tools = [t for t in tools if report[t]["catalogue"]["detected"]
                 or "secret" in report[t]["expected_scope"]]
    if cat_tools:
        L.append("## Secret-catalogue coverage (per-rule examples)\n")
        L.append("| Scanner | Examples | Detected | Coverage | CWE-accurate |")
        L.append("|---|--:|--:|--:|--:|")
        for tool in cat_tools:
            c = report[tool]["catalogue"]
            L.append(f"| {tool} | {c['total']} | {c['detected']} | {_recall(c['detected'],c['total'])} | {c['cwe']} |")
        L.append("")

    # ---- false positives detail ----
    any_fp = any(report[t]["false_positives"] or report[t]["noise"] for t in tools)
    L.append("## Errors (false positives & noise)\n")
    if not any_fp:
        L.append("None — no scanner reported on a negative or a non-fixture file. ✓\n")
    else:
        L.append("| Scanner | File | Type | Resembles |")
        L.append("|---|---|---|---|")
        for tool in tools:
            for rel in report[tool]["false_positives"]:
                meta_n = negatives.get(rel, {})
                L.append(f"| {tool} | {rel} | {meta_n.get('kind','negative')} | {meta_n.get('resembles','')} |")
            for rel in report[tool]["noise"]:
                L.append(f"| {tool} | {rel} | noise | not a known vulnerability |")
        L.append("")

    # ---- detection matrix (core fixtures only; catalogue is aggregated above) ----
    L.append("## Detection matrix (core fixtures)\n")
    L.append("Legend: `✓` detected w/ correct CWE · `~` detected, CWE not matched · "
             "`·` missed · `✗` **false positive**\n")
    L.append("| fixture | expected | " + " | ".join(tools) + " |")
    L.append("|---|---|" + "|".join([":-:"] * len(tools)) + "|")
    sym = {"cwe": "✓", "hit": "~", "miss": "·"}
    for rel, m in positives.items():
        cells = [sym.get(report[t]["core"].get(rel), " ") for t in tools]
        L.append(f"| {rel} | {','.join(sorted(m['cwes']))} | " + " | ".join(cells) + " |")
    for rel, m in negatives.items():
        cells = ["✗" if rel in report[t]["false_positives"] else " " for t in tools]
        L.append(f"| {rel} _(negative: {m['kind']})_ | no-finding | " + " | ".join(cells) + " |")
    L.append("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Scanner detection benchmark for guinea-pig fixtures")
    ap.add_argument("--mcp", help="path to the security_mcp repo (runs its CLI to produce SARIF)")
    ap.add_argument("--sarif-dir", help="parse existing SARIF files from this dir instead of running scanners")
    ap.add_argument("--tools", default="opengrep,trivy-misconfig",
                    help="comma-separated scanners to run via --mcp (default: opengrep,trivy-misconfig)")
    ap.add_argument("--language", help="CodeQL language (codeql scans one language at a time)")
    ap.add_argument("--output-dir", default=str(REPO / "benchmark" / "results"))
    ap.add_argument("--dry-run", action="store_true", help="only print the expected ground-truth, no scanners")
    args = ap.parse_args()

    gt = load_ground_truth()
    pos, cat, neg = gt["positives"], gt["catalogue"], gt["negatives"]
    print(f"Ground truth: {len(pos)} core positives, {len(cat)} secret-catalogue positives, "
          f"{len(neg)} negatives, {gt['dast']} DAST (endpoint-graded).")

    if args.dry_run:
        by_cat = defaultdict(int)
        for m in pos.values():
            for c in m["categories"]:
                by_cat[c] += 1
        for c, n in sorted(by_cat.items()):
            print(f"  positives {c:9} {n}")
        print(f"  catalogue secret    {len(cat)}")
        by_neg = defaultdict(int)
        for m in neg.values():
            by_neg[m["kind"]] += 1
        for k, n in sorted(by_neg.items()):
            print(f"  negatives {k:9} {n}")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output_dir) / f"bench_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.sarif_dir:
        sarif_dir = Path(args.sarif_dir)
        source = f"existing SARIF in {sarif_dir}"
    elif args.mcp:
        raw = run_mcp(Path(args.mcp).resolve(), REPO, args.tools.split(","), args.language, out_dir / "mcp")
        if not raw:
            sys.exit("security_mcp produced no raw SARIF directory.")
        sarif_dir = raw
        source = f"security_mcp ({args.tools})"
    else:
        sys.exit("Provide --mcp <security_mcp path> to run scanners, or --sarif-dir <dir> to score existing SARIF "
                 "(or --dry-run).")

    sarif_by_tool = collect_sarif(sarif_dir)
    if not sarif_by_tool:
        sys.exit(f"No *.sarif/*.json found in {sarif_dir}")
    print(f"Parsing SARIF from: {', '.join(sarif_by_tool)}")

    per_tool_hits = {tool: parse_sarif(text) for tool, text in sarif_by_tool.items()}
    tools = sorted(per_tool_hits)
    report = score(gt, per_tool_hits)

    meta = {"generated": ts, "source": source}
    md = render_markdown(gt, report, tools, meta)
    (out_dir / "benchmark.md").write_text(md, encoding="utf-8")
    (out_dir / "benchmark.json").write_text(json.dumps(
        {"meta": meta, "report": report,
         "ground_truth": {"positives": len(pos), "catalogue": len(cat), "negatives": len(neg)}},
        indent=2), encoding="utf-8")

    # console summary
    total_pos = len(pos) + len(cat)
    print("\nScanner            all-positives   catalogue     false+   noise")
    for tool in tools:
        r = report[tool]
        det = sum(1 for s in r["core"].values() if s != "miss") + r["catalogue"]["detected"]
        c = r["catalogue"]
        print(f"  {tool:16} {det:5}/{total_pos:<6} {_recall(det,total_pos):>4}   "
              f"{c['detected']:4}/{c['total']:<5}  {len(r['false_positives']):4}    {len(r['noise']):4}")
    print(f"\nWrote {out_dir/'benchmark.md'} and benchmark.json")


if __name__ == "__main__":
    main()
