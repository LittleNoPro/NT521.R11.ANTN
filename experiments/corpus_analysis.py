#!/usr/bin/env python3
"""Deterministic corpus analysis of CVE-GENIE's 429 published reproduction
artifacts. Reproduces the paper's headline aggregate numbers (cost/CVE, time,
CWE spread, language spread) WITHOUT running any exploit or calling any LLM:
we only read the authors' committed cve_info.json + log.txt.

Outputs: experiments/corpus/summary.json and three PNG charts.
Run:  env/bin/python experiments/corpus_analysis.py
"""
import ast, json, os, re, statistics
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CVES = ROOT / "cve-genie" / "results" / "reproduced_cves"
OUT = ROOT / "experiments" / "corpus"
OUT.mkdir(parents=True, exist_ok=True)

RESULTS_RE = re.compile(r"^Results:\s*(\{.*\})\s*$", re.M)
EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript/Node",
    ".jsx": "JavaScript", ".tsx": "TypeScript/Node", ".java": "Java",
    ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".rs": "Rust",
    ".c": "C/C++", ".cc": "C/C++", ".cpp": "C/C++", ".h": "C/C++",
    ".cs": "C#",
}

def parse_results(log_path):
    try:
        txt = log_path.read_text(errors="ignore")
    except OSError:
        return None
    m = None
    for m in RESULTS_RE.finditer(txt):
        pass  # keep the LAST Results line
    if not m:
        return None
    try:
        return ast.literal_eval(m.group(1))
    except (ValueError, SyntaxError):
        return None

def norm_cwe(c):
    # cve_info stores cwe as [{"id": "CWE-611", "value": "..."}]
    if isinstance(c, list):
        c = c[0] if c else None
    if isinstance(c, dict):
        return c.get("id")
    return c

FILE_RE = re.compile(r"[\w./-]+\.(py|js|jsx|ts|tsx|java|go|rb|php|rs|c|cc|cpp|h|cs)\b")

def infer_language(info):
    # Most reliable signal: the source files touched by the patch commits.
    counts = Counter()
    for pc in info.get("patch_commits") or []:
        content = pc.get("content") or ""
        for m in FILE_RE.finditer(content):
            lang = EXT_LANG.get("." + m.group(1))
            if lang:
                counts[lang] += 1
    if not counts:  # fallback: directory-tree text
        tree = info.get("dir_tree") or ""
        if isinstance(tree, (list, dict)):
            tree = json.dumps(tree)
        for ext, lang in EXT_LANG.items():
            n = tree.count(ext)
            if n:
                counts[lang] += n
    if counts:
        return counts.most_common(1)[0][0]
    return "Unknown"

rows = []
for d in sorted(CVES.iterdir()):
    if not d.is_dir():
        continue
    info_p = d / "conversations" / "cve_info.json"
    log_p = d / "log.txt"
    if not info_p.exists():
        continue
    try:
        info = json.loads(info_p.read_text(errors="ignore"))
    except (OSError, json.JSONDecodeError):
        continue
    res = parse_results(log_p)
    rows.append({
        "cve": d.name,
        "cwe": norm_cwe(info.get("cwe")),
        "lang": infer_language(info),
        "n_patch_commits": len(info.get("patch_commits") or []),
        "has_advisory": bool(info.get("sec_adv")),
        "cost": float(res["cost"]) if res and "cost" in res else None,
        "time": float(res["time"]) if res and "time" in res else None,
        "success": (str(res.get("success")).lower() == "true") if res else None,
    })

costs = [r["cost"] for r in rows if r["cost"] is not None]
times = [r["time"] for r in rows if r["time"] is not None]
cwes = Counter(r["cwe"] for r in rows if r["cwe"])
langs = Counter(r["lang"] for r in rows if r["lang"])

summary = {
    "n_artifacts": len(rows),
    "n_with_cost": len(costs),
    "cost_mean": round(statistics.mean(costs), 4),
    "cost_median": round(statistics.median(costs), 4),
    "cost_total": round(sum(costs), 2),
    "cost_min": round(min(costs), 4),
    "cost_max": round(max(costs), 4),
    "time_mean_s": round(statistics.mean(times), 1),
    "time_median_s": round(statistics.median(times), 1),
    "n_distinct_cwe": len(cwes),
    "top_cwe": cwes.most_common(15),
    "n_distinct_lang": len([l for l in langs if l != "Unknown"]),
    "lang_dist": langs.most_common(),
    "advisory_coverage": round(sum(r["has_advisory"] for r in rows) / len(rows), 3),
}
(OUT / "summary.json").write_text(json.dumps(summary, indent=2))
(OUT / "rows.json").write_text(json.dumps(rows, indent=1))

# ---- charts ----
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# 1) cost histogram
plt.figure(figsize=(6, 3.2))
plt.hist(costs, bins=40, color="#2b6cb0", edgecolor="white")
plt.axvline(summary["cost_mean"], color="#c0392b", ls="--",
            label=f"mean ${summary['cost_mean']:.2f}")
plt.axvline(summary["cost_median"], color="#27ae60", ls="--",
            label=f"median ${summary['cost_median']:.2f}")
plt.xlabel("Cost per reproduced CVE (USD)"); plt.ylabel("# CVEs")
plt.legend(); plt.tight_layout()
plt.savefig(OUT / "cost_hist.png", dpi=150); plt.close()

# 2) top CWE bar
top = cwes.most_common(12)
plt.figure(figsize=(6, 3.6))
plt.barh([c for c, _ in top][::-1], [n for _, n in top][::-1], color="#6b46c1")
plt.xlabel("# reproduced CVEs"); plt.tight_layout()
plt.savefig(OUT / "cwe_top.png", dpi=150); plt.close()

# 3) language bar
lc = [(l, n) for l, n in langs.most_common() if l != "Unknown"][:8]
plt.figure(figsize=(6, 3.2))
plt.bar([l for l, _ in lc], [n for _, n in lc], color="#dd6b20")
plt.ylabel("# reproduced CVEs"); plt.xticks(rotation=30, ha="right")
plt.tight_layout(); plt.savefig(OUT / "lang_dist.png", dpi=150); plt.close()

print(json.dumps(summary, indent=2))
