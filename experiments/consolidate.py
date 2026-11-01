#!/usr/bin/env python3
"""Consolidate all local-agent runs into one matrix for the report.
Reads experiments/<cve>/<tag>.json; prints + writes experiments/matrix.json.
Run: env/bin/python experiments/consolidate.py
"""
import json, glob, os
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
rows = []
for f in glob.glob(os.path.join(ROOT, "*", "*.json")):
    cve = os.path.basename(os.path.dirname(f))
    if not cve.startswith("CVE-"):
        continue
    d = json.load(open(f))
    tag = os.path.splitext(os.path.basename(f))[0]
    model = "7B" if "7b" in tag.lower() else "3B"
    rows.append(dict(cve=cve, tag=tag, model=model,
                     variant=d.get("variant", "?"), success=bool(d["success"]),
                     steps=d["metrics"]["steps"], tool_errors=d["metrics"]["tool_errors"]))

# aggregate success by (cve, model, variant): "s/n"
agg = defaultdict(lambda: [0, 0])
for r in rows:
    k = (r["cve"], r["model"], r["variant"])
    agg[k][0] += int(r["success"]); agg[k][1] += 1

matrix = {}
for (cve, model, variant), (s, n) in sorted(agg.items()):
    matrix.setdefault(cve, {}).setdefault(model, {})[variant] = f"{s}/{n}"

out = {"n_runs": len(rows), "matrix": matrix}
json.dump(out, open(os.path.join(ROOT, "matrix.json"), "w"), indent=2)
print(json.dumps(out, indent=2))
