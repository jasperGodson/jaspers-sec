#!/usr/bin/env python3
"""python3 tools/new_report.py "Title" [type] [tag,tag] -> prepends a skeleton to data/reports.json"""
import json, os, re, sys
from datetime import date
p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data/reports.json")
t = sys.argv[1]; r = json.load(open(p))
r.insert(0, dict(id=re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-")[:80], title=t, date=date.today().isoformat(),
                 type=sys.argv[2] if len(sys.argv) > 2 else "Intel Report", tags=sys.argv[3].split(",") if len(sys.argv) > 3 else [],
                 summary="", body="## Summary\n\n## Key findings\n\n- \n\n## Indicators\n\n## Detection and response\n\n## Sources\n\n- "))
json.dump(r, open(p, "w"), indent=2, ensure_ascii=False); print("added:", r[0]["id"])
