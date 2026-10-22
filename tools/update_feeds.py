#!/usr/bin/env python3
"""Pull every enabled source in data/sources.json into data/feeds.json. Stdlib only.
Add a source by editing sources.json: types are kev, nvd, rss, feodo, urlhaus, otx, json (generic)."""
import csv, io, json, os, re, sys, urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UA = "JaspersSec-feedbot/1.0 (+personal research)"
env = lambda s: re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), s)
strip = lambda s: re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()
defang = lambda u: u.replace("http", "hxxp", 1).replace(".", "[.]")

def get(url, headers=None, timeout=25):
    req = urllib.request.Request(env(url), headers={"User-Agent": UA, **{k: env(v) for k, v in (headers or {}).items()}})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

def iso(s):
    s = (s or "").strip()
    for f in (lambda: parsedate_to_datetime(s), lambda: datetime.fromisoformat(s.replace("Z", "+00:00")),
              lambda: datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")):
        try:
            d = f()
            return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()
        except Exception:
            pass
    return s

def dig(o, path):
    for k in path.split("."):
        o = o.get(k) if isinstance(o, dict) else None
    return o

def p_kev(s, raw):
    v = sorted(json.loads(raw)["vulnerabilities"], key=lambda x: x["dateAdded"], reverse=True)
    return [dict(title=f'{x["cveID"]} · {x["vendorProject"]} {x["product"]}: {x["vulnerabilityName"]}', cve=x["cveID"],
                 url="https://nvd.nist.gov/vuln/detail/" + x["cveID"], date=x["dateAdded"], summary=x["shortDescription"],
                 kind="vuln", tags=["KEV", x["vendorProject"]] + (["ransomware"] if x.get("knownRansomwareCampaignUse") == "Known" else []))
            for x in v]

def p_nvd(s, _):
    end = datetime.now(timezone.utc); start = end - timedelta(days=s.get("days", 2))
    f = "%Y-%m-%dT%H:%M:%S.000"
    h = {"apiKey": os.environ[s["key_env"]]} if os.environ.get(s.get("key_env", "")) else {}
    d = json.loads(get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start.strftime(f)}&pubEndDate={end.strftime(f)}', h))
    out = []
    for w in d.get("vulnerabilities", []):
        c = w["cve"]; m = c.get("metrics", {})
        sc = next((m[k][0]["cvssData"]["baseScore"] for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30") if m.get(k)), None)
        if sc is None or sc < s.get("min_cvss", 7): continue
        desc = next((x["value"] for x in c["descriptions"] if x["lang"] == "en"), "")
        out.append(dict(title=f'{c["id"]} (CVSS {sc})', cve=c["id"], url="https://nvd.nist.gov/vuln/detail/" + c["id"],
                        date=c["published"], summary=desc[:300], kind="vuln", tags=["NVD", f"CVSS {sc}"]))
    return sorted(out, key=lambda x: x["date"], reverse=True)

def p_rss(s, raw):
    root = ET.fromstring(raw); out = []
    for e in root.iter():
        if e.tag.split("}")[-1] not in ("item", "entry"): continue
        g = lambda *n: next((c for c in e if c.tag.split("}")[-1] in n), None)
        t, l, d, sm = g("title"), g("link"), g("pubDate", "updated", "published", "date"), g("description", "summary", "content")
        link = (l.get("href") or l.text) if l is not None else ""
        out.append(dict(title=strip(t.text if t is not None else ""), url=(link or "").strip(), date=iso(d.text if d is not None else ""),
                        summary=strip(sm.text if sm is not None else "")[:300], kind=s.get("kind", "news"), tags=[]))
    return out

def p_feodo(s, raw):
    return [dict(title=f'{x["ip_address"]}:{x.get("port","")} · {x.get("malware","")} C2', url="https://feodotracker.abuse.ch/browse/host/" + x["ip_address"],
                 date=iso(x.get("first_seen", "")), summary=f'Status {x.get("status","")}, country {x.get("country","")}', kind="ioc",
                 tags=[x.get("malware", ""), x.get("status", "")]) for x in json.loads(raw)]

def p_urlhaus(s, raw):
    rows = csv.reader(l for l in raw.splitlines() if l and not l.startswith("#"))
    return [dict(title=defang(r[2]), url=r[7], date=iso(r[1]), summary=f"Status {r[3]}, threat {r[5]}", kind="ioc",
                 tags=[t for t in r[6].split(",") if t][:3]) for r in rows if len(r) >= 8]

def p_otx(s, raw):
    return [dict(title=x["name"], url="https://otx.alienvault.com/pulse/" + x["id"], date=iso(x.get("modified", "")),
                 summary=strip(x.get("description", ""))[:300], kind="ioc", tags=(x.get("tags") or [])[:3])
            for x in json.loads(raw).get("results", [])]

def p_json(s, raw):
    d = json.loads(raw); lst = dig(d, s["list"]) if s.get("list") else d; m = s["map"]; out = []
    for x in lst or []:
        v = lambda k: dig(x, m[k]) if k in m else None
        t = v("tags")
        out.append(dict(title=str(v("title") or ""), url=str(v("url") or ""), date=iso(str(v("date") or "")), summary=strip(str(v("summary") or ""))[:300],
                        kind=s.get("kind", "news"), tags=t if isinstance(t, list) else ([t] if t else [])))
    return out

HANDLERS = dict(kev=p_kev, nvd=p_nvd, rss=p_rss, feodo=p_feodo, urlhaus=p_urlhaus, otx=p_otx, json=p_json)
EXTRA = dict(otx=lambda s: {"X-OTX-API-KEY": "${%s}" % s["key_env"]}, urlhaus=lambda s: ({"Auth-Key": "${%s}" % s["key_env"]} if s.get("key_env") else {}))

def main():
    cfg = json.load(open(os.path.join(ROOT, "data/sources.json"))); dflt = cfg.get("defaults", {})
    items, status = [], []
    for s in cfg["sources"]:
        if not s.get("enabled"): continue
        st = dict(id=s["id"], name=s["name"], ok=False, count=0, error="")
        try:
            if s.get("key_env") and not s.get("key_optional") and not os.environ.get(s["key_env"]):
                raise RuntimeError(f'set ${s["key_env"]} to enable')
            raw = "" if s["type"] == "nvd" else get(s["url"], {**EXTRA.get(s["type"], lambda _: {})(s), **s.get("headers", {})}, dflt.get("timeout", 25))
            got = [i for i in HANDLERS[s["type"]](s, raw) if i["title"]][: s.get("keep", dflt.get("keep", 40))]
            for i in got: items.append({**i, "source": s["id"], "source_name": s["name"], "tags": [t for t in i.get("tags", []) if t], "summary": i.get("summary", "")})
            st.update(ok=True, count=len(got))
        except Exception as e:
            st["error"] = f"{type(e).__name__}: {e}"[:160]
        status.append(st); print(("ok  " if st["ok"] else "FAIL"), s["id"], st["count"], st["error"], file=sys.stderr)
    seen, uniq = set(), []
    for i in sorted(items, key=lambda x: x.get("date", ""), reverse=True):
        k = (i["source"], i["url"] or i["title"])
        if k not in seen: seen.add(k); uniq.append(i)
    out = os.path.join(ROOT, "data/feeds.json")
    json.dump(dict(updated=datetime.now(timezone.utc).isoformat(), sources=status, items=uniq), open(out + ".tmp", "w"), indent=1, ensure_ascii=False)
    os.replace(out + ".tmp", out)
    print(f"wrote {len(uniq)} items from {sum(s['ok'] for s in status)}/{len(status)} sources")

if __name__ == "__main__": main()
