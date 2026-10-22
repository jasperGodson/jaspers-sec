# Jasper's Sec

Static, data-driven threat intel site. No build step, no dependencies.

## Run locally
    cd jaspers-sec
    python3 tools/update_feeds.py      # fetch all enabled feeds -> data/feeds.json
    python3 -m http.server 8000        # open http://localhost:8000

(Opening the HTML files directly with file:// will not work; the pages load JSON over HTTP.)

## Keep it updated
- **Feeds:** `tools/update_feeds.py` rewrites `data/feeds.json`. Run it on a timer (below).
- **Reports:** `python3 tools/new_report.py "Title" "Intel Report" tag1,tag2`, or use `admin.html`, or edit `data/reports.json` (body is Markdown).
- **Projects / detections / branding / About:** edit `data/projects.json`, `detections.json`, `site.json`.
- **Logo:** put your file in `assets/` and set `"logo"` in `data/site.json`.

## Add threat sources (no code needed)
Edit `data/sources.json`. Built-in types: `kev`, `nvd`, `rss`, `feodo`, `urlhaus`, `otx`, and a generic `json` type for any API:

    {"id":"mine","name":"My API","type":"json","kind":"ioc","url":"https://api.example.com/x",
     "headers":{"Authorization":"Bearer ${MY_KEY}"},"key_env":"MY_KEY",
     "list":"data.items","map":{"title":"value","url":"link","date":"created","summary":"desc","tags":"labels"},"enabled":true}

`kind` is `news`, `vuln` or `ioc`. API keys come from environment variables (`${NAME}`), never from the repo. Sources that need a key are skipped with a note on the Feeds page until the variable is set. Good candidates to add: AlienVault OTX (`otx`, key `OTX_API_KEY`), ThreatFox, VirusTotal, AbuseIPDB, GreyNoise, Shodan, GitHub advisories, vendor RSS feeds, ngCERT.

## Auto-refresh on Linux (systemd user timer)
`~/.config/systemd/user/jsec-feeds.service`

    [Service]
    Type=oneshot
    WorkingDirectory=%h/jaspers-sec
    EnvironmentFile=-%h/.config/jsec.env
    ExecStart=/usr/bin/python3 tools/update_feeds.py

`~/.config/systemd/user/jsec-feeds.timer`

    [Timer]
    OnBootSec=2min
    OnUnitActiveSec=3h
    [Install]
    WantedBy=timers.target

    systemctl --user enable --now jsec-feeds.timer

Put keys in `~/.config/jsec.env` as `OTX_API_KEY=...`.

## Hosting free
Push the folder to GitHub Pages, Cloudflare Pages or Netlify. To refresh feeds there, add a scheduled GitHub Action that runs `python3 tools/update_feeds.py` and commits `data/feeds.json` (store keys as repository secrets).

## Go live on Cloudflare Pages
See the steps in the chat reply: push to GitHub, connect the repo in Cloudflare Pages, add repo secrets, protect `/admin*` with Cloudflare Access.
