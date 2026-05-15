# Dark Crawler

![Dark Crawler](assets/dark_crawler_banner.svg)

A self-hosted dark web threat intelligence platform. Crawls `.onion` sites exclusively through Tor, monitors Telegram channels for leaked credentials and threat actor activity, detects exploits and data breaches, and presents everything in a live browser dashboard — designed to run 24/7 on a Raspberry Pi.

---

## ⚠️ Legal & Ethical Notice

This tool is intended **strictly for security research, academic study, and journalistic investigation**.

- You are solely responsible for complying with all applicable laws in your jurisdiction
- Do not use this tool to access, store, or distribute illegal content
- The crawler includes filters to block adult content and scam sites — do not remove or circumvent them
- The authors accept no liability for misuse of this software

---

## Features

### 🕷️ Crawler
- Crawls `.onion` sites **exclusively through Tor** — your public IP is never exposed
- Seeds from 364 ransomware gang sites, 37 dark web forums, and 52 search engines (via [deepdarkCTI](https://github.com/fastfire/deepdarkCTI))
- Discovers new sites by following links and scanning raw page text for `.onion` addresses
- Resumes where it left off after stopping (Scrapy JOBDIR persistence)
- Deduplicates by hostname — already-crawled sites are never revisited
- Filters at crawl time — noise never reaches the database:
  - Adult content
  - Scam shops (gift cards, CVV, clone cards, cashgod, etc.)
  - Seized/dead pages and DDoS redirect pages
  - Noise titles (403, 404, nginx defaults, "under construction")
  - Thin pages (less than 80 characters of body text)

### 📱 Telegram Monitor
- Monitors 400+ Telegram channels sourced from deepdarkCTI
- Covers infostealer log channels and threat actor channels
- Snowball discovery — automatically finds new channels from message links
- Runs as a separate process alongside the crawler
- Leak hits feed directly into the dashboard Leaks & Exploits tab

### 🔓 Leak & Exploit Detection
- Detects credential dumps, CVE IDs, SSN patterns, password hashes, and email dumps
- Confidence scoring (0–100%) with false positive filtering
- News site detection — articles reporting on breaches are not flagged as leaks
- Personal data search — check if your email, username, or any string appears in detected leaks
- Keyword context viewer — see exactly where a search term appears with surrounding text highlighted

### ⭐ Trust Scoring
- Every site gets a trust score based on uptime history, content richness, human signals (bookmarks/reviews), and uniqueness
- Top Picks surfaces the highest-trust sites automatically
- Mirrors (same content, different URLs) are detected and collapsed into groups

### 🔄 Automatic Re-Crawl
- High-scoring sites are auto-queued for periodic re-crawls
- Tiered intervals by category — forums every 12h, libraries weekly
- Runs in the background without interrupting the main crawl
- Tracks uptime percentage and content changes over time

### 📊 Dashboard
- Live browser UI — no command line needed after setup
- 12 tabs: ⭐ Top Picks · 🔍 Browse · 🔁 Mirrors · 🔓 Leaks & Exploits · 📱 Telegram · 🔔 Alerts · 📊 Stats · 📁 Files · 🔄 Re-Crawl · 🌐 Languages · 🕸 Network · 🗑 Filtered
- Full-text SQLite search across all categories simultaneously
- Detail drawer with personal notes per site
- Bookmark and reviewed tracking
- Real-time activity log showing live crawler output
- Keyword alerts — get notified when a term appears in any new site or leak

---

## Requirements

- Python 3.9+
- Raspberry Pi or any Linux machine (runs 24/7)
- Tor service on port 9050
- `PySocks` — for raw SOCKS5 `.onion` routing
- `telethon` — for Telegram monitor (optional)
- `langdetect` — for language detection (optional)
- Telegram API credentials from [my.telegram.org](https://my.telegram.org) (Telegram monitor only)

---

## Installation

**1. Clone the repo**
```bash
git clone https://github.com/bigmike33x/dark-crawler.git
cd dark-crawler
```

**2. Create virtual environment and install dependencies**
```bash
python3 -m venv venv
source venv/bin/activate       # Linux / Raspberry Pi
pip install -r requirements.txt
```

**3. Install and start Tor**
```bash
sudo apt install tor -y
sudo systemctl enable tor
sudo systemctl start tor
```

Verify Tor is working:
```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# Should return {"IsTor": true, ...}
```

**4. Build the CTI seed list**

Download these files from [deepdarkCTI](https://github.com/fastfire/deepdarkCTI):
- `ransomware_gang.md`
- `forum.md`
- `search_engines.md`
- `telegram_infostealer.md`
- `telegram_threat_actors.md`

Place them in the `dark-crawler` folder, then run:
```bash
python3 -c "
import re, json
from pathlib import Path

files = {
    'ransomware_onions':    'ransomware_gang.md',
    'forum_onions':         'forum.md',
    'search_onions':        'search_engines.md',
    'telegram_infostealer': 'telegram_infostealer.md',
    'telegram_threat_actors':'telegram_threat_actors.md',
}
ONION_RE = re.compile(r'https?://([a-z2-7]{16,56}\.onion[^\s|)]*)', re.I)
TG_RE    = re.compile(r'(https?://t\.me/[\w+@\-/]+)', re.I)
seeds = {k: [] for k in files}
for key, fname in files.items():
    try:
        for line in Path(fname).read_text().splitlines():
            if 'ONLINE' not in line and 'VALID' not in line: continue
            if 'telegram' in key:
                seeds[key].extend(TG_RE.findall(line))
            else:
                seeds[key].extend([f'http://{h}/' for h in ONION_RE.findall(line)])
    except FileNotFoundError:
        print(f'Skipping {fname}')
for k in seeds: seeds[k] = list(set(seeds[k]))
Path('cti_seeds.json').write_text(json.dumps(seeds, indent=2))
print('Done:', {k: len(v) for k, v in seeds.items()})
"
```

**5. Start the server**
```bash
python server_v2.py
```

Open your browser to `http://localhost:8765`, or from another device on the same network: `http://[pi-ip]:8765`

---

## Telegram Monitor (Optional)

**1. Get API credentials**

Go to [my.telegram.org](https://my.telegram.org), sign in, click **API Development Tools**, and create an app. Copy your `api_id` and `api_hash`.

**2. Run the monitor**
```bash
export TG_API_ID=your_api_id
export TG_API_HASH=your_api_hash
python telegram_monitor.py
```

It will ask for your phone number once to verify, then saves the session automatically. All future runs connect silently.

**3. What it does**

- Joins all channels from `cti_seeds.json` (400+ infostealer and threat actor channels)
- Processes the last 100 messages from each channel on startup
- Listens for new messages in real time
- Any message hitting confidence ≥ 45% appears in the **Leaks & Exploits** tab
- Discovers new channels from message links automatically (snowball)

---

## Auto-Start on Reboot (Raspberry Pi)

```bash
crontab -e
```

Add:
```
@reboot cd /home/pi/dark-crawler && /home/pi/dark-crawler/venv/bin/python server_v2.py &
@reboot cd /home/pi/dark-crawler && TG_API_ID=your_id TG_API_HASH=your_hash /home/pi/dark-crawler/venv/bin/python telegram_monitor.py >> telegram.log 2>&1 &
```

---

## Project Structure

```
dark-crawler/
├── darkweb_crawler/
│   ├── spiders/
│   │   └── onion_spider.py      ← crawler, CTI seeds, leak detection
│   ├── middlewares.py            ← Tor SOCKS5 proxy (.onion only, no clearnet)
│   ├── items.py                  ← data models (OnionPageItem, LeakItem)
│   └── settings.py              ← Scrapy config
├── server_v2.py                  ← web server + live dashboard (12 tabs)
├── telegram_monitor.py           ← Telegram channel monitor + snowball discovery
├── migrate_to_db.py              ← convert existing results.jsonl → crawler.db
├── assets/
│   ├── dark_crawler_banner.svg
│   ├── dark_crawler_diagram.svg
│   └── dark_crawler_screenshot.svg
├── scrapy.cfg
├── requirements.txt
├── .gitignore
└── README.md
```

> **Not in repo** (excluded via `.gitignore`):
> `crawler.db` · `results.jsonl` · `leaks.jsonl` · `cti_seeds.json` · `tg_session.session` · `crawl_job/` · `.crawler_state.json`

---

## How It Works

![Architecture](assets/dark_crawler_diagram.svg)

1. **Seeding** — loads 450+ `.onion` addresses from `cti_seeds.json` (ransomware gangs, forums, search engines) plus `.onion` search engine mirrors (Ahmia, Haystak, Torch, Fresh Onions)
2. **Crawling** — visits each `.onion` site via a raw SOCKS5 socket through Tor, saves title and text preview
3. **Discovery** — scans each page for new `.onion` addresses in links and raw text, queues them
4. **Filtering** — skips non-200 responses, empty pages, adult content, and scam sites
5. **Deduplication** — hostname-based dedup plus content-hash dedup to detect mirrors
6. **Leak detection** — scores every page for credentials, CVEs, hashes, SSNs, record counts
7. **Categorization** — keyword matching assigns each site to one of 15 categories
8. **Trust scoring** — uptime history, content richness, and human signals combine into a trust score
9. **Re-crawl** — high-trust sites are automatically re-checked on tiered schedules

---

## Dashboard

![Dashboard](assets/dark_crawler_screenshot.svg)

---

## Categories & Re-Crawl Intervals

| | Category | Interval |
|---|---|---|
| 🔍 | Search Engines & Indexes | 72h |
| 📖 | Wikis & Directories | 72h |
| 💬 | Forums & Communities | 12h |
| 📰 | News & Media | 12h |
| 💭 | Chat & Messaging | 12h |
| ✉️ | Email & Communication | 48h |
| ✍️ | Blogs & Personal Sites | 72h |
| 🛒 | Markets & Commerce | 48h |
| ⚙️ | Technology & Security | 48h |
| 🔒 | Privacy & Anonymity | 48h |
| 📚 | Libraries & Archives | 168h |
| 📡 | Leak & Whistleblower | 168h |
| ₿ | Finance & Crypto | 48h |
| 🖥️ | Hosting & Services | 96h |
| ☠️ | Ransomware | 24h |

---

## Credits

CTI seed data from [deepdarkCTI](https://github.com/fastfire/deepdarkCTI) by fastfire — a community-maintained collection of dark web and Telegram threat intelligence sources.

---

## Contributing

Pull requests are welcome. Please keep the adult content filters intact and do not add features that would make it easier to access or distribute illegal content.

---

## License

MIT License — see `LICENSE` for details.
