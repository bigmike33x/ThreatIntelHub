# Intel Site

A self-hosted threat intelligence dashboard for organizing, enriching, and reviewing cyber threat intelligence from approved sources.

This project has been reworked from the original crawler concept into an intel-focused platform. The current direction is centered on ransomware group intelligence, Telegram monitoring, archive/import workflows, IOC/entity enrichment, alerting, and a browser dashboard.

---

## Current Focus

- Ransomware group and victim intelligence
- Telegram threat actor and infostealer channel monitoring
- IOC, CVE, actor, TTP, and threat-type enrichment
- Leak/archive import tracking with malware scanning support
- Searchable SQLite-backed dashboard
- Analyst workflow tools such as alerts, notes, review status, and source tiering

---

## Legal & Ethical Notice

This project is intended for defensive security research, threat intelligence, academic study, and authorized investigation.

You are responsible for complying with all applicable laws, terms of service, and organizational policies. Do not use this project to access, store, distribute, or act on illegal material. Keep secrets, API keys, databases, session files, logs, and downloaded archives out of public repositories.

---

## Features

### Intel Dashboard

- Browser-based dashboard on port `8765`
- SQLite-backed local data store
- Summary view for Telegram intelligence, IOCs, actor tags, threat types, TTPs, and CVEs
- Source-tier filtering for Telegram channels
- Recent-message review and enrichment display

### Telegram Monitor

- Monitors configured Telegram channels
- Supports snowball discovery from Telegram links
- Stores channel metadata and message intelligence in SQLite
- Tags possible actors, TTPs, threat types, CVEs, and IOCs when enrichment is available
- Supports duplicate tracking and source-tier labeling

### Ransomware Intelligence

- Ransomware group and victim views
- Group-to-Telegram correlation
- Victim timeline correlation against Telegram messages
- External ransomware.live API support through an environment variable

### Archive Import

- Queue archive/download jobs from the dashboard
- Download and inventory archive files
- Run malware-scanning workflow when ClamAV is available
- Extract supported archives and import selected entities into SQLite
- Track job status, errors, files found, files processed, and entities imported

### Alerts and Review Workflow

- Keyword alerts
- Bookmarks, review flags, and notes
- Canary token hit storage
- Analyst-friendly dashboard views for triage

---

## Requirements

- Python 3.9+
- Linux recommended
- SQLite3
- Optional: ClamAV for archive malware scanning
- Optional: `7z`/p7zip for additional archive extraction support
- Telegram API credentials from `my.telegram.org` if using Telegram monitoring
- ransomware.live API key if using ransomware API-backed views

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/bigmike33x/dark-crawler.git
cd dark-crawler
```

If you rename the GitHub repo later, update the clone URL and your local `origin`.

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a local `.env` file or export variables in your shell. Do not commit `.env`.

```bash
export RANSOMWARE_LIVE_API_KEY="your_ransomware_live_api_key"
export TG_API_ID="your_telegram_api_id"
export TG_API_HASH="your_telegram_api_hash"
```

Optional archive temp directory:

```bash
export LEAK_TMP_DIR="/path/to/temp/storage"
```

### 4. Start the dashboard

```bash
python3 server.py
```

Open:

```text
http://localhost:8765/
```

---

## Running Components

### Dashboard

```bash
source venv/bin/activate
python3 server.py
```

Run in the background:

```bash
nohup python3 server.py >> server.log 2>&1 &
```

### Telegram Monitor

```bash
source venv/bin/activate
export TG_API_ID="your_telegram_api_id"
export TG_API_HASH="your_telegram_api_hash"
python3 telegram_monitor.py
```

The first run may ask for Telegram login verification and then create a local session file. Do not commit `*.session` files.

### Intelligence Worker

```bash
source venv/bin/activate
python3 intelligence_worker.py
```

This enriches Telegram message data when the required tables and optional dependencies are available.

### Archive Worker

Archive jobs are normally queued from the dashboard. A single job can also be run manually:

```bash
source venv/bin/activate
python3 leak_archive_worker.py --job-id <id>
```

---

## Optional System Packages

For archive scanning and extraction:

```bash
sudo apt update
sudo apt install clamav clamav-daemon p7zip-full -y
```

Update ClamAV signatures:

```bash
sudo freshclam
```

---

## Project Structure

```text
dark-crawler/
├── server.py                  # Web dashboard and API routes
├── telegram_monitor.py        # Telegram monitor and snowball discovery
├── intelligence_worker.py     # Message enrichment, IOC/tag processing
├── leak_archive_worker.py     # Archive download, scan, extract, and import worker
├── group_sync.py              # Ransomware/group sync helper
├── add_gang_attribution.py    # Attribution helper
├── ransomware_additions.py    # Optional ransomware-related helper data/scripts
├── requirements.txt
├── .gitignore
└── README.md
```

