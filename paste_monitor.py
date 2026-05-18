"""
paste_monitor.py — Dark Web Paste Site Monitor
────────────────────────────────────────────────
Continuously monitors dark web paste boards for fresh credential dumps,
leak announcements and exploit drops. Feeds hits into crawler.db.

Run alongside server_v2.py:
    python paste_monitor.py

All requests go through Tor on port 9050 — no clearnet.
"""

import time
import sqlite3
import hashlib
import logging
import re
import socks
import socket
import json
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [PASTE] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger()

DB_PATH  = Path(__file__).parent / 'crawler.db'
TOR_HOST = '127.0.0.1'
TOR_PORT = 9050

# ── Dark web paste sites to monitor ───────────────────────────────────────────
PASTE_SITES = [
    # ZeroBin — updated 2025 address (encrypted pastebin)
    {
        'name':    'ZeroBin',
        'url':     'http://zerobinftagjpeeebbvyzjcqyjpmjvynj5qlexwyxe7l3vqejxnqv5qd.onion/',
        'index':   'http://zerobinftagjpeeebbvyzjcqyjpmjvynj5qlexwyxe7l3vqejxnqv5qd.onion/',
        'link_re': r'href="(/\?[a-zA-Z0-9_-]+)"',
    },
    # ZeroBin mirror
    {
        'name':    'ZeroBin Mirror',
        'url':     'http://ej3kv4ebuugcmuwxctx5ic7zxh73rnxt42soi3tdneu2c2em55thufqd.onion/',
        'index':   'http://ej3kv4ebuugcmuwxctx5ic7zxh73rnxt42soi3tdneu2c2em55thufqd.onion/',
        'link_re': r'href="(/\?[a-zA-Z0-9_-]+)"',
    },
    # Deep Paste — updated address
    {
        'name':    'Deep Paste',
        'url':     'http://depastedihrn3jtw.onion/',
        'index':   'http://depastedihrn3jtw.onion/',
        'link_re': r'href="(show\.php\?md5=[a-f0-9]+)"',
    },
    # Stronghold pastebin
    {
        'name':    'Stronghold',
        'url':     'http://nzxj65x32vh2fkhk.onion/',
        'index':   'http://nzxj65x32vh2fkhk.onion/',
        'link_re': r'href="(/[a-zA-Z0-9]{6,})"',
    },
    # Pastepad
    {
        'name':    'Pastepad',
        'url':     'http://mc6nld3smffo3vgm.onion/',
        'index':   'http://mc6nld3smffo3vgm.onion/',
        'link_re': r'href="(/[a-zA-Z0-9]{6,})"',
    },
    # Prvt.zone
    {
        'name':    'Prvt.zone',
        'url':     'http://jjfcjwxf3szomuas.onion/',
        'index':   'http://jjfcjwxf3szomuas.onion/',
        'link_re': r'href="(/[a-zA-Z0-9_-]{6,})"',
    },
]

# ── Check interval per site ────────────────────────────────────────────────────
CHECK_INTERVAL = 300  # 5 minutes between checks per site

# ── Leak detection ─────────────────────────────────────────────────────────────
EMAIL_RE  = re.compile(r'[\w\.-]+@[\w\.-]+\.\w{2,}')
HASH_RE   = re.compile(r'\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b', re.I)
CVE_RE    = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
SSN_RE    = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
RECORD_RE = re.compile(r'(\d+[\.,]?\d*)\s*(million|k|thousand)\s*(records?|accounts?|emails?)', re.I)
MAGNET_RE = re.compile(r'magnet:\?xt=urn:', re.I)
LEAK_KWS  = [
    'credential','dump','leak','breach','combo list','stealer',
    'password','hash','database','ssn','social security','fullz',
    'username:password','user:pass','email:pass','login:pass',
    '0day','exploit','cve','vulnerability','rce','sql injection',
    'ransomware','victim','encrypted','data stolen',
]
NOISE_KWS = [
    'buy now','for sale','contact me','telegram','btc only',
    'guaranteed','trusted vendor','escrow',
]

def analyze(text):
    if not text or len(text) < 30:
        return False, 0, {}
    tl    = text.lower()
    score = 0
    ext   = {}

    # Hard noise filter
    if sum(1 for k in NOISE_KWS if k in tl) >= 2:
        return False, 0, {}

    emails = EMAIL_RE.findall(text)
    if len(emails) >= 5:
        score += 35
        ext['sample_emails'] = list(set(emails[:5]))
    elif len(emails) >= 2:
        score += 15

    hashes = HASH_RE.findall(text)
    if len(hashes) >= 5:
        score += 30
        ext['hash_count'] = len(hashes)
    elif len(hashes) >= 2:
        score += 10

    cves = list(set(CVE_RE.findall(text)))
    if cves:
        score += 35
        ext['cves'] = cves[:10]

    if SSN_RE.search(text):
        score += 40
        ext['has_ssn'] = True

    records = RECORD_RE.findall(text)
    if records:
        score += 20
        ext['record_counts'] = [f"{m[0]} {m[1]} {m[2]}" for m in records[:3]]

    if MAGNET_RE.search(text):
        score += 15
        ext['has_magnet'] = True

    kw_hits = [k for k in LEAK_KWS if k in tl]
    score  += min(len(kw_hits) * 4, 20)
    if kw_hits:
        ext['signals'] = kw_hits[:5]

    # Check for credential line patterns (user:pass format)
    cred_lines = len(re.findall(r'[\w\.-]+@[\w\.-]+:[\w\W]{4,30}', text))
    if cred_lines >= 3:
        score += 25
        ext['cred_lines'] = cred_lines

    return score >= 35, min(score, 100), ext

# ── Tor fetch ──────────────────────────────────────────────────────────────────
def tor_get(url, timeout=20):
    parsed = urlparse(url)
    host   = parsed.hostname
    port   = parsed.port or 80
    path   = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, TOR_HOST, TOR_PORT, rdns=True)
    s.settimeout(timeout)

    try:
        s.connect((host, port))
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: text/plain,text/html,*/*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        s.sendall(req)

        chunks = []
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk: break
                chunks.append(chunk)
            except socket.timeout:
                break

        raw = b''.join(chunks)
        if not raw:
            return None, None

        sep = b'\r\n\r\n'
        idx = raw.find(sep)
        if idx == -1:
            sep = b'\n\n'
            idx = raw.find(sep)

        body = raw[idx + len(sep):] if idx != -1 else raw
        return body.decode('utf-8', errors='replace'), raw[:idx].decode('utf-8', errors='replace')

    except Exception as e:
        log.debug(f"Tor fetch failed {url}: {e}")
        return None, None
    finally:
        try: s.close()
        except: pass

# ── Database ───────────────────────────────────────────────────────────────────
def db():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con

def ensure_tables():
    con = db()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS paste_items (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        url         TEXT UNIQUE,
        site_name   TEXT,
        content     TEXT,
        content_hash TEXT,
        has_leak    INTEGER DEFAULT 0,
        confidence  INTEGER DEFAULT 0,
        extracted   TEXT DEFAULT "{}",
        first_seen  INTEGER,
        last_seen   INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_paste_leak ON paste_items(has_leak);
    CREATE INDEX IF NOT EXISTS idx_paste_site ON paste_items(site_name);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_paste_hash ON paste_items(content_hash);
    ''')
    con.commit()
    con.close()

def content_hash(text):
    return hashlib.md5((text or '').encode()).hexdigest()

def is_known(url):
    con = db()
    row = con.execute("SELECT id FROM paste_items WHERE url=?", (url,)).fetchone()
    con.close()
    return row is not None

def is_duplicate_content(text):
    """Return True if identical content already exists regardless of URL."""
    chash = content_hash(text)
    con   = db()
    row   = con.execute(
        "SELECT id FROM paste_items WHERE content_hash=?", (chash,)
    ).fetchone()
    con.close()
    return row is not None

def save_paste(url, site_name, content, is_leak, confidence, extracted):
    now  = int(time.time())
    chash = content_hash(content)
    con  = db()
    try:
        # INSERT OR IGNORE handles both URL and content_hash uniqueness
        con.execute('''INSERT OR IGNORE INTO paste_items
            (url,site_name,content,content_hash,has_leak,confidence,extracted,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,?,?,?)''',
            (url, site_name, content[:5000], chash,
             1 if is_leak else 0, confidence,
             json.dumps(extracted), now, now))

        # High confidence hits also go to main leaks table
        if is_leak and confidence >= 45:
            con.execute('''INSERT OR IGNORE INTO leaks
                (url,title,confidence,full_text,cves,breach_targets,
                 record_counts,has_emails,has_hashes,has_ssn,has_magnet,timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                (url,
                 f"[Paste] {site_name}: {content[:80].strip()}",
                 confidence, content[:2000],
                 json.dumps(extracted.get('cves', [])),
                 '[]',
                 json.dumps(extracted.get('record_counts', [])),
                 1 if extracted.get('sample_emails') else 0,
                 1 if extracted.get('hash_count') else 0,
                 1 if extracted.get('has_ssn') else 0,
                 1 if extracted.get('has_magnet') else 0,
                 now))
        con.commit()
    except Exception as e:
        log.debug(f"DB save error: {e}")
    finally:
        con.close()

# ── Monitor logic ──────────────────────────────────────────────────────────────
def check_site(site):
    name    = site['name']
    index   = site['index']
    link_re = re.compile(site['link_re'])
    base    = f"{urlparse(index).scheme}://{urlparse(index).hostname}"

    log.info(f"Checking {name}...")
    body, _ = tor_get(index)
    if not body:
        log.debug(f"No response from {name}")
        return 0

    # Find paste links
    links = link_re.findall(body)
    new_count = 0

    for link in links[:50]:  # max 50 links per check
        # Build full URL
        if link.startswith('http'):
            full_url = link
        elif link.startswith('/'):
            full_url = base + link
        else:
            full_url = base + '/' + link

        if is_known(full_url):
            continue

        # Fetch the paste content
        content, _ = tor_get(full_url)
        if not content or len(content.strip()) < 30:
            continue

        # Skip if identical content already saved from another source
        if is_duplicate_content(content):
            log.debug(f"Duplicate content skipped: {full_url}")
            continue

        is_leak, confidence, extracted = analyze(content)

        save_paste(full_url, name, content, is_leak, confidence, extracted)

        if is_leak:
            log.info(f"[LEAK {confidence}%] {name}: {content[:80].strip()}")
            new_count += 1
        else:
            log.debug(f"Saved paste: {full_url}")

        time.sleep(2)  # be polite between paste fetches

    log.info(f"{name}: checked {len(links)} links, {new_count} leaks found")
    return new_count

def run():
    ensure_tables()
    log.info("Dark Crawler — Paste Monitor")
    log.info("-----------------------------")
    log.info(f"Monitoring {len(PASTE_SITES)} dark web paste sites")
    log.info(f"Check interval: {CHECK_INTERVAL}s per site")

    # Track last check time per site
    last_check = {site['name']: 0 for site in PASTE_SITES}
    total_leaks = 0

    while True:
        now = time.time()
        for site in PASTE_SITES:
            if now - last_check[site['name']] >= CHECK_INTERVAL:
                try:
                    found = check_site(site)
                    total_leaks += found
                    last_check[site['name']] = now
                    if found > 0:
                        log.info(f"Total leaks found so far: {total_leaks}")
                except Exception as e:
                    log.warning(f"Error checking {site['name']}: {e}")
                time.sleep(5)  # gap between sites

        # Show stats every hour
        con = db()
        total_pastes = con.execute("SELECT COUNT(*) FROM paste_items").fetchone()[0]
        leak_pastes  = con.execute("SELECT COUNT(*) FROM paste_items WHERE has_leak=1").fetchone()[0]
        con.close()
        log.info(f"Stats: {total_pastes} pastes stored, {leak_pastes} leak hits")

        # Sleep until next site is due
        time.sleep(30)

if __name__ == '__main__':
    run()
