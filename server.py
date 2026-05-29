# -*- coding: utf-8 -*-
"""
server_v2.py — Dark Crawler dashboard backed by SQLite
"""
import http.server, socketserver, threading, subprocess
import os
import json, sys, sqlite3, time, hashlib, re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote_plus

BASE_DIR   = Path(__file__).parent
DB_PATH    = BASE_DIR / "crawler.db"
RESULTS    = BASE_DIR / "results.jsonl"
LEAKS_FILE = BASE_DIR / "leaks.jsonl"
_STATE_FILE= BASE_DIR / ".crawler_state.json"
PORT       = 8765
RANSOMWARE_LIVE_API_KEY = os.environ.get("RANSOMWARE_LIVE_API_KEY", "")

# ── Language detection ─────────────────────────────────────────────────────────
try:
    from langdetect import detect as _lang_detect
    def detect_language(text):
        try: return _lang_detect(text[:500])
        except: return "unknown"
except ImportError:
    def detect_language(text): return "unknown"

# ── File extensions to flag ────────────────────────────────────────────────────
FLAG_EXTS = {'.sql','.gz','.zip','.tar','.7z','.rar',
             '.txt','.csv','.json','.db','.sqlite',
             '.pdf','.docx','.xlsx','.torrent'}

# ── Categorization ─────────────────────────────────────────────────────────────
CATEGORY_RULES = [
    ("Search Engines",     ["search engine","index","ahmia","torch","haystack","searx"]),
    ("Wikis & Directories",["wiki","hidden wiki","link list","catalog","directory"]),
    ("Forums",             ["forum","board","thread","community","discussion","chan","bbs"]),
    ("News & Media",       ["news","article","press","journalist","media","report"]),
    ("Chat & Messaging",   ["chat","jabber","xmpp","irc","messenger"]),
    ("Email",              ["email","mail","smtp","webmail"]),
    ("Blogs",              ["blog","personal","diary","journal","portfolio"]),
    ("Markets",            ["market","shop","store","buy","sell","vendor"]),
    ("Technology",         ["security","hacking","ctf","tech","software","code"]),
    ("Privacy Tools",      ["privacy","anonymous","vpn","encryption","pgp","tails","whonix"]),
    ("Libraries",          ["library","archive","book","ebook","pdf","document"]),
    ("Whistleblower",      ["leak","whistle","securedrop","classified"]),
    ("Finance & Crypto",   ["bitcoin","crypto","wallet","exchange","monero","finance"]),
    ("Hosting",            ["hosting","host","server","vps","domain"]),
]
NOISE_KWS = [
    'gift card','clone card','cashgod','buy money','bitcoin generator',
    'stolen wallets','escrow marketplace','darkweb shop','bazaar plastic',
    'this site has been seized','seized by','link disabled',
    'ddos protection by','you will be redirected','please wait',
    'buy cocaine','buy heroin','buy meth','buy fentanyl',
]

# CSAM hard block — these terms in title or preview = immediate rejection
CSAM_BLOCK_KWS = [
    'pthc','ptsc','jailbait','child porn','lolita','underage sex',
    'child sex','kiddie','preteen','pedo','pedophil','childlove',
    'rindexx','rape video','rape image','raped bitch','rape kids',
    'cp -','cp video','kdv','yvids','zoo sex','snuff',
    'cute girls underage','boy love','girl love',
    # Human trafficking
    'buy girl','buy boy','buy child','buy baby','buy newborn',
    'sex slave','sex slaves','young wife for sale','human traffic',
    'illegal trade of people','behappy','sell girl','sell boy',
    'sell child','baby for sale','child for sale','slave market',
]

def is_csam(title, preview):
    text = f"{title} {preview}".lower()
    return any(kw in text for kw in CSAM_BLOCK_KWS)
BOOST_KWS = {
    'library':6,'archive':6,'securedrop':8,'whistleblower':8,'wiki':4,
    'research':5,'journalism':7,'pgp':5,'encryption':4,'forum':3,
    'community':3,'blog':2,'news':4,'tails':5,'whonix':5,
    'documentation':5,'guide':3,'privacy':3,'anonymous':2,
    'search engine':4,'directory':3,'open source':4,
}

def categorize(e):
    text = f"{e.get('title','')} {e.get('body_preview','')}".lower()
    for cat, kws in CATEGORY_RULES:
        if any(kw in text for kw in kws): return cat
    return "Uncategorized"

def base_score(e):
    t = (e.get('title') or '').lower()
    p = (e.get('body_preview') or '').lower()
    text = f"{t} {p}"
    s = 2 if e.get('status')==200 else -10
    if any(kw in text for kw in NOISE_KWS): s -= 50
    for kw, pts in BOOST_KWS.items():
        if kw in text: s += pts
    pl = len(p)
    if pl > 250: s += 5
    elif pl < 30: s -= 5
    if t and t not in ('[no title]','403 forbidden'): s += 3
    return max(s, -99)

def content_hash(text):
    normalized = re.sub(r'\s+', ' ', (text or '').lower().strip())[:500]
    return hashlib.md5(normalized.encode()).hexdigest()

def trust_score(site):
    """
    Trust score on top of base score:
    - Uptime ratio: sites seen alive multiple times rank higher
    - Content richness: longer previews = more real content
    - Human signals: bookmarked or reviewed by user
    - Age: sites discovered earlier that are still alive
    - Unique content: not a mirror
    """
    s = site.get('score', 0)
    uptime  = site.get('uptime_count', 1)
    down    = site.get('downtime_count', 0)
    total   = uptime + down
    ratio   = uptime / total if total > 0 else 1.0
    preview_len = len(site.get('preview',''))

    # Uptime bonus — max +15
    s += int(ratio * 15)
    # Seen alive more than once bonus
    if uptime > 2:  s += min(uptime, 8)
    # Content richness bonus — max +8
    s += min(int(preview_len / 40), 8)
    # Human signals
    if site.get('bookmarked'): s += 12
    if site.get('reviewed'):   s += 5
    # Mirror penalty — mirrors are less interesting than originals
    if site.get('mirror_group') and site.get('uptime_count',1) == 1:
        s -= 5
    return s

# ── DB ─────────────────────────────────────────────────────────────────────────
def db():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA cache_size=-32000")  # 32MB page cache
    con.execute("PRAGMA temp_store=MEMORY")  # temp tables in RAM
    return con


def table_exists(con, name):
    try:
        return con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (name,)
        ).fetchone() is not None
    except Exception:
        return False

def column_exists(con, table, column):
    try:
        return column in {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
    except Exception:
        return False

def attach_telegram_intel(con, message_rows):
    """Attach read-only enrichment data to Telegram message rows for UI display.
    Safe if intelligence_worker tables/columns do not exist yet.
    """
    messages = [dict(r) for r in message_rows]
    if not messages:
        return messages

    ids = [m.get('id') for m in messages if m.get('id') is not None]
    if not ids:
        return messages

    by_id = {m['id']: m for m in messages}
    placeholders = ','.join('?' for _ in ids)

    # Defaults keep the old UI/API behavior if intel tables are missing.
    for m in messages:
        m['intel_tags'] = {}
        m['intel_iocs'] = {}
        m['intel_ioc_count'] = 0
        m['intel_tag_count'] = 0
        if 'is_duplicate' not in m:
            m['is_duplicate'] = 0

    try:
        # Add source tier from telegram_channels when available.
        if table_exists(con, 'telegram_channels') and column_exists(con, 'telegram_channels', 'source_tier'):
            chan_ids = sorted({str(m.get('channel_id')) for m in messages if m.get('channel_id')})
            if chan_ids:
                cp = ','.join('?' for _ in chan_ids)
                chan_rows = con.execute(
                    f"SELECT channel_id, COALESCE(source_tier,'unknown') AS source_tier FROM telegram_channels WHERE channel_id IN ({cp})",
                    chan_ids
                ).fetchall()
                tier_by_chan = {str(r['channel_id']): r['source_tier'] for r in chan_rows}
                for m in messages:
                    m['source_tier'] = tier_by_chan.get(str(m.get('channel_id')), 'unknown')

        if table_exists(con, 'msg_tags'):
            has_conf = column_exists(con, 'msg_tags', 'confidence')
            conf_select = ', confidence' if has_conf else ', 50 AS confidence'
            tag_rows = con.execute(
                f"SELECT msg_id, tag_type, tag_value{conf_select} "
                f"FROM msg_tags WHERE msg_id IN ({placeholders}) "
                "ORDER BY confidence DESC, tag_type, tag_value",
                ids
            ).fetchall()
            for r in tag_rows:
                mid = r['msg_id']
                if mid not in by_id:
                    continue
                tags = by_id[mid]['intel_tags'].setdefault(r['tag_type'], [])
                if len(tags) < 8:
                    tags.append({'value': r['tag_value'], 'confidence': r['confidence']})
                by_id[mid]['intel_tag_count'] += 1

        if table_exists(con, 'ioc_links') and table_exists(con, 'iocs'):
            quality_select = 'COALESCE(i.quality, 50)' if column_exists(con, 'iocs', 'quality') else '50'
            ioc_rows = con.execute(
                f"SELECT l.msg_id, i.type, i.value, {quality_select} AS quality "
                f"FROM ioc_links l JOIN iocs i ON i.id=l.ioc_id "
                f"WHERE l.msg_id IN ({placeholders}) "
                "ORDER BY quality DESC, i.type, i.value",
                ids
            ).fetchall()
            for r in ioc_rows:
                mid = r['msg_id']
                if mid not in by_id:
                    continue
                iocs = by_id[mid]['intel_iocs'].setdefault(r['type'], [])
                if len(iocs) < 8:
                    iocs.append({'value': r['value'], 'quality': r['quality']})
                by_id[mid]['intel_ioc_count'] += 1
    except Exception:
        # Never let enrichment display break the Telegram tab.
        return messages

    return messages

def ransomware_telegram_correlation(con, group_name):
    """Build read-only Telegram intel correlation for a ransomware group name.
    Uses enriched msg_tags/iocs when present and falls back to raw Telegram text search.
    Never writes to the DB.
    """
    name = (group_name or '').strip()
    term = re.sub(r'\s+', ' ', name.lower()).replace(' ransomware', '').strip()
    if not term or not table_exists(con, 'telegram_messages'):
        return {"group": name, "mentions": 0, "mentions_24h": 0, "mentions_7d": 0,
                "last_seen": None, "top_channels": [], "top_ttps": [],
                "related_iocs": [], "related_cves": [], "recent_messages": []}

    like = f"%{term}%"
    match_parts = ["LOWER(tm.text) LIKE ?"]
    params = [like]

    if table_exists(con, 'msg_tags'):
        match_parts.insert(0, "EXISTS (SELECT 1 FROM msg_tags mt WHERE mt.msg_id=tm.id AND mt.tag_type IN ('actor','ner_ransom_group','ner_threat_actor') AND LOWER(mt.tag_value) LIKE ?)")
        params.insert(0, like)

    where_sql = "(" + " OR ".join(match_parts) + ")"
    if column_exists(con, 'telegram_messages', 'is_duplicate'):
        where_sql += " AND COALESCE(tm.is_duplicate,0)=0"

    def run(sql):
        return con.execute(sql, params).fetchall()

    try:
        now_ts = int(time.time())
        summary = con.execute(f"""
            SELECT COUNT(*) AS mentions,
                   MAX(tm.timestamp) AS last_seen,
                   SUM(CASE WHEN tm.timestamp>=? THEN 1 ELSE 0 END) AS mentions_24h,
                   SUM(CASE WHEN tm.timestamp>=? THEN 1 ELSE 0 END) AS mentions_7d
            FROM telegram_messages tm
            WHERE {where_sql}
        """, [now_ts - 86400, now_ts - 7*86400] + params).fetchone()

        tier_expr = "COALESCE(tc.source_tier,'unknown')" if column_exists(con, 'telegram_channels', 'source_tier') else "'unknown'"
        top_channels = run(f"""
            SELECT COALESCE(tm.channel_name,'unknown') AS channel_name,
                   COUNT(*) AS mentions,
                   MAX(tm.timestamp) AS last_seen,
                   {tier_expr} AS source_tier
            FROM telegram_messages tm
            LEFT JOIN telegram_channels tc ON tc.channel_id=tm.channel_id
            WHERE {where_sql}
            GROUP BY COALESCE(tm.channel_name,'unknown'), {tier_expr}
            ORDER BY mentions DESC, last_seen DESC
            LIMIT 8
        """)

        top_ttps = []
        if table_exists(con, 'msg_tags'):
            conf_expr = 'COALESCE(mt.confidence,50)' if column_exists(con, 'msg_tags', 'confidence') else '50'
            top_ttps = run(f"""
                SELECT mt.tag_value, COUNT(*) AS mentions, ROUND(AVG({conf_expr})) AS avg_confidence
                FROM telegram_messages tm
                JOIN msg_tags mt ON mt.msg_id=tm.id
                WHERE {where_sql} AND mt.tag_type='ttp'
                GROUP BY mt.tag_value
                ORDER BY mentions DESC, avg_confidence DESC
                LIMIT 8
            """)

        related_iocs = []
        related_cves = []
        if table_exists(con, 'ioc_links') and table_exists(con, 'iocs'):
            quality_expr = 'COALESCE(i.quality,50)' if column_exists(con, 'iocs', 'quality') else '50'
            related_iocs = run(f"""
                SELECT i.type, i.value, COUNT(*) AS mentions, MAX({quality_expr}) AS quality
                FROM telegram_messages tm
                JOIN ioc_links il ON il.msg_id=tm.id
                JOIN iocs i ON i.id=il.ioc_id
                WHERE {where_sql} AND i.type NOT IN ('domain','url')
                GROUP BY i.type, i.value
                ORDER BY mentions DESC, quality DESC
                LIMIT 12
            """)
            related_cves = run(f"""
                SELECT i.value AS cve, COUNT(*) AS mentions, MAX(tm.timestamp) AS last_seen
                FROM telegram_messages tm
                JOIN ioc_links il ON il.msg_id=tm.id
                JOIN iocs i ON i.id=il.ioc_id
                WHERE {where_sql} AND i.type='cve'
                GROUP BY i.value
                ORDER BY mentions DESC, last_seen DESC
                LIMIT 10
            """)

        recent_rows = run(f"""
            SELECT tm.*
            FROM telegram_messages tm
            WHERE {where_sql}
            ORDER BY tm.timestamp DESC
            LIMIT 8
        """)
        recent_messages = attach_telegram_intel(con, recent_rows)

        return {
            "group": name,
            "mentions": int(summary['mentions'] or 0),
            "mentions_24h": int(summary['mentions_24h'] or 0),
            "mentions_7d": int(summary['mentions_7d'] or 0),
            "last_seen": summary['last_seen'],
            "top_channels": [dict(r) for r in top_channels],
            "top_ttps": [dict(r) for r in top_ttps],
            "related_iocs": [dict(r) for r in related_iocs],
            "related_cves": [dict(r) for r in related_cves],
            "recent_messages": recent_messages,
        }
    except Exception as e:
        return {"group": name, "error": str(e), "mentions": 0, "mentions_24h": 0,
                "mentions_7d": 0, "last_seen": None, "top_channels": [],
                "top_ttps": [], "related_iocs": [], "related_cves": [], "recent_messages": []}


def ransomware_victim_timeline(con, group_name, victim_name, victim_domain='', published_ts=0):
    """Build a read-only Telegram timeline for a ransomware victim.
    Searches Telegram text for victim name/domain and returns before/after events.
    Never writes to the DB.
    """
    group = (group_name or '').strip()
    victim = re.sub(r'\s+', ' ', (victim_name or '').strip())
    domain = (victim_domain or '').strip().lower()
    try:
        published_ts = int(published_ts or 0)
    except Exception:
        published_ts = 0

    empty = {"group": group, "victim": victim, "domain": domain,
             "published_ts": published_ts, "mentions": 0, "before": 0,
             "after": 0, "first_seen": None, "last_seen": None,
             "top_channels": [], "related_iocs": [], "related_cves": [],
             "timeline": []}

    if not victim or len(victim) < 3 or not table_exists(con, 'telegram_messages'):
        return empty

    terms = []
    # Victim/company name is the main match term.
    terms.append(victim.lower())
    # Domain match is stronger when ransomware.live provides one.
    if domain and len(domain) > 3:
        terms.append(domain)
        root = domain.split('/')[0].replace('www.', '')
        if root and root not in terms:
            terms.append(root)

    # Avoid huge noisy searches from one-word generic victim names.
    cleaned_terms = []
    for t in terms:
        t = re.sub(r'\s+', ' ', t.strip().lower())
        if len(t) >= 4 and t not in cleaned_terms:
            cleaned_terms.append(t)
    if not cleaned_terms:
        return empty

    parts = ["LOWER(tm.text) LIKE ?" for _ in cleaned_terms]
    params = [f"%{t}%" for t in cleaned_terms]
    where_sql = "(" + " OR ".join(parts) + ")"
    if column_exists(con, 'telegram_messages', 'is_duplicate'):
        where_sql += " AND COALESCE(tm.is_duplicate,0)=0"

    try:
        summary = con.execute(f"""
            SELECT COUNT(*) AS mentions,
                   MIN(tm.timestamp) AS first_seen,
                   MAX(tm.timestamp) AS last_seen,
                   SUM(CASE WHEN ? > 0 AND tm.timestamp < ? THEN 1 ELSE 0 END) AS before_count,
                   SUM(CASE WHEN ? > 0 AND tm.timestamp >= ? THEN 1 ELSE 0 END) AS after_count
            FROM telegram_messages tm
            WHERE {where_sql}
        """, [published_ts, published_ts, published_ts, published_ts] + params).fetchone()

        tier_expr = "COALESCE(tc.source_tier,'unknown')" if column_exists(con, 'telegram_channels', 'source_tier') else "'unknown'"
        top_channels = con.execute(f"""
            SELECT COALESCE(tm.channel_name,'unknown') AS channel_name,
                   COUNT(*) AS mentions,
                   MAX(tm.timestamp) AS last_seen,
                   {tier_expr} AS source_tier
            FROM telegram_messages tm
            LEFT JOIN telegram_channels tc ON tc.channel_id=tm.channel_id
            WHERE {where_sql}
            GROUP BY COALESCE(tm.channel_name,'unknown'), {tier_expr}
            ORDER BY mentions DESC, last_seen DESC
            LIMIT 8
        """, params).fetchall()

        related_iocs = []
        related_cves = []
        if table_exists(con, 'ioc_links') and table_exists(con, 'iocs'):
            quality_expr = 'COALESCE(i.quality,50)' if column_exists(con, 'iocs', 'quality') else '50'
            related_iocs = con.execute(f"""
                SELECT i.type, i.value, COUNT(*) AS mentions, MAX({quality_expr}) AS quality
                FROM telegram_messages tm
                JOIN ioc_links il ON il.msg_id=tm.id
                JOIN iocs i ON i.id=il.ioc_id
                WHERE {where_sql} AND i.type NOT IN ('domain','url')
                GROUP BY i.type, i.value
                ORDER BY mentions DESC, quality DESC
                LIMIT 12
            """, params).fetchall()
            related_cves = con.execute(f"""
                SELECT i.value AS cve, COUNT(*) AS mentions, MAX(tm.timestamp) AS last_seen
                FROM telegram_messages tm
                JOIN ioc_links il ON il.msg_id=tm.id
                JOIN iocs i ON i.id=il.ioc_id
                WHERE {where_sql} AND i.type='cve'
                GROUP BY i.value
                ORDER BY mentions DESC, last_seen DESC
                LIMIT 10
            """, params).fetchall()

        rows = con.execute(f"""
            SELECT tm.*
            FROM telegram_messages tm
            WHERE {where_sql}
            ORDER BY tm.timestamp ASC
            LIMIT 80
        """, params).fetchall()
        messages = attach_telegram_intel(con, rows)

        # If the victim was published, keep the timeline focused around the event.
        if published_ts:
            start = published_ts - 45*86400
            end = published_ts + 30*86400
            focused = [m for m in messages if m.get('timestamp') and start <= int(m.get('timestamp')) <= end]
            if focused:
                messages = focused

        for m in messages:
            ts = int(m.get('timestamp') or 0)
            if published_ts and ts:
                if ts < published_ts:
                    m['timeline_relation'] = 'before'
                    m['days_from_publish'] = int((published_ts - ts) / 86400)
                elif ts >= published_ts:
                    m['timeline_relation'] = 'after'
                    m['days_from_publish'] = int((ts - published_ts) / 86400)
            else:
                m['timeline_relation'] = 'seen'
                m['days_from_publish'] = None

        return {
            "group": group,
            "victim": victim,
            "domain": domain,
            "published_ts": published_ts,
            "mentions": int(summary['mentions'] or 0),
            "before": int(summary['before_count'] or 0),
            "after": int(summary['after_count'] or 0),
            "first_seen": summary['first_seen'],
            "last_seen": summary['last_seen'],
            "top_channels": [dict(r) for r in top_channels],
            "related_iocs": [dict(r) for r in related_iocs],
            "related_cves": [dict(r) for r in related_cves],
            "timeline": messages[-40:],
        }
    except Exception as e:
        out = dict(empty)
        out['error'] = str(e)
        return out



def ensure_leak_archive_tables(con=None):
    """Create archive import queue/status tables used by leak_archive_worker.py."""
    own = con is None
    if own:
        con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS leak_archives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        download_url TEXT,
        victim_name TEXT,
        actor TEXT,
        leak_name TEXT,
        source_type TEXT,
        local_path TEXT,
        sha256 TEXT,
        status TEXT DEFAULT 'queued',
        malware_detected INTEGER DEFAULT 0,
        malware_signature TEXT,
        scan_result TEXT,
        error TEXT,
        files_found INTEGER DEFAULT 0,
        files_processed INTEGER DEFAULT 0,
        entities_imported INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS leak_archive_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        archive_id INTEGER,
        file_path TEXT,
        file_ext TEXT,
        size_bytes INTEGER,
        detected_type TEXT,
        score INTEGER DEFAULT 0,
        status TEXT DEFAULT 'queued',
        reason TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_leak_archives_status ON leak_archives(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_leak_archive_files_archive ON leak_archive_files(archive_id);
    """)
    if own:
        con.commit()
        con.close()

def start_leak_archive_worker(job_id):
    """Start one archive import job without blocking the dashboard."""
    worker = BASE_DIR / "leak_archive_worker.py"
    if not worker.exists():
        return {"ok": False, "reason": "leak_archive_worker.py not found in project folder"}
    subprocess.Popen(
        [sys.executable, str(worker), "--job-id", str(job_id)],
        cwd=str(BASE_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return {"ok": True}

def ensure_indexes():
    con = db()
    con.executescript("""
        CREATE INDEX IF NOT EXISTS idx_sites_noise_trust ON sites(noise,trust_score DESC,score DESC);
        CREATE INDEX IF NOT EXISTS idx_sites_host        ON sites(host);
        CREATE INDEX IF NOT EXISTS idx_sites_host_noise  ON sites(host,noise);
        CREATE INDEX IF NOT EXISTS idx_sites_category    ON sites(category,noise);
        CREATE INDEX IF NOT EXISTS idx_sites_bookmarked  ON sites(bookmarked,noise);
        CREATE INDEX IF NOT EXISTS idx_sites_timestamp   ON sites(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_leaks_conf        ON leaks(confidence DESC);
        CREATE INDEX IF NOT EXISTS idx_leaks_ts          ON leaks(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_tgmsg_leak        ON telegram_messages(has_leak,confidence DESC);
        CREATE INDEX IF NOT EXISTS idx_tgmsg_chan        ON telegram_messages(channel_id);
        CREATE INDEX IF NOT EXISTS idx_tgchan_source     ON telegram_channels(source_tier);
    """)
    con.commit(); con.close()

def ensure_db():
    con = db()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS sites (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        url            TEXT UNIQUE,
        host           TEXT,
        title          TEXT,
        status         INTEGER,
        preview        TEXT,
        category       TEXT,
        score          INTEGER,
        trust_score    INTEGER DEFAULT 0,
        noise          INTEGER DEFAULT 0,
        bookmarked     INTEGER DEFAULT 0,
        reviewed       INTEGER DEFAULT 0,
        notes          TEXT DEFAULT "",
        timestamp      INTEGER,
        last_seen      INTEGER,
        content_hash   TEXT,
        mirror_group   TEXT,
        language       TEXT DEFAULT "unknown",
        uptime_count   INTEGER DEFAULT 1,
        downtime_count INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_trust    ON sites(trust_score DESC);
    CREATE INDEX IF NOT EXISTS idx_score    ON sites(score DESC);
    CREATE INDEX IF NOT EXISTS idx_category ON sites(category);
    CREATE INDEX IF NOT EXISTS idx_bookmark ON sites(bookmarked);
    CREATE INDEX IF NOT EXISTS idx_noise    ON sites(noise);
    CREATE INDEX IF NOT EXISTS idx_mirror   ON sites(mirror_group);
    CREATE INDEX IF NOT EXISTS idx_host     ON sites(host);
    CREATE VIRTUAL TABLE IF NOT EXISTS sites_fts USING fts5(
        url, title, preview, category,
        content=sites, content_rowid=id
    );
    CREATE TABLE IF NOT EXISTS leaks (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        url            TEXT UNIQUE,
        title          TEXT,
        confidence     INTEGER,
        full_text      TEXT,
        cves           TEXT DEFAULT "[]",
        breach_targets TEXT DEFAULT "[]",
        record_counts  TEXT DEFAULT "[]",
        exploit_types  TEXT DEFAULT "[]",
        has_emails     INTEGER DEFAULT 0,
        has_hashes     INTEGER DEFAULT 0,
        has_ssn        INTEGER DEFAULT 0,
        has_magnet     INTEGER DEFAULT 0,
        reviewed       INTEGER DEFAULT 0,
        bookmarked     INTEGER DEFAULT 0,
        notes          TEXT DEFAULT "",
        timestamp      INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_leak_conf ON leaks(confidence DESC);
    CREATE VIRTUAL TABLE IF NOT EXISTS leaks_fts USING fts5(
        url, title, full_text, cves, breach_targets,
        content=leaks, content_rowid=id
    );
    CREATE TABLE IF NOT EXISTS alerts (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        keyword TEXT UNIQUE,
        created INTEGER
    );
    CREATE TABLE IF NOT EXISTS alert_hits (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id  INTEGER,
        site_id   INTEGER,
        site_type TEXT DEFAULT "site",
        seen      INTEGER DEFAULT 0,
        timestamp INTEGER
    );
    CREATE TABLE IF NOT EXISTS crawl_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   INTEGER,
        sites_found INTEGER,
        leaks_found INTEGER,
        duration_s  INTEGER
    );
    CREATE TABLE IF NOT EXISTS file_links (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id   INTEGER,
        url       TEXT UNIQUE,
        extension TEXT,
        timestamp INTEGER
    );
    CREATE TABLE IF NOT EXISTS recrawl_queue (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id      INTEGER UNIQUE,
        url          TEXT,
        interval_h   INTEGER DEFAULT 24,
        last_crawled INTEGER,
        next_crawl   INTEGER,
        change_count INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS site_history (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id         INTEGER,
        timestamp       INTEGER,
        status          INTEGER,
        content_changed INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS telegram_channels (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        url          TEXT UNIQUE,
        name         TEXT,
        channel_id   TEXT,
        channel_type TEXT DEFAULT 'cti',
        joined       INTEGER DEFAULT 0,
        active       INTEGER DEFAULT 1,
        message_count INTEGER DEFAULT 0,
        last_message INTEGER,
        discovered_from TEXT,
        source_tier TEXT DEFAULT 'unknown'
    );
    CREATE TABLE IF NOT EXISTS telegram_messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id  TEXT,
        channel_name TEXT,
        message_id  INTEGER,
        text        TEXT,
        timestamp   INTEGER,
        has_leak    INTEGER DEFAULT 0,
        confidence  INTEGER DEFAULT 0,
        UNIQUE(channel_id, message_id)
    );
    CREATE INDEX IF NOT EXISTS idx_tgmsg_leak ON telegram_messages(has_leak,confidence DESC);
    CREATE INDEX IF NOT EXISTS idx_tgmsg_chan ON telegram_messages(channel_id);
    CREATE TABLE IF NOT EXISTS paste_items (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        site_name  TEXT,
        url        TEXT UNIQUE,
        content    TEXT,
        has_leak   INTEGER DEFAULT 0,
        confidence INTEGER DEFAULT 0,
        first_seen INTEGER
    );
    CREATE TABLE IF NOT EXISTS stealer_logs (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        filename  TEXT UNIQUE,
        log_type  TEXT,
        parsed_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS stealer_credentials (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id   INTEGER,
        url      TEXT,
        username TEXT,
        password TEXT
    );
    CREATE TABLE IF NOT EXISTS canary_hits (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        token_id   TEXT,
        token_type TEXT,
        memo       TEXT,
        src_ip     TEXT,
        geo        TEXT,
        useragent  TEXT,
        raw        TEXT,
        timestamp  INTEGER
    );
    ''')
    # Safe Telegram channel/source migrations used by the Telegram intel UI.
    tg_chan_cols = {r[1] for r in con.execute("PRAGMA table_info(telegram_channels)").fetchall()}
    if 'source_tier' not in tg_chan_cols:
        con.execute("ALTER TABLE telegram_channels ADD COLUMN source_tier TEXT DEFAULT 'unknown'")

    tg_msg_cols = {r[1] for r in con.execute("PRAGMA table_info(telegram_messages)").fetchall()}
    if 'intel_processed' not in tg_msg_cols:
        con.execute("ALTER TABLE telegram_messages ADD COLUMN intel_processed INTEGER DEFAULT 0")
    if 'is_duplicate' not in tg_msg_cols:
        con.execute("ALTER TABLE telegram_messages ADD COLUMN is_duplicate INTEGER DEFAULT 0")
    if 'msg_hash' not in tg_msg_cols:
        con.execute("ALTER TABLE telegram_messages ADD COLUMN msg_hash TEXT")

    ensure_leak_archive_tables(con)

def update_trust_scores():
    """Recalculate trust scores for all sites — runs after re-crawl updates."""
    con = db()
    rows = con.execute(
        "SELECT id,score,uptime_count,downtime_count,bookmarked,reviewed,"
        "mirror_group,preview FROM sites WHERE noise=0"
    ).fetchall()
    updates = [(trust_score(dict(r)), r['id']) for r in rows]
    con.executemany("UPDATE sites SET trust_score=? WHERE id=?", updates)
    con.commit()
    con.close()

def group_mirrors():
    con = db()
    # Group by identical title
    dupes = con.execute('''
        SELECT LOWER(TRIM(title)) as t, COUNT(*) as c
        FROM sites WHERE noise=0 AND title != "" AND title != "[no title]"
        GROUP BY t HAVING c > 1
    ''').fetchall()
    for row in dupes:
        mg = hashlib.md5(row['t'].encode()).hexdigest()[:12]
        con.execute("UPDATE sites SET mirror_group=? WHERE LOWER(TRIM(title))=? AND noise=0",
                    (mg, row['t']))
    # Also group by content hash
    hash_dupes = con.execute('''
        SELECT content_hash, COUNT(*) as c
        FROM sites WHERE noise=0 AND content_hash IS NOT NULL
        GROUP BY content_hash HAVING c > 1
    ''').fetchall()
    for row in hash_dupes:
        mg = hashlib.md5(row['content_hash'].encode()).hexdigest()[:12]
        con.execute("UPDATE sites SET mirror_group=? WHERE content_hash=? AND noise=0",
                    (mg, row['content_hash']))
    con.commit()
    con.close()
    return len(dupes) + len(hash_dupes)

def run_alerts(new_site_ids, new_leak_ids):
    con = db()
    alerts = con.execute("SELECT * FROM alerts").fetchall()
    if not alerts:
        con.close()
        return
    for alert in alerts:
        kw = alert['keyword'].lower()
        for sid in new_site_ids:
            s = con.execute("SELECT title,preview FROM sites WHERE id=?", (sid,)).fetchone()
            if s and kw in f"{s['title']} {s['preview']}".lower():
                con.execute(
                    "INSERT OR IGNORE INTO alert_hits (alert_id,site_id,site_type,seen,timestamp) VALUES (?,?,?,0,?)",
                    (alert['id'], sid, 'site', int(time.time())))
        for lid in new_leak_ids:
            l = con.execute("SELECT title,full_text FROM leaks WHERE id=?", (lid,)).fetchone()
            if l and kw in f"{l['title']} {l['full_text']}".lower():
                con.execute(
                    "INSERT OR IGNORE INTO alert_hits (alert_id,site_id,site_type,seen,timestamp) VALUES (?,?,?,0,?)",
                    (alert['id'], lid, 'leak', int(time.time())))
    con.commit()
    con.close()





# ── HTTP Handler ───────────────────────────────────────────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",len(body))
        self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """Handle POST requests -- file uploads and webhook alerts."""
        if self.path.startswith("/webhook/"):
            self.do_GET()
            return

        if self.path == "/api/archive_import/upload":
            import uuid as _uuid, re as _re
            ct = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in ct:
                self.send_json({"ok": False, "reason": "Expected multipart/form-data"}, 400)
                return
            try:
                m = _re.search(r'boundary=([^\s;]+)', ct)
                if not m:
                    self.send_json({"ok": False, "reason": "No boundary in Content-Type"}, 400)
                    return
                boundary = m.group(1).strip('"').encode()
                length   = int(self.headers.get("Content-Length", 0))
                body     = self.rfile.read(length)
                fields, file_bytes, file_name = {}, None, None
                for part in body.split(b"--" + boundary)[1:]:
                    if part.startswith(b"--"):
                        break
                    if b"\r\n\r\n" not in part:
                        continue
                    raw_hdrs, part_body = part.split(b"\r\n\r\n", 1)
                    if part_body.endswith(b"\r\n"):
                        part_body = part_body[:-2]
                    hdr = raw_hdrs.decode("utf-8", errors="replace")
                    name_m  = _re.search(r'name="([^"]+)"', hdr, _re.I)
                    fname_m = _re.search(r'filename="([^"]*)"', hdr, _re.I)
                    if not name_m:
                        continue
                    if fname_m:
                        file_name  = Path(fname_m.group(1)).name
                        file_bytes = part_body
                    else:
                        fields[name_m.group(1)] = part_body.decode("utf-8", errors="replace")
                if not file_bytes or not file_name:
                    self.send_json({"ok": False, "reason": "No file received"}, 400)
                    return
                victim_name = fields.get("victim_name", "").strip()
                actor       = fields.get("actor", "unknown").strip() or "unknown"
                leak_name   = fields.get("leak_name", "").strip() or Path(file_name).stem
                source_type = fields.get("source_type", "archive").strip() or "archive"
                upload_dir  = BASE_DIR / "stealer_uploads"
                upload_dir.mkdir(exist_ok=True)
                safe_name = f"{int(time.time())}_{_uuid.uuid4().hex[:6]}_{file_name}"
                (upload_dir / safe_name).write_bytes(file_bytes)
                ensure_leak_archive_tables()
                con = db()
                try:
                    cur = con.execute("""
                        INSERT INTO leak_archives
                        (download_url, victim_name, actor, leak_name, source_type,
                         local_path, status)
                        VALUES (?, ?, ?, ?, ?, ?, 'queued')
                    """, (f"local://{safe_name}", victim_name, actor, leak_name,
                          source_type, str(upload_dir / safe_name)))
                    job_id = cur.lastrowid
                    con.commit()
                    worker_res = start_leak_archive_worker(job_id)
                    if not worker_res.get("ok"):
                        con.execute("UPDATE leak_archives SET status='worker_missing', error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                                    (worker_res.get("reason"), job_id))
                        con.commit()
                        self.send_json({"ok": False, "job_id": job_id, "reason": worker_res.get("reason")}, 500)
                        return
                    self.send_json({"ok": True, "job_id": job_id, "filename": safe_name})
                except Exception as e:
                    self.send_json({"ok": False, "reason": str(e)}, 500)
                finally:
                    con.close()
            except Exception as e:
                self.send_json({"ok": False, "reason": str(e)}, 500)
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)
        g  = lambda k,d="": qs.get(k,[d])[0]

        if p.path == "/" or p.path.startswith("/group/"):
            body = DASHBOARD_HTML.encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",len(body))
            self.end_headers()
            self.wfile.write(body)
            return


        elif p.path == "/api/status":
            con = db()
            leaks_c = con.execute("SELECT COUNT(*) FROM leaks").fetchone()[0]
            unseen  = con.execute("SELECT COUNT(*) FROM alert_hits WHERE seen=0").fetchone()[0]
            tg_msg  = con.execute("SELECT COUNT(*) FROM telegram_messages").fetchone()[0]
            tg_leak = con.execute("SELECT COUNT(*) FROM telegram_messages WHERE has_leak=1").fetchone()[0]
            con.close()
            self.send_json({"leaks":leaks_c,"unseen_alerts":unseen,
                           "tg_messages":tg_msg,"tg_leaks":tg_leak})

        elif p.path == "/api/categories":
            con  = db()
            rows = con.execute("SELECT category,COUNT(*) as count FROM sites WHERE noise=0 GROUP BY category ORDER BY count DESC").fetchall()
            con.close()
            self.send_json([dict(r) for r in rows])

        elif p.path == "/api/top":
            con  = db()
            rows = con.execute("SELECT * FROM sites WHERE noise=0 ORDER BY trust_score DESC,score DESC LIMIT 30").fetchall()
            con.close()
            self.send_json([dict(r) for r in rows])

        elif p.path == "/api/leaks":
            q    = g("q"); sort=g("sort","confidence")
            page = int(g("page","1")); per_page=50; offset=(page-1)*per_page
            where, params = [], []
            if q:
                where.append("id IN (SELECT rowid FROM leaks_fts WHERE leaks_fts MATCH ?)")
                params.append(q+"*")
            w     = ("WHERE "+" AND ".join(where)) if where else ""
            order = {"confidence":"confidence DESC","newest":"timestamp DESC"}.get(sort,"confidence DESC")
            con   = db()
            total = con.execute(f"SELECT COUNT(*) FROM leaks {w}",params).fetchone()[0]
            rows  = con.execute(f"SELECT * FROM leaks {w} ORDER BY {order} LIMIT ? OFFSET ?",
                                params+[per_page,offset]).fetchall()
            con.close()
            self.send_json({"leaks":[dict(r) for r in rows],"total":total})

        elif p.path == "/api/leaks/search":
            term = g("term","").strip()
            if not term or len(term)<3:
                self.send_json({"results":[],"total":0}); return
            con  = db()
            rows = con.execute(
                "SELECT * FROM leaks WHERE full_text LIKE ? ORDER BY confidence DESC LIMIT 50",
                (f"%{term}%",)).fetchall()
            con.close()
            self.send_json({"results":[dict(r) for r in rows],"total":len(rows)})

        elif p.path == "/api/intel/search":
            term = g("term","").strip()
            if not term or len(term)<3:
                self.send_json({"term":term,"total":0,"exposures":[],"leaks":[],"telegram":[]}); return
            like = f"%{term}%"
            con = db()
            try:
                exposures = []
                if table_exists(con, "exposure_entities"):
                    cols = {r[1] for r in con.execute("PRAGMA table_info(exposure_entities)").fetchall()}
                    value_col = "value_plain" if "value_plain" in cols else ("value" if "value" in cols else None)
                    type_col = "entity_type" if "entity_type" in cols else ("type" if "type" in cols else None)
                    times_col = "times_seen" if "times_seen" in cols else None
                    if value_col:
                        select_cols = [f"{value_col} AS value"]
                        select_cols.append(f"{type_col} AS entity_type" if type_col else "'unknown' AS entity_type")
                        select_cols.append(f"{times_col} AS times_seen" if times_col else "1 AS times_seen")
                        if "id" in cols:
                            select_cols.append("id")
                        rows = con.execute(
                            f"SELECT {', '.join(select_cols)} FROM exposure_entities WHERE {value_col} LIKE ? ORDER BY times_seen DESC LIMIT 100",
                            (like,)
                        ).fetchall()
                        exposures = [dict(r) for r in rows]

                leaks = []
                if table_exists(con, "leaks"):
                    leaks = [dict(r) for r in con.execute(
                        "SELECT id,url,title,confidence,has_emails,has_hashes,has_ssn,has_magnet,timestamp "
                        "FROM leaks WHERE title LIKE ? OR url LIKE ? OR full_text LIKE ? "
                        "ORDER BY confidence DESC LIMIT 50",
                        (like, like, like)
                    ).fetchall()]

                telegram = []
                if table_exists(con, "telegram_messages"):
                    telegram = [dict(r) for r in con.execute(
                        "SELECT id,channel_name,message_id,text,timestamp,confidence,has_leak "
                        "FROM telegram_messages WHERE text LIKE ? OR channel_name LIKE ? "
                        "ORDER BY timestamp DESC LIMIT 50",
                        (like, like)
                    ).fetchall()]

                self.send_json({
                    "term": term,
                    "total": len(exposures) + len(leaks) + len(telegram),
                    "exposures": exposures,
                    "leaks": leaks,
                    "telegram": telegram
                })
            except Exception as e:
                self.send_json({"term":term,"total":0,"exposures":[],"leaks":[],"telegram":[],"error":str(e)}, 500)
            finally:
                con.close()

        elif p.path == "/api/search/context":
            q = g("q","").strip()
            max_rows = int(g("max","20") or 20)
            if not q or len(q)<2:
                self.send_json({"results":[],"total":0}); return
            like = f"%{q}%"
            qlow = q.lower()
            results = []
            def make_snippet(txt):
                txt = txt or ""
                low = txt.lower()
                idx = low.find(qlow)
                if idx < 0:
                    return txt[:240], -1, -1
                start = max(0, idx - 90)
                end = min(len(txt), idx + len(q) + 150)
                return txt[start:end], idx - start, idx - start + len(q)
            con = db()
            try:
                if table_exists(con, "leaks"):
                    for r in con.execute(
                        "SELECT id,url,title,full_text,confidence FROM leaks "
                        "WHERE title LIKE ? OR url LIKE ? OR full_text LIKE ? "
                        "ORDER BY confidence DESC LIMIT ?",
                        (like, like, like, max_rows)
                    ).fetchall():
                        sn, s, e = make_snippet(r["full_text"] or r["title"] or "")
                        results.append({"source":"leaks","id":r["id"],"title":r["title"],"url":r["url"],"snippet":sn,"kw_start":s,"kw_end":e,"confidence":r["confidence"]})

                if table_exists(con, "telegram_messages") and len(results) < max_rows:
                    for r in con.execute(
                        "SELECT id,channel_name,message_id,text,timestamp,confidence FROM telegram_messages "
                        "WHERE text LIKE ? OR channel_name LIKE ? ORDER BY timestamp DESC LIMIT ?",
                        (like, like, max_rows - len(results))
                    ).fetchall():
                        sn, s, e = make_snippet(r["text"] or "")
                        title = f"Telegram: {r['channel_name'] or 'unknown'} #{r['message_id'] or ''}"
                        results.append({"source":"telegram","id":r["id"],"title":title,"url":"","snippet":sn,"kw_start":s,"kw_end":e,"confidence":r["confidence"]})

                if table_exists(con, "exposure_entities") and len(results) < max_rows:
                    cols = {rr[1] for rr in con.execute("PRAGMA table_info(exposure_entities)").fetchall()}
                    value_col = "value_plain" if "value_plain" in cols else ("value" if "value" in cols else None)
                    type_col = "entity_type" if "entity_type" in cols else ("type" if "type" in cols else None)
                    times_col = "times_seen" if "times_seen" in cols else None
                    if value_col:
                        select_cols = [f"{value_col} AS value"]
                        select_cols.append(f"{type_col} AS entity_type" if type_col else "'unknown' AS entity_type")
                        select_cols.append(f"{times_col} AS times_seen" if times_col else "1 AS times_seen")
                        for r in con.execute(
                            f"SELECT {', '.join(select_cols)} FROM exposure_entities WHERE {value_col} LIKE ? ORDER BY times_seen DESC LIMIT ?",
                            (like, max_rows - len(results))
                        ).fetchall():
                            sn, s, e = make_snippet(r["value"] or "")
                            results.append({"source":"archive","id":None,"title":f"Imported dump entity: {r['entity_type']}","url":"","snippet":sn,"kw_start":s,"kw_end":e,"times_seen":r["times_seen"]})
                self.send_json({"results":results[:max_rows],"total":len(results)})
            except Exception as e:
                self.send_json({"results":[],"total":0,"error":str(e)}, 500)
            finally:
                con.close()

        elif p.path == "/api/alerts":
            con  = db()
            rows = con.execute('''
                SELECT a.*,COUNT(h.id) as hit_count,
                       SUM(CASE WHEN h.seen=0 THEN 1 ELSE 0 END) as unseen
                FROM alerts a LEFT JOIN alert_hits h ON h.alert_id=a.id
                GROUP BY a.id ORDER BY a.created DESC
            ''').fetchall()
            con.close()
            self.send_json([dict(r) for r in rows])

        elif p.path == "/api/alerts/add":
            kw = g("keyword","").strip().lower()
            if not kw: self.send_json({"ok":False,"error":"empty"}); return
            con = db()
            try:
                con.execute("INSERT INTO alerts (keyword,created) VALUES(?,?)",(kw,int(time.time())))
                con.commit(); self.send_json({"ok":True})
            except sqlite3.IntegrityError:
                self.send_json({"ok":False,"error":"already exists"})
            con.close()

        elif p.path == "/api/alerts/delete":
            aid = int(g("id","0")); con = db()
            con.execute("DELETE FROM alerts WHERE id=?",(aid,))
            con.execute("DELETE FROM alert_hits WHERE alert_id=?",(aid,))
            con.commit(); con.close()
            self.send_json({"ok":True})

        elif p.path == "/api/alerts/hits":
            con  = db()
            rows = con.execute('''
                SELECT h.*,a.keyword,
                    CASE h.site_type WHEN "site" THEN (SELECT title FROM sites WHERE id=h.site_id)
                    ELSE (SELECT title FROM leaks WHERE id=h.site_id) END as title,
                    CASE h.site_type WHEN "site" THEN (SELECT url FROM sites WHERE id=h.site_id)
                    ELSE (SELECT url FROM leaks WHERE id=h.site_id) END as url
                FROM alert_hits h JOIN alerts a ON a.id=h.alert_id
                ORDER BY h.timestamp DESC LIMIT 100
            ''').fetchall()
            con.execute("UPDATE alert_hits SET seen=1 WHERE seen=0")
            con.commit(); con.close()
            self.send_json([dict(r) for r in rows])

        elif p.path == "/api/stats":
            con = db()
            self.send_json({
                "leaks":      con.execute("SELECT COUNT(*) FROM leaks").fetchone()[0],
                "tg_total":   con.execute("SELECT COUNT(*) FROM telegram_messages").fetchone()[0],
                "tg_leaks":   con.execute("SELECT COUNT(*) FROM telegram_messages WHERE has_leak=1").fetchone()[0],
                "channels":   con.execute("SELECT COUNT(*) FROM telegram_channels WHERE joined=1").fetchone()[0] if table_exists(con,"telegram_channels") else 0,
                "archives":   con.execute("SELECT COUNT(*) FROM leak_archives").fetchone()[0] if table_exists(con,"leak_archives") else 0,
                "iocs":       con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0] if table_exists(con,"iocs") else 0,
            })
            con.close()



        elif p.path == "/api/archive_import/create":
            ensure_leak_archive_tables()
            download_url = g("download_url","").strip()
            victim_name = g("victim_name","").strip()
            actor = g("actor","").strip() or "unknown"
            leak_name = g("leak_name","").strip()
            source_type = g("source_type","archive").strip() or "archive"
            if not download_url:
                self.send_json({"ok": False, "reason": "Missing download_url"}, 400)
                return
            con = db()
            try:
                cur = con.execute("""
                    INSERT INTO leak_archives
                    (download_url, victim_name, actor, leak_name, source_type, status)
                    VALUES (?, ?, ?, ?, ?, 'queued')
                """, (download_url, victim_name, actor, leak_name, source_type))
                job_id = cur.lastrowid
                con.commit()
                worker_res = start_leak_archive_worker(job_id)
                if not worker_res.get("ok"):
                    con.execute("UPDATE leak_archives SET status='worker_missing', error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                                (worker_res.get("reason"), job_id))
                    con.commit()
                    self.send_json({"ok": False, "job_id": job_id, "reason": worker_res.get("reason")}, 500)
                    return
                self.send_json({"ok": True, "job_id": job_id})
            except Exception as e:
                self.send_json({"ok": False, "reason": str(e)}, 500)
            finally:
                con.close()

        elif p.path == "/api/archive_import/update":
            ensure_leak_archive_tables()
            job_id = g("id", "").strip()
            if not job_id:
                self.send_json({"ok": False, "reason": "Missing id"}, 400); return
            updates = {k: v for k, v in {
                "victim_name": g("victim_name"),
                "actor":       g("actor"),
                "leak_name":   g("leak_name"),
            }.items() if qs.get(k) is not None}
            if not updates:
                self.send_json({"ok": False, "reason": "No fields to update"}, 400); return
            con = db()
            try:
                set_clause = ", ".join(f"{k}=?" for k in updates)
                con.execute(
                    f"UPDATE leak_archives SET {set_clause}, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    list(updates.values()) + [job_id]
                )
                con.commit()
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"ok": False, "reason": str(e)}, 500)
            finally:
                con.close()

        elif p.path == "/api/archive_import/jobs":
            ensure_leak_archive_tables()
            con = db()
            try:
                rows = con.execute("""
                    SELECT *
                    FROM leak_archives
                    ORDER BY id DESC
                    LIMIT 100
                """).fetchall()
                self.send_json({"jobs": [dict(r) for r in rows]})
            except Exception as e:
                self.send_json({"jobs": [], "error": str(e)}, 500)
            finally:
                con.close()

        elif p.path == "/api/archive_import/files":
            ensure_leak_archive_tables()
            archive_id = int(g("id","0") or 0)
            con = db()
            try:
                rows = con.execute("""
                    SELECT *
                    FROM leak_archive_files
                    WHERE archive_id=?
                    ORDER BY score DESC, size_bytes DESC
                    LIMIT 300
                """, (archive_id,)).fetchall()
                self.send_json({"files": [dict(r) for r in rows]})
            except Exception as e:
                self.send_json({"files": [], "error": str(e)}, 500)
            finally:
                con.close()

        elif p.path == "/api/archive_import/run":
            ensure_leak_archive_tables()
            job_id = int(g("id","0") or 0)
            if not job_id:
                self.send_json({"ok": False, "reason": "Missing id"}, 400)
                return
            con = db()
            try:
                con.execute("UPDATE leak_archives SET status='queued', error=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?", (job_id,))
                con.commit()
                worker_res = start_leak_archive_worker(job_id)
                self.send_json({"ok": worker_res.get("ok", False), "reason": worker_res.get("reason")})
            finally:
                con.close()





        elif p.path=="/api/bookmark":
            sid=int(g("id","0")); val=int(g("val","1")); con=db()
            con.execute("UPDATE sites SET bookmarked=? WHERE id=?",(val,sid))
            con.commit(); con.close(); self.send_json({"ok":True})
        elif p.path=="/api/reviewed":
            sid=int(g("id","0")); val=int(g("val","1")); con=db()
            con.execute("UPDATE sites SET reviewed=? WHERE id=?",(val,sid))
            con.commit(); con.close(); self.send_json({"ok":True})
        elif p.path=="/api/note":
            sid=int(g("id","0")); note=g("note",""); con=db()
            con.execute("UPDATE sites SET notes=? WHERE id=?",(note,sid))
            con.commit(); con.close(); self.send_json({"ok":True})
        elif p.path=="/api/leaks/bookmark":
            sid=int(g("id","0")); val=int(g("val","1")); con=db()
            con.execute("UPDATE leaks SET bookmarked=? WHERE id=?",(val,sid))
            con.commit(); con.close(); self.send_json({"ok":True})
        elif p.path == "/api/leaks/cleanup":
            # Remove false positives below new confidence threshold
            threshold = int(g("threshold","40"))
            con = db()
            removed = con.execute(
                "SELECT COUNT(*) FROM leaks WHERE confidence<?", (threshold,)
            ).fetchone()[0]
            con.execute("DELETE FROM leaks WHERE confidence<?", (threshold,))
            con.commit(); con.close()
            self.send_json({"ok":True,"removed":removed})

        elif p.path == "/api/telegram":
            view = g("view","leaks")  # leaks|all|channels
            q    = g("q")
            page = int(g("page","1")); per_page=50; offset=(page-1)*per_page
            actor = g("actor")
            threat = g("threat")
            ttp = g("ttp")
            ioc_type = g("ioc_type")
            source_tier = g("source_tier")
            min_conf = int(g("min_conf","0") or 0)
            days = int(g("days","0") or 0)
            hide_dupes = g("hide_dupes","0") == "1"
            con  = db()
            try:
                if view == "channels":
                    where, params = [], []
                    if q:
                        where.append("(url LIKE ? OR name LIKE ? OR channel_type LIKE ?)")
                        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
                    if source_tier:
                        where.append("COALESCE(source_tier,'unknown')=?")
                        params.append(source_tier)
                    w = ("WHERE " + " AND ".join(where)) if where else ""
                    rows = con.execute(
                        f"SELECT * FROM telegram_channels {w} ORDER BY message_count DESC LIMIT 200", params
                    ).fetchall()
                    self.send_json({"channels":[dict(r) for r in rows]})
                    return

                muted_sub = "SELECT channel_id FROM telegram_channels WHERE active=0 AND channel_id IS NOT NULL"
                where = [f"channel_id NOT IN ({muted_sub})"]
                params = []
                if view == "leaks":
                    where.append("has_leak=1")
                if q:
                    where.append("(text LIKE ? OR channel_name LIKE ?)")
                    params.extend([f"%{q}%", f"%{q}%"])
                if min_conf > 0:
                    where.append("confidence>=?")
                    params.append(min_conf)
                if days > 0:
                    where.append("timestamp>=?")
                    params.append(int(time.time()) - days * 86400)
                if hide_dupes and column_exists(con, 'telegram_messages', 'is_duplicate'):
                    where.append("COALESCE(is_duplicate,0)=0")
                if source_tier:
                    where.append("EXISTS (SELECT 1 FROM telegram_channels tc WHERE tc.channel_id=telegram_messages.channel_id AND COALESCE(tc.source_tier,'unknown')=?)")
                    params.append(source_tier)

                # Read-only intelligence filters. If enrichment tables do not exist yet,
                # the filters safely return no matches instead of breaking the Telegram tab.
                if actor:
                    if table_exists(con, 'msg_tags'):
                        where.append("EXISTS (SELECT 1 FROM msg_tags mt WHERE mt.msg_id=telegram_messages.id AND mt.tag_type='actor' AND mt.tag_value=?)")
                        params.append(actor)
                    else:
                        where.append("0")
                if threat:
                    if table_exists(con, 'msg_tags'):
                        where.append("EXISTS (SELECT 1 FROM msg_tags mt WHERE mt.msg_id=telegram_messages.id AND mt.tag_type='threat_type' AND mt.tag_value=?)")
                        params.append(threat)
                    else:
                        where.append("0")
                if ttp:
                    if table_exists(con, 'msg_tags'):
                        where.append("EXISTS (SELECT 1 FROM msg_tags mt WHERE mt.msg_id=telegram_messages.id AND mt.tag_type='ttp' AND mt.tag_value=?)")
                        params.append(ttp)
                    else:
                        where.append("0")
                if ioc_type:
                    if table_exists(con, 'ioc_links') and table_exists(con, 'iocs'):
                        where.append("EXISTS (SELECT 1 FROM ioc_links il JOIN iocs i ON i.id=il.ioc_id WHERE il.msg_id=telegram_messages.id AND i.type=?)")
                        params.append(ioc_type)
                    else:
                        where.append("0")

                w = "WHERE " + " AND ".join(where)
                total = con.execute(f"SELECT COUNT(*) FROM telegram_messages {w}",params).fetchone()[0]
                rows  = con.execute(
                    f"SELECT * FROM telegram_messages {w} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    params+[per_page,offset]).fetchall()
                self.send_json({"messages":attach_telegram_intel(con, rows),"total":total})
            finally:
                con.close()

        elif p.path == "/api/telegram/filter_options":
            con = db()
            try:
                actors = []
                threats = []
                ttps = []
                ioc_types = []
                if table_exists(con, 'msg_tags'):
                    actors = [r['tag_value'] for r in con.execute(
                        "SELECT tag_value, COUNT(*) c FROM msg_tags WHERE tag_type='actor' GROUP BY tag_value ORDER BY c DESC, tag_value LIMIT 100"
                    ).fetchall()]
                    threats = [r['tag_value'] for r in con.execute(
                        "SELECT tag_value, COUNT(*) c FROM msg_tags WHERE tag_type='threat_type' GROUP BY tag_value ORDER BY c DESC, tag_value LIMIT 100"
                    ).fetchall()]
                    ttps = [r['tag_value'] for r in con.execute(
                        "SELECT tag_value, COUNT(*) c FROM msg_tags WHERE tag_type='ttp' GROUP BY tag_value ORDER BY c DESC, tag_value LIMIT 100"
                    ).fetchall()]
                if table_exists(con, 'iocs'):
                    ioc_types = [r['type'] for r in con.execute(
                        "SELECT type, COUNT(*) c FROM iocs GROUP BY type ORDER BY c DESC, type LIMIT 50"
                    ).fetchall()]
                tiers = [r['source_tier'] for r in con.execute(
                    "SELECT COALESCE(source_tier,'unknown') AS source_tier, COUNT(*) c FROM telegram_channels GROUP BY COALESCE(source_tier,'unknown') ORDER BY c DESC"
                ).fetchall()]
                self.send_json({"actors":actors,"threats":threats,"ttps":ttps,"ioc_types":ioc_types,"source_tiers":tiers})
            except Exception as e:
                self.send_json({"actors":[],"threats":[],"ttps":[],"ioc_types":[],"source_tiers":["unknown"]})
            finally:
                con.close()

        elif p.path == "/api/telegram/source_tier":
            url = g("url")
            tier = g("tier","unknown")
            allowed = {'actor_owned','affiliate','broker','intel_source','news_repost','random','spam','unknown'}
            if tier not in allowed:
                self.send_json({"ok": False, "reason": "Invalid source tier"}, 400)
                return
            if not url:
                self.send_json({"ok": False, "reason": "Missing channel URL"}, 400)
                return
            con = db()
            try:
                con.execute("UPDATE telegram_channels SET source_tier=? WHERE url=?", (tier, url))
                con.commit()
                self.send_json({"ok": True, "source_tier": tier})
            except Exception as e:
                self.send_json({"ok": False, "reason": str(e)}, 500)
            finally:
                con.close()

        elif p.path == "/api/telegram/stats":
            try:
                con = db()
                total_msg  = con.execute("SELECT COUNT(*) FROM telegram_messages").fetchone()[0]
                leak_msg   = con.execute("SELECT COUNT(*) FROM telegram_messages WHERE has_leak=1").fetchone()[0]
                channels   = con.execute("SELECT COUNT(*) FROM telegram_channels WHERE joined=1").fetchone()[0]
                discovered = con.execute("SELECT COUNT(*) FROM telegram_channels WHERE channel_type='discovered'").fetchone()[0]
                con.close()
                self.send_json({"total_messages":total_msg,"leak_messages":leak_msg,
                               "joined_channels":channels,"discovered_channels":discovered})
            except:
                self.send_json({"total_messages":0,"leak_messages":0,"joined_channels":0,"discovered_channels":0})

        elif p.path == "/api/intel/dashboard":
            days = int(g("days","7") or 0)
            since = int(time.time()) - days * 86400 if days > 0 else 0
            con = db()
            try:
                total_messages = con.execute("SELECT COUNT(*) FROM telegram_messages").fetchone()[0] if table_exists(con, 'telegram_messages') else 0
                processed = 0
                queue = 0
                dupes = 0
                if table_exists(con, 'telegram_messages'):
                    if column_exists(con, 'telegram_messages', 'intel_processed'):
                        processed = con.execute("SELECT COUNT(*) FROM telegram_messages WHERE intel_processed=1").fetchone()[0]
                        queue = con.execute("SELECT COUNT(*) FROM telegram_messages WHERE intel_processed=0").fetchone()[0]
                    if column_exists(con, 'telegram_messages', 'is_duplicate'):
                        dupes = con.execute("SELECT COUNT(*) FROM telegram_messages WHERE is_duplicate=1").fetchone()[0]

                ioc_count = con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0] if table_exists(con, 'iocs') else 0
                tag_count = con.execute("SELECT COUNT(*) FROM msg_tags").fetchone()[0] if table_exists(con, 'msg_tags') else 0

                def qrows(sql, params=()):
                    try:
                        return [dict(r) for r in con.execute(sql, params).fetchall()]
                    except Exception:
                        return []

                time_clause = ""
                time_params = []
                if since:
                    time_clause = " AND tm.timestamp>=?"
                    time_params = [since]

                top_actors = []
                threat_types = []
                top_ttps = []
                if table_exists(con, 'msg_tags') and table_exists(con, 'telegram_messages'):
                    conf_expr = "COALESCE(mt.confidence,50)" if column_exists(con, 'msg_tags', 'confidence') else "50"
                    top_actors = qrows(
                        "SELECT mt.tag_value AS name, COUNT(*) AS count, ROUND(AVG("+conf_expr+")) AS avg_conf "
                        "FROM msg_tags mt JOIN telegram_messages tm ON tm.id=mt.msg_id "
                        "WHERE mt.tag_type='actor'" + time_clause +
                        " GROUP BY mt.tag_value ORDER BY count DESC LIMIT 10", time_params)
                    threat_types = qrows(
                        "SELECT mt.tag_value AS name, COUNT(*) AS count, ROUND(AVG("+conf_expr+")) AS avg_conf "
                        "FROM msg_tags mt JOIN telegram_messages tm ON tm.id=mt.msg_id "
                        "WHERE mt.tag_type='threat_type'" + time_clause +
                        " GROUP BY mt.tag_value ORDER BY count DESC LIMIT 10", time_params)
                    top_ttps = qrows(
                        "SELECT mt.tag_value AS name, COUNT(*) AS count, ROUND(AVG("+conf_expr+")) AS avg_conf "
                        "FROM msg_tags mt JOIN telegram_messages tm ON tm.id=mt.msg_id "
                        "WHERE mt.tag_type='ttp'" + time_clause +
                        " GROUP BY mt.tag_value ORDER BY count DESC LIMIT 10", time_params)

                hot_iocs = []
                top_cves = []
                if table_exists(con, 'iocs'):
                    qcol = 'COALESCE(quality,50)' if column_exists(con, 'iocs', 'quality') else '50'
                    hot_iocs = qrows(
                        f"SELECT type,value,times_seen,{qcol} AS quality FROM iocs "
                        "WHERE type NOT IN ('domains','emails','cves','ips') "
                        "AND LOWER(value) NOT IN ('t.me','telegram.me','github.com','check-host.net') "
                        "ORDER BY times_seen DESC, quality DESC LIMIT 12")
                    top_cves = qrows(
                        f"SELECT value,times_seen,{qcol} AS quality FROM iocs WHERE type='cve' "
                        "ORDER BY times_seen DESC, quality DESC LIMIT 10")

                top_channels = []
                if table_exists(con, 'telegram_messages'):
                    tier_select = "COALESCE(tc.source_tier,'unknown')" if (table_exists(con, 'telegram_channels') and column_exists(con, 'telegram_channels', 'source_tier')) else "'unknown'"
                    join_chan = "LEFT JOIN telegram_channels tc ON tc.channel_id=tm.channel_id" if table_exists(con, 'telegram_channels') else ""
                    where_time = "WHERE tm.timestamp>=?" if since else ""
                    top_channels = qrows(
                        f"SELECT tm.channel_name AS name, tm.channel_id AS channel_id, {tier_select} AS source_tier, "
                        "COUNT(*) AS messages, SUM(CASE WHEN tm.has_leak=1 THEN 1 ELSE 0 END) AS leaks, MAX(tm.timestamp) AS last_seen "
                        f"FROM telegram_messages tm {join_chan} {where_time} "
                        "GROUP BY tm.channel_id, tm.channel_name ORDER BY leaks DESC, messages DESC LIMIT 10", time_params)

                recent_rows = []
                if table_exists(con, 'telegram_messages'):
                    where = []
                    params = []
                    if since:
                        where.append('timestamp>=?'); params.append(since)
                    where.append('has_leak=1')
                    w = 'WHERE ' + ' AND '.join(where) if where else ''
                    recent_rows = con.execute(
                        f"SELECT * FROM telegram_messages {w} ORDER BY confidence DESC, timestamp DESC LIMIT 10",
                        params).fetchall()
                    recent_rows = attach_telegram_intel(con, recent_rows)

                self.send_json({
                    "summary": {
                        "messages": total_messages, "processed": processed, "queue": queue,
                        "duplicates": dupes, "iocs": ioc_count, "tags": tag_count
                    },
                    "top_actors": top_actors,
                    "threat_types": threat_types,
                    "top_ttps": top_ttps,
                    "hot_iocs": hot_iocs,
                    "top_cves": top_cves,
                    "top_channels": top_channels,
                    "recent_messages": recent_rows
                })
            except Exception as e:
                self.send_json({"summary":{"messages":0,"processed":0,"queue":0,"duplicates":0,"iocs":0,"tags":0},"error":str(e)})
            finally:
                con.close()


        elif p.path == "/api/purge/csam":
            # Remove any CSAM sites that slipped through filters
            con = db()
            terms = [
                "%pthc%","%ptsc%","%jailbait%","%child porn%","%lolita%",
                "%underage sex%","%child sex%","%kiddie%","%preteen%",
                "%pedo%","%rindexx%","%raped bitch%","%rape kids%",
                "%rape video%","%rape image%","%yvids%","%zoo sex%",
                "%cute girls underage%","%boy love%","%girl love%",
                "%cp video%","%kdv%","%snuff%",
            ]
            removed = 0
            for term in terms:
                r = con.execute(
                    "DELETE FROM sites WHERE LOWER(title) LIKE ? OR LOWER(preview) LIKE ?",
                    (term, term))
                removed += r.rowcount
            con.commit(); con.close()
            self.send_json({"ok":True,"removed":removed})



        elif p.path == "/webhook/canary":
            # Canarytokens webhook — receives alerts when tokens fire
            try:
                length  = int(self.headers.get("Content-Length", 0))
                body    = self.rfile.read(length) if length else b"{}"
                payload = json.loads(body)
            except:
                payload = {}
            con = db()
            try:
                # Extract key fields from canarytokens payload
                token_id    = payload.get("token_id",    payload.get("canarytoken","unknown"))
                token_type  = payload.get("token_type",  "unknown")
                memo        = payload.get("memo",        "")
                src_ip      = payload.get("src_ip",      payload.get("ip","unknown"))
                src_geo     = json.dumps(payload.get("geo",{}))
                useragent   = payload.get("useragent",   "")
                ts          = int(time.time())
                raw         = json.dumps(payload)
                con.execute("""
                    CREATE TABLE IF NOT EXISTS canary_hits (
                        id         INTEGER PRIMARY KEY AUTOINCREMENT,
                        token_id   TEXT,
                        token_type TEXT,
                        memo       TEXT,
                        src_ip     TEXT,
                        geo        TEXT,
                        useragent  TEXT,
                        raw        TEXT,
                        timestamp  INTEGER
                    )""")
                con.execute(
                    "INSERT INTO canary_hits (token_id,token_type,memo,src_ip,geo,useragent,raw,timestamp) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (token_id, token_type, memo, src_ip, src_geo, useragent, raw, ts))
                # Also create an alert hit
                con.execute(
                    "INSERT OR IGNORE INTO alerts (keyword,active,unseen) VALUES (?,1,0) "
                    "ON CONFLICT(keyword) DO NOTHING",
                    (f"[CANARY] {memo}",))
                con.commit()
                log(f"[CANARY HIT] {memo} — IP: {src_ip} type: {token_type}")
            except Exception as e:
                log(f"Canary webhook error: {e}")
            finally:
                con.close()
            self.send_json({"ok": True})

        elif p.path == "/api/canary/hits":
            page     = int(g("page","1")); per=50; offset=(page-1)*per
            con      = db()
            try:
                con.execute("""
                    CREATE TABLE IF NOT EXISTS canary_hits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        token_id TEXT, token_type TEXT, memo TEXT,
                        src_ip TEXT, geo TEXT, useragent TEXT,
                        raw TEXT, timestamp INTEGER
                    )""")
                rows  = con.execute(
                    "SELECT * FROM canary_hits ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (per, offset)).fetchall()
                total = con.execute("SELECT COUNT(*) FROM canary_hits").fetchone()[0]
                self.send_json({"hits":[dict(r) for r in rows],"total":total})
            except:
                self.send_json({"hits":[],"total":0})
            con.close()

        elif p.path == "/api/sites/subpages":
            # Return all subpages for a given host
            host = g("host","")
            if not host: self.send_json([]); return
            con  = db()
            rows = con.execute(
                "SELECT id,url,title,score,trust_score,status,category,bookmarked,preview "
                "FROM sites WHERE host=? AND noise=0 ORDER BY trust_score DESC,score DESC LIMIT 100",
                (host,)).fetchall()
            con.close()
            self.send_json([dict(r) for r in rows])

        elif p.path == "/api/site/delete":
            sid = int(g("id","0"))
            con = db()
            con.execute("DELETE FROM sites WHERE id=?", (sid,))
            con.execute("DELETE FROM recrawl_queue WHERE site_id=?", (sid,))
            con.execute("DELETE FROM file_links WHERE site_id=?", (sid,))
            con.execute("DELETE FROM alert_hits WHERE site_id=? AND site_type='site'", (sid,))
            con.commit(); con.close()
            self.send_json({"ok":True})

        elif p.path == "/api/telegram/mute":
            url = g("url","").strip()
            mute = int(g("mute","1"))
            if not url: self.send_json({"ok":False}); return
            con = db()
            # muted=1 means skip in monitoring, active=0 means excluded
            con.execute("UPDATE telegram_channels SET active=? WHERE url=?", (0 if mute else 1, url))
            con.commit(); con.close()
            self.send_json({"ok":True,"muted":bool(mute)})

        elif p.path == "/api/telegram/muted":
            con = db()
            rows = con.execute(
                "SELECT url,name,channel_type FROM telegram_channels WHERE active=0 ORDER BY name"
            ).fetchall()
            con.close()
            self.send_json([dict(r) for r in rows])

        elif p.path=="/api/leaks/note":
            sid=int(g("id","0")); note=g("note",""); con=db()
            con.execute("UPDATE leaks SET notes=? WHERE id=?",(note,sid))
            con.commit(); con.close(); self.send_json({"ok":True})

        elif p.path == "/api/ransomware/groups":
            import http.client as _hc, ssl as _ssl
            try:
                _key = os.environ.get("RANSOMWARE_LIVE_API_KEY", RANSOMWARE_LIVE_API_KEY)
                _ctx = _ssl.create_default_context()
                _conn = _hc.HTTPSConnection("api-pro.ransomware.live", timeout=20, context=_ctx)
                _conn.request("GET", "/groups", headers={"accept":"application/json","X-Api-Key":_key})
                _resp = _conn.getresponse()
                _body = _resp.read()
                _conn.close()
                self.send_response(_resp.status)
                self.send_header("Content-Type","application/json")
                self.send_header("Access-Control-Allow-Origin","*")
                self.end_headers()
                self.wfile.write(_body)
            except Exception as e:
                self.send_json({"error": str(e)}, 502)

        elif p.path == "/api/ransomware/correlation":
            name = g("name","").strip()
            if not name:
                self.send_json({"error":"missing name"}, 400); return
            con = db()
            try:
                self.send_json(ransomware_telegram_correlation(con, name))
            finally:
                con.close()

        elif p.path == "/api/ransomware/victim_timeline":
            name = g("group","").strip()
            victim = g("victim","").strip()
            domain = g("domain","").strip()
            published = g("published", "0").strip()
            if not victim:
                self.send_json({"error":"missing victim"}, 400); return
            con = db()
            try:
                self.send_json(ransomware_victim_timeline(con, name, victim, domain, published))
            finally:
                con.close()

        elif p.path == "/api/ransomware/group":
            name = g("name","").strip().lower()
            if not name:
                self.send_json({"error":"missing name"}, 400); return
            import http.client as _hc, ssl as _ssl
            try:
                _key = os.environ.get("RANSOMWARE_LIVE_API_KEY", RANSOMWARE_LIVE_API_KEY)
                _ctx = _ssl.create_default_context()
                _conn = _hc.HTTPSConnection("api-pro.ransomware.live", timeout=20, context=_ctx)
                _conn.request("GET", f"/groups/{name}", headers={"accept":"application/json","X-Api-Key":_key})
                _resp = _conn.getresponse()
                _body = _resp.read()
                _conn.close()
                self.send_response(_resp.status)
                self.send_header("Content-Type","application/json")
                self.send_header("Access-Control-Allow-Origin","*")
                self.end_headers()
                self.wfile.write(_body)
            except Exception as e:
                self.send_json({"error": str(e)}, 502)


        else:
            self.send_response(404); self.end_headers()



DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dark Crawler</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  /* Core palette */
  --bg:       #0a0c10;
  --surface:  #0f1218;
  --surface2: #151a22;
  --surface3: #1c2230;
  --border:   #1e2736;
  --border2:  #253044;

  /* Accent */
  --accent:   #3b82f6;
  --accent-lo:#1d3a6e;
  --accent-hi:#60a5fa;
  --green:    #10b981;
  --green-lo: #064e35;
  --red:      #ef4444;
  --red-lo:   #4c1515;
  --amber:    #f59e0b;
  --amber-lo: #4c3200;
  --purple:   #8b5cf6;

  /* Text */
  --text:     #e2e8f0;
  --text-2:   #94a3b8;
  --text-3:   #475569;

  /* Severity */
  --sev-critical: #ef4444;
  --sev-high:     #f59e0b;
  --sev-medium:   #3b82f6;
  --sev-low:      #10b981;

  /* Motion - Emil Kowalski approach */
  --ease-out:    cubic-bezier(0.23, 1, 0.32, 1);
  --ease-in-out: cubic-bezier(0.77, 0, 0.175, 1);
  --ease-drawer: cubic-bezier(0.32, 0.72, 0, 1);

  --nav-w: 220px;
  --header-h: 52px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Inter', sans-serif;
  font-size: 14px;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* ── Scanline overlay ───────────────────────────────────────────────────────── */
body::after {
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(
    0deg, transparent, transparent 2px,
    rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

/* ── Topbar ─────────────────────────────────────────────────────────────────── */
.topbar {
  height: var(--header-h);
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  padding: 0 20px;
  gap: 16px;
  flex-shrink: 0;
  z-index: 50;
}

.logo {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  font-size: 15px;
  letter-spacing: -0.01em;
  color: var(--text);
}

.logo-icon {
  width: 28px;
  height: 28px;
  background: linear-gradient(135deg, var(--accent), var(--purple));
  border-radius: 7px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
}

.topbar-stats {
  display: flex;
  gap: 6px;
  margin-left: auto;
}

.stat-pill {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 12px;
  color: var(--text-2);
  transition: border-color 150ms var(--ease-out);
}

.stat-pill:hover { border-color: var(--border2); }

.stat-pill .val {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  font-weight: 500;
  color: var(--text);
}

.topbar-actions {
  display: flex;
  gap: 6px;
  margin-left: 8px;
}

.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 7px;
  font-size: 12px;
  font-weight: 500;
  font-family: inherit;
  cursor: pointer;
  border: 1px solid var(--border);
  background: var(--surface2);
  color: var(--text-2);
  transition:
    background 150ms var(--ease-out),
    border-color 150ms var(--ease-out),
    color 150ms var(--ease-out),
    transform 100ms var(--ease-out);
}

@media (hover: hover) and (pointer: fine) {
  .btn:hover {
    background: var(--surface3);
    border-color: var(--border2);
    color: var(--text);
  }
  .btn:active { transform: scale(0.97); }
}

.btn.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}

@media (hover: hover) and (pointer: fine) {
  .btn.primary:hover { background: var(--accent-hi); border-color: var(--accent-hi); }
}

.btn.danger {
  background: var(--red-lo);
  border-color: var(--red);
  color: var(--red);
}

.btn.success {
  background: var(--green-lo);
  border-color: var(--green);
  color: var(--green);
}

.btn:disabled { opacity: 0.4; cursor: not-allowed; }

/* ── Status indicator ───────────────────────────────────────────────────────── */
.status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--text-3);
  flex-shrink: 0;
}

.status-dot.running {
  background: var(--green);
  box-shadow: 0 0 8px var(--green);
  animation: pulse 1.5s ease-in-out infinite;
}

.status-dot.finished { background: var(--accent); }

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

/* ── Layout ─────────────────────────────────────────────────────────────────── */
.app-body {
  flex: 1;
  display: flex;
  overflow: hidden;
}

/* ── Left Nav ───────────────────────────────────────────────────────────────── */
.nav {
  width: var(--nav-w);
  background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  overflow-y: auto;
  padding: 8px;
}

.nav-section-label {
  font-size: 10px;
  font-weight: 600;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 12px 8px 4px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 7px;
  cursor: pointer;
  color: var(--text-2);
  font-size: 13px;
  font-weight: 400;
  transition:
    background 120ms var(--ease-out),
    color 120ms var(--ease-out);
  position: relative;
  user-select: none;
}

@media (hover: hover) and (pointer: fine) {
  .nav-item:hover {
    background: var(--surface2);
    color: var(--text);
  }
}

.nav-item.active {
  background: var(--accent-lo);
  color: var(--accent-hi);
  font-weight: 500;
}

.nav-icon {
  font-size: 15px;
  width: 18px;
  text-align: center;
  flex-shrink: 0;
}

.nav-badge {
  margin-left: auto;
  background: var(--red);
  color: #fff;
  font-size: 10px;
  font-weight: 600;
  padding: 1px 5px;
  border-radius: 10px;
  min-width: 18px;
  text-align: center;
}

.nav-badge.blue {
  background: var(--accent);
}

.nav-divider {
  height: 1px;
  background: var(--border);
  margin: 8px 0;
}

/* ── Main content ───────────────────────────────────────────────────────────── */
.main {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-width: 0;
}

/* ── Content toolbar ────────────────────────────────────────────────────────── */
.content-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 20px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  background: var(--surface);
}

.content-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  letter-spacing: -0.01em;
}

.content-subtitle {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--text-3);
  margin-left: 4px;
}

.search-bar {
  position: relative;
  flex: 1;
  max-width: 380px;
}

.search-bar input {
  width: 100%;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text);
  font-family: inherit;
  font-size: 13px;
  padding: 7px 12px 7px 34px;
  outline: none;
  transition:
    border-color 150ms var(--ease-out),
    box-shadow 150ms var(--ease-out);
}

.search-bar input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(59,130,246,0.12);
}

.search-bar::before {
  content: '⌕';
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-3);
  pointer-events: none;
  font-size: 15px;
}

.select {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 7px;
  color: var(--text-2);
  font-family: inherit;
  font-size: 12px;
  padding: 7px 10px;
  outline: none;
  cursor: pointer;
  transition: border-color 150ms var(--ease-out);
}

.select:focus { border-color: var(--accent); }

.result-count {
  margin-left: auto;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--text-3);
  white-space: nowrap;
}

.result-count span { color: var(--accent-hi); }

/* ── Panels ─────────────────────────────────────────────────────────────────── */
.panel {
  flex: 1;
  overflow: hidden;
  display: none;
  flex-direction: column;
}

.panel.active { display: flex; }

.panel-scroll {
  flex: 1;
  overflow-y: auto;
  padding: 16px 20px;
}

/* ── Category sidebar (Browse) ──────────────────────────────────────────────── */
.browse-layout {
  display: flex;
  flex: 1;
  overflow: hidden;
}

.cat-sidebar {
  width: 180px;
  border-right: 1px solid var(--border);
  overflow-y: auto;
  flex-shrink: 0;
  padding: 8px;
}

.cat-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 8px;
  border-radius: 6px;
  cursor: pointer;
  color: var(--text-2);
  font-size: 12px;
  transition: background 100ms var(--ease-out), color 100ms var(--ease-out);
}

@media (hover: hover) and (pointer: fine) {
  .cat-item:hover { background: var(--surface2); color: var(--text); }
}

.cat-item.active {
  background: var(--accent-lo);
  color: var(--accent-hi);
  font-weight: 500;
}

.cat-count {
  margin-left: auto;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--text-3);
}

.cat-item.active .cat-count { color: var(--accent); }

/* ── Top grid ───────────────────────────────────────────────────────────────── */
.top-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 10px;
}

.site-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px;
  cursor: pointer;
  position: relative;
  opacity: 0;
  transform: translateY(6px);
  animation: cardIn 250ms var(--ease-out) forwards;
  transition:
    border-color 150ms var(--ease-out),
    transform 150ms var(--ease-out),
    box-shadow 150ms var(--ease-out);
}

@keyframes cardIn {
  to { opacity: 1; transform: translateY(0); }
}

.site-card:nth-child(1)  { animation-delay: 0ms; }
.site-card:nth-child(2)  { animation-delay: 30ms; }
.site-card:nth-child(3)  { animation-delay: 60ms; }
.site-card:nth-child(4)  { animation-delay: 90ms; }
.site-card:nth-child(5)  { animation-delay: 120ms; }
.site-card:nth-child(6)  { animation-delay: 150ms; }
.site-card:nth-child(n+7){ animation-delay: 180ms; }

@media (hover: hover) and (pointer: fine) {
  .site-card:hover {
    border-color: var(--border2);
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(0,0,0,0.3);
  }
}

.site-card.bookmarked { border-color: var(--amber); }
.site-card.mirror     { border-style: dashed; }

.card-score {
  position: absolute;
  top: 12px;
  right: 12px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  padding: 2px 7px;
  border-radius: 4px;
  background: var(--surface3);
  color: var(--accent-hi);
}

.card-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  margin-bottom: 6px;
  padding-right: 50px;
  line-height: 1.4;
}

.card-url {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--accent);
  margin-bottom: 8px;
  word-break: break-all;
  opacity: 0.8;
}

.card-preview {
  font-size: 12px;
  color: var(--text-2);
  line-height: 1.5;
  margin-bottom: 10px;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.card-footer {
  display: flex;
  align-items: center;
  gap: 6px;
  justify-content: space-between;
}

.category-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: var(--text-3);
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 2px 7px;
}

.card-actions {
  display: flex;
  gap: 4px;
}

.icon-btn {
  width: 26px;
  height: 26px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 5px;
  border: 1px solid var(--border);
  background: transparent;
  cursor: pointer;
  font-size: 12px;
  color: var(--text-3);
  transition:
    background 120ms var(--ease-out),
    border-color 120ms var(--ease-out),
    color 120ms var(--ease-out),
    transform 100ms var(--ease-out);
}

@media (hover: hover) and (pointer: fine) {
  .icon-btn:hover { background: var(--surface3); border-color: var(--border2); color: var(--text); }
  .icon-btn:active { transform: scale(0.93); }
}

.icon-btn.on { border-color: var(--amber); color: var(--amber); }

/* ── Table ──────────────────────────────────────────────────────────────────── */
.data-table { width: 100%; border-collapse: collapse; }

.data-table th {
  text-align: left;
  padding: 9px 14px;
  font-size: 11px;
  font-weight: 600;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.07em;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  position: sticky;
  top: 0;
  z-index: 10;
}

.data-table td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  color: var(--text);
  vertical-align: middle;
}

@media (hover: hover) and (pointer: fine) {
  .data-table tr:hover td { background: var(--surface2); }
}

.td-mono {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--text-3);
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.td-mono a { color: var(--text-3); text-decoration: none; transition: color 120ms; }

@media (hover: hover) and (pointer: fine) {
  .td-mono a:hover { color: var(--text); text-decoration: underline; }
}

.td-dim { color: var(--text-2); font-size: 12px; }
.td-small { font-size: 12px; }

.score-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  padding: 2px 6px;
  border-radius: 4px;
  display: inline-block;
}

.score-hi  { background: var(--green-lo);  color: var(--green); }
.score-mid { background: var(--accent-lo); color: var(--accent-hi); }
.score-lo  { background: var(--surface3);  color: var(--text-3); }

.mirror-chip {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-size: 10px;
  font-family: 'JetBrains Mono', monospace;
  padding: 1px 6px;
  border: 1px solid var(--border2);
  border-radius: 3px;
  color: var(--text-3);
  cursor: pointer;
  margin-left: 6px;
  transition: border-color 120ms, color 120ms;
}

@media (hover: hover) and (pointer: fine) {
  .mirror-chip:hover { border-color: var(--accent); color: var(--accent); }
}

/* ── Severity badges ────────────────────────────────────────────────────────── */
.sev {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.03em;
}

.sev-critical { background: rgba(239,68,68,0.15); color: var(--sev-critical); }
.sev-high     { background: rgba(245,158,11,0.15); color: var(--sev-high); }
.sev-medium   { background: rgba(59,130,246,0.15);  color: var(--sev-medium); }
.sev-low      { background: rgba(16,185,129,0.15);  color: var(--sev-low); }

/* ── Signal chips ───────────────────────────────────────────────────────────── */
.chip {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-size: 10px;
  font-family: 'JetBrains Mono', monospace;
  padding: 2px 6px;
  border-radius: 4px;
  border: 1px solid var(--border);
  color: var(--text-3);
  margin: 1px;
}

.chip-red    { border-color: rgba(239,68,68,0.4);   color: var(--red);   background: rgba(239,68,68,0.08); }
.chip-amber  { border-color: rgba(245,158,11,0.4);  color: var(--amber); background: rgba(245,158,11,0.08); }
.chip-blue   { border-color: rgba(59,130,246,0.4);  color: var(--accent-hi); background: rgba(59,130,246,0.08); }
.chip-green  { border-color: rgba(16,185,129,0.4);  color: var(--green); background: rgba(16,185,129,0.08); }

/* ── Leak event cards (Flare-style) ─────────────────────────────────────────── */
.event-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px 16px;
  margin-bottom: 8px;
  cursor: pointer;
  opacity: 0;
  animation: cardIn 200ms var(--ease-out) forwards;
  transition: border-color 150ms var(--ease-out), box-shadow 150ms var(--ease-out);
}

@media (hover: hover) and (pointer: fine) {
  .event-card:hover {
    border-color: var(--border2);
    box-shadow: 0 4px 16px rgba(0,0,0,0.25);
  }
}

.event-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.event-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  line-height: 1.4;
  flex: 1;
}

.event-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.event-source {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: var(--text-3);
}

.event-time {
  font-size: 11px;
  color: var(--text-3);
}

/* ── Stats cards ────────────────────────────────────────────────────────────── */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 10px;
  margin-bottom: 20px;
}

.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px;
}

.stat-val {
  font-family: 'JetBrains Mono', monospace;
  font-size: 28px;
  font-weight: 500;
  color: var(--text);
  letter-spacing: -0.02em;
  margin-bottom: 4px;
}

.stat-lbl {
  font-size: 11px;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.07em;
  font-weight: 500;
}

.stat-card.accent .stat-val { color: var(--accent-hi); }
.stat-card.green  .stat-val { color: var(--green); }
.stat-card.red    .stat-val { color: var(--red); }
.stat-card.amber  .stat-val { color: var(--amber); }

/* ── Bar chart ──────────────────────────────────────────────────────────────── */
.bar-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 7px;
}

.bar-label {
  font-size: 12px;
  color: var(--text-2);
  width: 170px;
  flex-shrink: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.bar-track {
  flex: 1;
  height: 5px;
  background: var(--surface3);
  border-radius: 3px;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  border-radius: 3px;
  background: linear-gradient(90deg, var(--accent), var(--accent-hi));
  transition: width 600ms var(--ease-out);
}

.bar-num {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--text-3);
  width: 40px;
  text-align: right;
  flex-shrink: 0;
}

/* ── Section title ──────────────────────────────────────────────────────────── */
.section-title {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.09em;
  margin: 20px 0 10px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}

.section-title:first-child { margin-top: 0; }

/* ── Drawer (detail panel) ──────────────────────────────────────────────────── */
#drawer {
  position: fixed;
  right: 0;
  top: var(--header-h);
  bottom: 0;
  width: 380px;
  background: var(--surface);
  border-left: 1px solid var(--border);
  z-index: 100;
  display: flex;
  flex-direction: column;
  transform: translateX(100%);
  transition: transform 280ms var(--ease-drawer);
}

#drawer.open { transform: translateX(0); }

#drawer-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.4);
  z-index: 99;
  opacity: 0;
  pointer-events: none;
  transition: opacity 250ms var(--ease-out);
}

#drawer-overlay.visible {
  opacity: 1;
  pointer-events: auto;
}

.dr-header {
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: flex-start;
  gap: 10px;
}

.dr-title {
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
  flex: 1;
  line-height: 1.4;
}

.dr-close {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-3);
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  font-size: 12px;
  transition: background 120ms, border-color 120ms, color 120ms, transform 100ms;
  flex-shrink: 0;
}

@media (hover: hover) and (pointer: fine) {
  .dr-close:hover { background: var(--surface2); border-color: var(--border2); color: var(--text); }
  .dr-close:active { transform: scale(0.92); }
}

.dr-body {
  flex: 1;
  overflow-y: auto;
  padding: 14px 16px;
}

.dr-url {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--accent);
  margin-bottom: 12px;
  word-break: break-all;
  opacity: 0.85;
}

.dr-url a { color: inherit; text-decoration: none; }
@media (hover: hover) and (pointer: fine) {
  .dr-url a:hover { opacity: 1; text-decoration: underline; }
}

.dr-tags {
  display: flex;
  gap: 5px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}

.dr-tag {
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 4px;
  border: 1px solid var(--border);
  color: var(--text-3);
  font-family: 'JetBrains Mono', monospace;
  opacity: 0;
  animation: tagIn 180ms var(--ease-out) forwards;
}

.dr-tag:nth-child(1) { animation-delay: 40ms; }
.dr-tag:nth-child(2) { animation-delay: 70ms; }
.dr-tag:nth-child(3) { animation-delay: 100ms; }
.dr-tag:nth-child(4) { animation-delay: 130ms; }

@keyframes tagIn {
  from { opacity: 0; transform: translateY(3px); }
  to   { opacity: 1; transform: translateY(0); }
}

.dr-tag.blue   { border-color: rgba(59,130,246,0.5);  color: var(--accent-hi); background: rgba(59,130,246,0.08); }
.dr-tag.green  { border-color: rgba(16,185,129,0.5);  color: var(--green);     background: rgba(16,185,129,0.08); }
.dr-tag.red    { border-color: rgba(239,68,68,0.5);   color: var(--red);       background: rgba(239,68,68,0.08); }
.dr-tag.amber  { border-color: rgba(245,158,11,0.5);  color: var(--amber);     background: rgba(245,158,11,0.08); }

.dr-section-label {
  font-size: 10px;
  font-weight: 600;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.09em;
  margin: 14px 0 6px;
}

.dr-preview {
  font-size: 12px;
  color: var(--text-2);
  line-height: 1.7;
  white-space: pre-wrap;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 7px;
  padding: 10px 12px;
}

.dr-note {
  width: 100%;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 7px;
  color: var(--text);
  font-family: inherit;
  font-size: 12px;
  padding: 10px 12px;
  resize: vertical;
  outline: none;
  min-height: 70px;
  transition: border-color 150ms var(--ease-out), box-shadow 150ms var(--ease-out);
}

.dr-note:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(59,130,246,0.12);
}

.dr-actions {
  display: flex;
  gap: 6px;
  margin-top: 12px;
  flex-wrap: wrap;
}

/* ── Pagination ─────────────────────────────────────────────────────────────── */
.pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 3px;
  padding: 10px;
  border-top: 1px solid var(--border);
  flex-shrink: 0;
  background: var(--surface);
}

.pg {
  height: 30px;
  min-width: 30px;
  padding: 0 8px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-3);
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 120ms, border-color 120ms, color 120ms, transform 80ms;
}

@media (hover: hover) and (pointer: fine) {
  .pg:hover { background: var(--surface2); border-color: var(--border2); color: var(--text); }
  .pg:active { transform: scale(0.95); }
}

.pg.active {
  background: var(--accent-lo);
  border-color: var(--accent);
  color: var(--accent-hi);
}

.pg:disabled { opacity: 0.3; cursor: not-allowed; }
.pg-info { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-3); padding: 0 6px; }

/* ── Toast ──────────────────────────────────────────────────────────────────── */
#toast-container {
  position: fixed;
  bottom: 20px;
  right: 20px;
  z-index: 9000;
  display: flex;
  flex-direction: column;
  gap: 8px;
  pointer-events: none;
}

.toast {
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 8px;
  padding: 10px 14px;
  font-size: 13px;
  color: var(--text);
  box-shadow: 0 4px 20px rgba(0,0,0,0.4);
  display: flex;
  align-items: center;
  gap: 8px;
  pointer-events: auto;
  transform: translateY(8px);
  opacity: 0;
  animation: toastIn 250ms var(--ease-out) forwards;
}

@keyframes toastIn {
  to { transform: translateY(0); opacity: 1; }
}

.toast.out {
  animation: toastOut 200ms var(--ease-out) forwards;
}

@keyframes toastOut {
  to { transform: translateY(4px); opacity: 0; }
}

.toast-icon { font-size: 14px; }
.toast.success { border-color: rgba(16,185,129,0.4); }
.toast.error   { border-color: rgba(239,68,68,0.4); }
.toast.info    { border-color: rgba(59,130,246,0.4); }

/* ── Activity log ───────────────────────────────────────────────────────────── */
.activity-bar {
  border-top: 1px solid var(--border);
  background: var(--surface);
  flex-shrink: 0;
}

.activity-header {
  display: flex;
  align-items: center;
  padding: 4px 14px;
  border-bottom: 1px solid var(--border);
  gap: 8px;
}

.activity-label {
  font-size: 10px;
  font-weight: 600;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.09em;
}

.activity-live {
  font-size: 10px;
  color: var(--green);
  display: none;
  animation: pulse 1.5s infinite;
}

.activity-clear {
  margin-left: auto;
  background: transparent;
  border: none;
  color: var(--text-3);
  font-size: 11px;
  cursor: pointer;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: inherit;
  transition: color 120ms, background 120ms;
}

@media (hover: hover) and (pointer: fine) {
  .activity-clear:hover { color: var(--text); background: var(--surface2); }
}

#log {
  height: 90px;
  overflow-y: auto;
  padding: 4px 14px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--text-3);
}

.ll {
  padding: 1px 0;
  line-height: 1.5;
  animation: llIn 180ms var(--ease-out);
}

@keyframes llIn {
  from { opacity: 0; transform: translateX(-4px); }
  to   { opacity: 1; transform: translateX(0); }
}

.ll.g { color: var(--green); }
.ll.b { color: var(--accent-hi); }
.ll.r { color: var(--red); }
.ll.a { color: var(--amber); }

/* ── Alert row ──────────────────────────────────────────────────────────────── */
.alert-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 8px;
  transition: border-color 150ms;
}

@media (hover: hover) and (pointer: fine) {
  .alert-row:hover { border-color: var(--border2); }
}

/* ── Empty state ────────────────────────────────────────────────────────────── */
.empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  gap: 10px;
  color: var(--text-3);
  font-size: 13px;
}

.empty-icon { font-size: 36px; opacity: 0.3; }

/* ── Filter chips row ───────────────────────────────────────────────────────── */
.filter-row {
  display: flex;
  gap: 6px;
  align-items: center;
  flex-wrap: wrap;
}

.filter-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 5px 10px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-3);
  font-size: 12px;
  font-family: inherit;
  cursor: pointer;
  transition: background 120ms, border-color 120ms, color 120ms, transform 80ms;
}

@media (hover: hover) and (pointer: fine) {
  .filter-btn:hover { background: var(--surface2); border-color: var(--border2); color: var(--text); }
  .filter-btn:active { transform: scale(0.96); }
}

.filter-btn.on {
  background: var(--accent-lo);
  border-color: var(--accent);
  color: var(--accent-hi);
}

/* Telegram sub-tab style — flat underline tabs */
.tg-sub-tab {
  border-radius: 0;
  border-color: transparent;
  background: transparent;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
}
.tg-sub-tab.on {
  background: transparent;
  border-color: transparent;
  border-bottom: 2px solid var(--accent);
  color: var(--accent-hi);
}

/* ── Mirror expand rows ─────────────────────────────────────────────────────── */
.mirror-row td {
  background: rgba(59,130,246,0.04);
  border-left: 2px solid var(--accent);
}

/* ── Scrollbar ──────────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--surface3); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--border2); }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}

/* ── Compatibility classes (referenced by JS render functions) ──────────────── */
.td-url { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-3); max-width: 190px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.td-url a { color: var(--text-3); text-decoration: none; transition: color 120ms; }
.td-url a:hover { color: var(--text); }
.td-title { font-size: 13px; color: var(--text); max-width: 220px; cursor: pointer; }
.td-cat { font-size: 11px; color: var(--text-3); white-space: nowrap; }
.td-score { font-family: 'JetBrains Mono', monospace; font-size: 11px; text-align: center; }
.td-preview { font-size: 12px; color: var(--text-2); max-width: 260px; }
.td-actions { white-space: nowrap; }
.score-hi  { color: var(--green); }
.score-mid { color: var(--accent-hi); }
.score-lo  { color: var(--text-3); }
.row-btn { background: transparent; border: 1px solid var(--border); border-radius: 5px; color: var(--text-3); font-size: 11px; padding: 3px 7px; cursor: pointer; font-family: inherit; transition: background 120ms, border-color 120ms, color 120ms; }
.row-btn:hover { background: var(--surface3); border-color: var(--border2); color: var(--text); }
.row-btn.on { border-color: var(--amber); color: var(--amber); }
.lbadge { display: inline-flex; align-items: center; font-size: 10px; padding: 2px 6px; border: 1px solid var(--border); border-radius: 4px; color: var(--text-3); margin: 1px; }
.new-badge { background: var(--green); color: #000; font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 4px; }
.section-title { font-size: 11px; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.09em; margin: 20px 0 10px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
.section-title:first-child { margin-top: 0; }
.alert-kw { font-family: 'JetBrains Mono', monospace; font-size: 14px; color: var(--accent-hi); flex: 1; }
.alert-hits { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-2); }
.alert-unseen { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--red); }
.hit-row { padding: 10px 14px; border-bottom: 1px solid var(--border); display: flex; gap: 10px; align-items: flex-start; }
.hit-kw { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent-hi); white-space: nowrap; }
.hit-title { font-size: 13px; color: var(--text); flex: 1; }
.hit-url { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-3); }
.hit-type { font-size: 10px; padding: 2px 6px; border: 1px solid; border-radius: 4px; font-family: 'JetBrains Mono', monospace; }
.hit-type.leak { border-color: var(--red); color: var(--red); }
.hit-type.site { border-color: var(--text-3); color: var(--text-3); }
.mirror-group-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 12px; overflow: hidden; }
.mirror-group-header { padding: 12px 16px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; cursor: pointer; background: rgba(59,130,246,0.03); }
.mirror-group-title { font-size: 13px; font-weight: 500; color: var(--text); flex: 1; }
.mirror-count-badge { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent-hi); border: 1px solid var(--accent); border-radius: 4px; padding: 2px 7px; }
.mirror-urls { padding: 8px 16px; }
.mirror-url-row { display: flex; align-items: center; gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--border); }
.mirror-url-row:last-child { border-bottom: none; }
.mirror-url-link { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-3); flex: 1; word-break: break-all; }
.mirror-url-link a { color: inherit; text-decoration: none; }
.mirror-url-link a:hover { color: var(--text); }

/* ── Ransomware cards ───────────────────────────────────────────────────────── */
.rw-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
  cursor: pointer;
  transition:
    border-color 150ms var(--ease-out),
    background   150ms var(--ease-out);
}
@media (hover: hover) and (pointer: fine) {
  .rw-card:hover {
    border-color: var(--red);
    background: var(--surface2);
  }
}


.mini-badge{display:inline-flex;align-items:center;gap:3px;padding:2px 7px;border:1px solid var(--border);border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.02em;background:rgba(255,255,255,.035);color:var(--text-2);}
.mini-badge.intel-actor{border-color:rgba(239,68,68,.45);color:var(--red);}
.mini-badge.intel-threat{border-color:rgba(245,158,11,.45);color:var(--amber);}
.mini-badge.intel-ttp{border-color:rgba(59,130,246,.45);color:var(--accent-hi);}
.mini-badge.intel-ioc{border-color:rgba(34,197,94,.45);color:var(--green);}
.mini-badge.intel-dupe{border-color:rgba(148,163,184,.35);color:var(--text-3);}

</style>
</head>
<body>

<!-- Topbar -->
<header class="topbar">
  <div class="logo">
    <div class="logo-icon">🕷</div>
    Dark Crawler
  </div>

  <div style="display:flex;align-items:center;gap:8px;margin-left:16px;">
    <div class="status-dot idle" id="dot"></div>
    <span id="stText" style="font-size:12px;color:var(--text-3);">Idle</span>
    <span id="actLive" class="activity-live">● LIVE</span>
  </div>

  <div class="topbar-stats">
    <div class="stat-pill">
      <span>Leaks</span>
      <span class="val" id="hLeaks" style="color:var(--red);">—</span>
    </div>
    <div class="stat-pill">
      <span>TG Messages</span>
      <span class="val" id="hTgMsg" style="color:var(--accent-hi);">—</span>
    </div>
    <div class="stat-pill">
      <span>TG Leaks</span>
      <span class="val" id="hTgLeak" style="color:var(--amber);">—</span>
    </div>
    <div id="alertBadge"></div>
    <div id="newBadge"></div>
  </div>

</header>

<!-- App body -->
<div class="app-body">

  <!-- Left nav -->
  <nav class="nav">
    <div class="nav-section-label">Intelligence</div>
    <div class="nav-item" onclick="setTab('leaks')"     id="tab-leaks" class="nav-item active">
      <span class="nav-icon">&#128269;</span> Intel Search
    </div>
    <div class="nav-item" onclick="setTab('telegram')"  id="tab-telegram">
      <span class="nav-icon">&#128241;</span> Telegram
      <span class="nav-badge blue" id="tgBadge" style="display:none">0</span>
    </div>
    <div class="nav-item" onclick="setTab('intel')" id="tab-intel">
      <span class="nav-icon">&#129504;</span> Intel Dashboard
    </div>
    <div class="nav-item" onclick="setTab('ransomware')" id="tab-ransomware">
      <span class="nav-icon">&#9760;&#65039;</span> Ransomware Groups
      <span class="nav-badge" id="rwBadge" style="display:none;background:var(--red);">0</span>
    </div>
    <div class="nav-item" onclick="setTab('canaries')" id="tab-canaries">
      <span class="nav-icon">&#128038;</span> Canary Tokens
    </div>



    <div class="nav-divider"></div>
    <div class="nav-section-label">Management</div>

    <div class="nav-item" onclick="setTab('archiveImport')" id="tab-archiveImport">
      <span class="nav-icon">&#128230;</span> Archive Import
    </div>
    <div class="nav-item" onclick="setTab('alerts')"    id="tab-alerts">
      <span class="nav-icon">&#128276;</span> Alerts
      <span class="nav-badge" id="alertNavBadge" style="display:none">0</span>
    </div>
    <div class="nav-item" onclick="setTab('bookmarks')" id="tab-bookmarks">
      <span class="nav-icon">&#128278;</span> Bookmarks
    </div>
    <div class="nav-item" onclick="setTab('stats')"     id="tab-stats">
      <span class="nav-icon">&#128202;</span> Stats
    </div>
  </nav>

  <!-- Main -->
  <div class="main">

    <!-- LEAKS -->
    <div class="panel active" id="leaksPanel">
      <!-- Mode tab bar -->
      <div style="display:flex;align-items:center;gap:0;border-bottom:1px solid var(--border);flex-shrink:0;padding:0 16px;background:var(--bg-2);">
        <div class="content-title" style="margin-right:20px;white-space:nowrap;font-size:13px;">Intel Search</div>
        <button class="filter-btn tg-sub-tab on" id="isMode-leaks"   onclick="setIntelSearchMode('leaks')"   style="border-radius:0;margin:0;">&#128270; Leaks</button>
        <button class="filter-btn tg-sub-tab"    id="isMode-dump"    onclick="setIntelSearchMode('dump')"    style="border-radius:0;margin:0;">&#9888; Dump Search</button>
        <button class="filter-btn tg-sub-tab"    id="isMode-context" onclick="setIntelSearchMode('context')" style="border-radius:0;margin:0;">&#128203; Context</button>
      </div>
      <!-- Leaks search bar (default) -->
      <div id="isBar-leaks" style="display:flex;align-items:center;gap:8px;padding:8px 16px;border-bottom:1px solid var(--border);flex-shrink:0;">
        <div class="search-bar" style="flex:1;">
          <input type="text" id="leakQ" placeholder="Search Telegram intel, CVEs, targets, domains…" oninput="loadLeaks()">
        </div>
        <select class="select" id="leakSort" onchange="loadLeaks()">
          <option value="confidence">Highest confidence</option>
          <option value="newest">Newest</option>
        </select>
        <button class="filter-btn" id="fEmails"  onclick="toggleLeakFilter('emails')">📧 Emails</button>
        <button class="filter-btn" id="fHashes"  onclick="toggleLeakFilter('hashes')">🔑 Hashes</button>
        <button class="filter-btn" id="fCve"     onclick="toggleLeakFilter('cve')">🐛 CVE</button>
        <button class="filter-btn" id="fMagnet"  onclick="toggleLeakFilter('magnet')">💾 Files</button>
        <button class="filter-btn" id="fSsn"     onclick="toggleLeakFilter('ssn')">🪪 SSN</button>
        <div class="result-count"><span id="leakShown">—</span> / <span id="leakTotal">—</span></div>
      </div>
      <!-- Dump search bar (hidden by default) -->
      <div id="isBar-dump" style="display:none;align-items:center;gap:8px;padding:8px 16px;border-bottom:1px solid var(--border);background:rgba(239,68,68,0.04);flex-shrink:0;">
        <span style="font-size:11px;color:var(--red);font-weight:600;white-space:nowrap;letter-spacing:.05em;">⚠ IMPORTED DUMPS</span>
        <div class="search-bar" style="flex:1;">
          <input type="text" id="personalSearch" placeholder="email, username, SSN, phone, domain…" onkeydown="if(event.key==='Enter')searchPersonal()">
        </div>
        <button class="btn danger" onclick="searchPersonal()">Search Imported Data</button>
      </div>
      <!-- Context search bar (hidden by default) -->
      <div id="isBar-context" style="display:none;align-items:center;gap:8px;padding:8px 16px;border-bottom:1px solid var(--border);background:rgba(59,130,246,0.03);flex-shrink:0;">
        <span style="font-size:11px;color:var(--accent-hi);font-weight:600;white-space:nowrap;letter-spacing:.05em;">CONTEXT</span>
        <div class="search-bar" style="flex:1;">
          <input type="text" id="contextQ" placeholder="company, CVE, username, archive keyword…" onkeydown="if(event.key==='Enter')searchContext()">
        </div>
        <button class="btn" style="border-color:var(--accent);color:var(--accent-hi);" onclick="searchContext()">Search with Context</button>
      </div>
      <!-- Inline results panels for dump + context (hidden when not active) -->
      <div id="isResults-dump"    style="display:none;padding:10px 20px;max-height:260px;overflow-y:auto;flex-shrink:0;border-bottom:1px solid var(--border);font-size:12px;"></div>
      <div id="isResults-context" style="display:none;padding:10px 20px;max-height:260px;overflow-y:auto;flex-shrink:0;border-bottom:1px solid var(--border);"></div>
      <div class="panel-scroll" style="padding:0;" id="leakTableWrap"></div>
      <div id="leakPgEl"></div>
    </div>

    <!-- TELEGRAM -->
    <div class="panel" id="telegramPanel">
      <div class="content-header">
        <div class="content-title">Telegram Monitor</div>
        <div style="display:flex;gap:8px;margin-left:8px;">
          <div class="stat-pill"><span>Channels</span><span class="val" id="tgChannels" style="color:var(--accent-hi);">—</span></div>
          <div class="stat-pill"><span>Messages</span><span class="val" id="tgMessages">—</span></div>
          <div class="stat-pill"><span>Leak Hits</span><span class="val" id="tgLeaks" style="color:var(--red);">—</span></div>
          <div class="stat-pill"><span>Discovered</span><span class="val" id="tgDiscovered" style="color:var(--amber);">—</span></div>
        </div>
        <div class="search-bar" style="margin-left:8px;">
          <input type="text" id="tgQ" placeholder="Search messages…" oninput="loadTelegram()">
        </div>
        <div class="result-count"><span id="tgShown">—</span> / <span id="tgTotal">—</span></div>
      </div>
      <div style="display:flex;border-bottom:1px solid var(--border);flex-shrink:0;padding:0 16px;gap:4px;">
        <button class="filter-btn tg-sub-tab on" onclick="setTgTab('leaks')"    id="tg-tab-leaks">&#128276; Leak Hits</button>
        <button class="filter-btn tg-sub-tab"    onclick="setTgTab('all')"      id="tg-tab-all">&#128172; All Messages</button>
        <button class="filter-btn tg-sub-tab"    onclick="setTgTab('channels')" id="tg-tab-channels">&#128225; Channels</button>
      </div>
      <div id="tgIntelFilters" style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:10px 16px;border-bottom:1px solid var(--border);background:rgba(255,255,255,.015);">
        <select class="select" id="tgActor" onchange="tgPage=1;loadTelegram()"><option value="">All Actors</option></select>
        <select class="select" id="tgThreat" onchange="tgPage=1;loadTelegram()"><option value="">All Threat Types</option></select>
        <select class="select" id="tgTtp" onchange="tgPage=1;loadTelegram()"><option value="">All TTPs</option></select>
        <select class="select" id="tgIoc" onchange="tgPage=1;loadTelegram()"><option value="">All IOC Types</option></select>
        <select class="select" id="tgSourceTier" onchange="tgPage=1;loadTelegram()">
          <option value="">All Sources</option>
          <option value="actor_owned">Actor-owned</option>
          <option value="affiliate">Affiliate</option>
          <option value="broker">Broker</option>
          <option value="intel_source">Intel source</option>
          <option value="news_repost">News/repost</option>
          <option value="random">Random</option>
          <option value="spam">Spam</option>
          <option value="unknown">Unknown</option>
        </select>
        <select class="select" id="tgMinConf" onchange="tgPage=1;loadTelegram()">
          <option value="0">Any Confidence</option>
          <option value="35">35%+</option>
          <option value="50">50%+</option>
          <option value="70">70%+</option>
        </select>
        <select class="select" id="tgDays" onchange="tgPage=1;loadTelegram()">
          <option value="0">All Time</option>
          <option value="1">24h</option>
          <option value="7">7d</option>
          <option value="30">30d</option>
        </select>
        <label style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text-2);white-space:nowrap;">
          <input type="checkbox" id="tgHideDupes" onchange="tgPage=1;loadTelegram()"> Hide duplicates
        </label>
        <button class="filter-btn" onclick="resetTelegramFilters()">Reset</button>
      </div>
      <div class="panel-scroll" style="padding:0;" id="tgTableWrap"></div>
      <div id="tgPgEl"></div>
    </div>

    <!-- INTEL DASHBOARD -->
    <div class="panel" id="intelPanel">
      <div class="content-header">
        <div class="content-title">&#129504; Intel Dashboard</div>
        <div style="display:flex;gap:8px;margin-left:8px;">
          <div class="stat-pill"><span>IOCs</span><span class="val" id="intelIocs" style="color:var(--accent-hi);">—</span></div>
          <div class="stat-pill"><span>Tags</span><span class="val" id="intelTags">—</span></div>
          <div class="stat-pill"><span>Duplicates</span><span class="val" id="intelDupes" style="color:var(--amber);">—</span></div>
          <div class="stat-pill"><span>Queue</span><span class="val" id="intelQueue" style="color:var(--red);">—</span></div>
        </div>
        <select class="select" id="intelDays" onchange="loadIntelDashboard()" style="margin-left:auto;">
          <option value="1">24h</option>
          <option value="7" selected>7d</option>
          <option value="30">30d</option>
          <option value="0">All Time</option>
        </select>
        <button class="filter-btn" onclick="loadIntelDashboard(true)">&#8635; Refresh</button>
      </div>
      <div style="display:flex;gap:8px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--border);background:rgba(255,255,255,.015);flex-wrap:wrap;">
        <button class="filter-btn active" id="intelTabOverview" onclick="showIntelSubTab('overview')">Overview</button>
        <button class="filter-btn" id="intelTabActors" onclick="showIntelSubTab('actors')">Actors &amp; Threats</button>
        <button class="filter-btn" id="intelTabIocs" onclick="showIntelSubTab('iocs')">IOCs &amp; CVEs</button>
        <button class="filter-btn" id="intelTabChannels" onclick="showIntelSubTab('channels')">Channels</button>
        <button class="filter-btn" id="intelTabRecent" onclick="showIntelSubTab('recent')">Recent Messages</button>
      </div>
      <div class="panel-scroll" id="intelDashWrap"></div>
    </div>

        <!-- RANSOMWARE GROUPS -->
    <div class="panel" id="ransomwarePanel">
      <div class="content-header">
        <div class="content-title">&#9760;&#65039; Ransomware Groups</div>
        <div style="display:flex;gap:6px;margin-left:8px;">
          <div class="stat-pill">
            <span>Groups</span>
            <span class="val" id="rwGangCount" style="color:var(--red);">—</span>
          </div>
          <div class="stat-pill">
            <span>Total Victims</span>
            <span class="val" id="rwVictimCount" style="color:var(--amber);">—</span>
          </div>
          <div class="stat-pill">
            <span>Active</span>
            <span class="val" id="rwActiveCount" style="color:var(--green);">—</span>
          </div>
        </div>
        <div class="search-bar" style="margin-left:8px;">
          <input type="text" id="rwQ" placeholder="Search groups…" oninput="filterRansomware()">
        </div>
        <select class="select" id="rwStatus" onchange="filterRansomware()">
          <option value="">All Status</option>
          <option value="Active">Active</option>
          <option value="Inactive">Inactive</option>
          <option value="Unknown">Unknown</option>
        </select>
        <button class="btn" onclick="loadRansomware(true)" style="margin-left:4px;" title="Refresh from API">↻ Refresh</button>
        <div class="result-count"><span id="rwShown">—</span></div>
      </div>
      <div class="panel-scroll" id="rwContent" style="padding:0;position:relative;"></div>
    </div>

<!-- ARCHIVE IMPORT is next -->
    <div class="panel" id="stealerPanel">
      <div class="content-header">
        <div class="content-title">Stealer Logs</div>
        <div style="display:flex;gap:8px;margin-left:8px;">
          <div class="stat-pill"><span>Log Files</span><span class="val" id="stLogs" style="color:var(--accent-hi);">—</span></div>
          <div class="stat-pill"><span>Credentials</span><span class="val" id="stCreds" style="color:var(--red);">—</span></div>
        </div>
        <div style="margin-left:auto;font-size:11px;color:var(--text-3);">Drop files into <code style="color:var(--accent);font-family:JetBrains Mono,monospace;">stealer_logs/</code></div>
      </div>
      <div style="padding:12px 20px;border-bottom:1px solid var(--border);background:rgba(16,185,129,0.03);flex-shrink:0;">
        <div style="font-size:11px;font-weight:600;color:var(--green);text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;">Credential Search</div>
        <div style="display:flex;gap:8px;">
          <div class="search-bar" style="max-width:360px;flex:1;">
            <input type="text" id="stealerQ" placeholder="email, username, domain…" onkeydown="if(event.key==='Enter')searchStealer()">
          </div>
          <button class="btn success" onclick="searchStealer()">Search</button>
        </div>
        <div id="stealerResults" style="margin-top:8px;max-height:220px;overflow-y:auto;"></div>
      </div>
      <div class="panel-scroll">
        <div class="section-title">Recent Log Files</div>
        <div id="stealerLogs"></div>
      </div>
    </div>


    <!-- ARCHIVE IMPORT -->
    <div class="panel" id="archiveImportPanel">
      <div class="content-header">
        <div class="content-title">Archive Import</div>
        <div class="result-count">Downloader → ClamAV → Extract → ClamAV → Import</div>
        <button class="btn" onclick="loadArchiveImport()" style="margin-left:auto;">↻ Refresh</button>
      </div>
      <div style="padding:12px 20px;border-bottom:1px solid var(--border);background:rgba(59,130,246,0.03);flex-shrink:0;">
        <div style="font-size:11px;font-weight:600;color:var(--accent-hi);text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;">Queue New Archive</div>
        <div style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr 140px auto;gap:8px;align-items:end;">
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">Download URL</div>
            <input class="select" style="width:100%;" id="archiveUrl" placeholder="https://example.com/file.zip">
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">Victim</div>
            <input class="select" style="width:100%;" id="archiveVictim" placeholder="victim">
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">Actor</div>
            <input class="select" style="width:100%;" id="archiveActor" placeholder="unknown">
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">Leak Name</div>
            <input class="select" style="width:100%;" id="archiveLeakName" placeholder="source/leak">
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">Type</div>
            <select class="select" style="width:100%;" id="archiveSourceType">
              <option value="archive">archive</option>
              <option value="csv">csv</option>
              <option value="txt">txt</option>
              <option value="json">json</option>
              <option value="sql">sql</option>
            </select>
          </div>
          <button class="btn primary" onclick="queueArchiveImport()">Queue + Start</button>
        </div>
      </div>
      <!-- Upload from PC -->
      <div style="padding:12px 20px;border-bottom:1px solid var(--border);background:rgba(16,185,129,0.03);flex-shrink:0;">
        <div style="font-size:11px;font-weight:600;color:var(--green);text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;">Upload from PC</div>
        <div style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr 140px auto;gap:8px;align-items:end;">
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">File (.zip .tar.gz .txt .csv .sql)</div>
            <input type="file" id="archiveUploadFile" class="select" style="width:100%;padding:3px 8px;cursor:pointer;">
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">Victim</div>
            <input class="select" style="width:100%;" id="archiveUploadVictim" placeholder="victim">
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">Actor</div>
            <input class="select" style="width:100%;" id="archiveUploadActor" placeholder="unknown">
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">Leak Name</div>
            <input class="select" style="width:100%;" id="archiveUploadLeakName" placeholder="auto from filename">
          </div>
          <div>
            <div style="font-size:11px;color:var(--text-3);margin-bottom:4px;">Type</div>
            <select class="select" style="width:100%;" id="archiveUploadSourceType">
              <option value="archive">archive</option>
              <option value="csv">csv</option>
              <option value="txt">txt</option>
              <option value="json">json</option>
              <option value="sql">sql</option>
            </select>
          </div>
          <button class="btn success" onclick="uploadArchiveFile()" id="archiveUploadBtn">Upload + Start</button>
        </div>
        <div id="archiveUploadProgress" style="margin-top:6px;font-size:11px;color:var(--text-3);display:none;"></div>
      </div>
      <div class="panel-scroll" style="padding:0;" id="archiveImportWrap"></div>
    </div>

    <!-- ALERTS -->
    <div class="panel" id="alertsPanel">
      <div class="content-header">
        <div class="content-title">Alerts</div>
        <div class="search-bar" style="max-width:260px;">
          <input type="text" id="alertInput" placeholder="Keyword to watch…" onkeydown="if(event.key==='Enter')addAlert()">
        </div>
        <button class="btn primary" onclick="addAlert()">+ Add Alert</button>
        <button class="btn" onclick="loadAlertHits()" style="margin-left:4px;">View Hits</button>
      </div>
      <div style="flex:1;overflow-y:auto;">
        <div style="padding:16px 20px;" id="alertList"></div>
        <div id="alertHits" style="padding:0 20px 16px;display:none;">
          <div class="section-title">Recent Hits</div>
          <div id="hitList"></div>
        </div>
      </div>
    </div>

    <!-- BOOKMARKS next -->
    <div class="panel" id="languagePanel">
      <div class="content-header"><div class="content-title">Languages</div></div>
      <div class="panel-scroll">
        <div class="section-title">Sites by Detected Language</div>
        <div id="languageList"></div>
      </div>
    </div>



    <!-- BOOKMARKS -->
    <div class="panel" id="bookmarksPanel">
      <div class="content-header">
        <div class="content-title">Bookmarks</div>
        <div class="search-bar">
          <input type="text" id="bmQ" placeholder="Search bookmarks…" oninput="onSearch()">
        </div>
        <div class="result-count"><span id="browseShown2">—</span> bookmarked</div>
      </div>
      <div class="panel-scroll" style="padding:0;" id="bmTableWrap"></div>
      <div id="bmPgEl"></div>
    </div>

    <!-- Activity log -->
    <div class="activity-bar">
      <div class="activity-header">
        <span class="activity-label">Activity Log</span>
        <span class="activity-live" id="liveInd">● Live</span>
        <button class="activity-clear" onclick="document.getElementById('log').innerHTML=''">clear</button>
      </div>
      <div id="log"></div>
    </div>

      <!-- CANARIES -->
      <div class="panel" id="canariesPanel">
        <div class="content-header">
          <div class="content-title">Canary Tokens</div>
          <div style="display:flex;gap:8px;margin-left:8px;">
            <div class="stat-pill"><span>Total Hits</span><span class="val" id="canaryTotal" style="color:var(--amber);">—</span></div>
          </div>
          <div style="margin-left:auto;font-size:11px;color:var(--text-3);">
            Webhook: <code id="webhookUrl" style="color:var(--accent);font-family:JetBrains Mono,monospace;font-size:11px;">loading...</code>
          </div>
        </div>
        <div style="padding:10px 20px;border-bottom:1px solid var(--border);background:rgba(245,158,11,0.03);flex-shrink:0;">
          <div style="font-size:11px;font-weight:600;color:var(--amber);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px;">Setup</div>
          <div style="font-size:12px;color:var(--text-2);line-height:1.8;">
            1. Create tokens at <a href="https://canarytokens.org" target="_blank" style="color:var(--accent);">canarytokens.org</a> &mdash; recommended: DNS, Word, PDF, Web bug<br>
            2. Set webhook URL to the address shown above<br>
            3. Embed tokens in bait files and post to paste sites
          </div>
        </div>
        <div class="panel-scroll" style="padding:0;" id="canaryTableWrap"></div>
        <div id="canaryPgEl"></div>
      </div>

    <!-- STATS -->
    <div class="panel" id="statsPanel">
      <div class="content-header">
        <div class="content-title">Stats</div>
      </div>
      <div class="panel-scroll" style="padding:20px;"></div>
    </div>

  </div><!-- /main -->
</div><!-- /app-body -->

<!-- Drawer overlay -->
<div id="drawer-overlay" onclick="closeDrawer()"></div>

<!-- Detail drawer -->
<div id="drawer">
  <div class="dr-header">
    <div class="dr-title" id="drTitle">—</div>
    <button class="dr-close" onclick="closeDrawer()">✕</button>
  </div>
  <div class="dr-body">
    <div class="dr-url" id="drUrl"></div>
    <div class="dr-tags" id="drMeta"></div>
    <div class="dr-section-label">Preview</div>
    <div class="dr-preview" id="drPreview"></div>
    <div class="dr-section-label">Notes</div>
    <textarea class="dr-note" id="drNote" placeholder="Add research notes…"></textarea>
    <div class="dr-actions">
      <button class="btn primary" onclick="saveNote()">Save Note</button>
      <button class="btn" id="drBm" onclick="toggleDrawerBm()">🔖 Bookmark</button>
      <button class="btn" id="drRv" onclick="toggleDrawerRv()">✓ Reviewed</button>
      <button class="btn" id="drDelBtn" onclick="deleteSite()" style="border-color:var(--red);color:var(--red);margin-top:8px;width:100%;">🗑 Delete Site</button>
    </div>
  </div>
</div>

<!-- Toast container -->
<div id="toast-container"></div>




<script>

















// ESC closes drawer
document.addEventListener('keydown', e=>{
  if(e.key==='Escape') closeDrawer();
});

// ── Toast notifications ───────────────────────────────────────────────────────
function toast(msg, type='info', duration=2500){
  const icons = {success:'✓', error:'✕', info:'ℹ'};
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-icon">${icons[type]||'ℹ'}</span>${esc(msg)}`;
  container.appendChild(el);
  setTimeout(()=>{
    el.classList.add('out');
    setTimeout(()=>el.remove(), 220);
  }, duration);
}


const ICONS={
  "Search Engines":"🔍","Wikis & Directories":"📖","Forums":"💬",
  "News & Media":"📰","Chat & Messaging":"💭","Email":"✉️",
  "Blogs":"✍️","Markets":"🛒","Technology":"⚙️","Privacy Tools":"🔒",
  "Libraries":"📚","Whistleblower":"📡","Finance & Crypto":"₿",
  "Hosting":"🖥️","Uncategorized":"❓"
};

let currentTab='top', activeCat='all', currentPage=1, totalItems=0;
let pollTimer=null, drawerSite=null, searchTimer=null;
let groupByHost=true, expandedHosts=new Set();
let leakPage=1, leakTotal=0, leakFilters=new Set();
const PER_PAGE=50;

// ── Intel Search mode switcher ────────────────────────────────────────────────
let _intelSearchMode = 'leaks';
function setIntelSearchMode(mode){
  _intelSearchMode = mode;
  ['leaks','dump','context'].forEach(m=>{
    const btn = document.getElementById('isMode-'+m);
    const bar = document.getElementById('isBar-'+m);
    const res = document.getElementById('isResults-'+m);
    if(btn){ btn.classList.toggle('on', m===mode); }
    if(bar){ bar.style.display = m===mode ? 'flex' : 'none'; }
    if(res){ res.style.display = 'none'; } // reset results on mode switch
  });
  // show/hide the leaks table
  const leakWrap = document.getElementById('leakTableWrap');
  const leakPg   = document.getElementById('leakPgEl');
  if(leakWrap) leakWrap.style.display = mode==='leaks' ? '' : 'none';
  if(leakPg)   leakPg.style.display   = mode==='leaks' ? '' : 'none';
  if(mode==='leaks'){ leakPage=1; loadLeaks(); }
  else if(mode==='dump')    document.getElementById('personalSearch')?.focus();
  else if(mode==='context') document.getElementById('contextQ')?.focus();
}
const _siteCache={}, _leakCache={};

// Tab data cache — avoid re-fetching unchanged data
const _tabCache={};
let _lastSiteCount=0;
let _activitySince=0;
let _pollInterval=3000;  // starts at 3s, slows to 15s when idle

function esc(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function jsEsc(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"').replace(/\n/g,' ');}
function ts(){return`[${new Date().toLocaleTimeString()}] `;}

// ── Tab ────────────────────────────────────────────────────────────────────────
async function setTab(tab){
  currentTab=tab; currentPage=1; activeCat='all';

  // Update nav items
  document.querySelectorAll('.nav-item').forEach(t=>t.classList.remove('active'));
  const navEl = document.getElementById('tab-'+tab);
  if(navEl) navEl.classList.add('active');

  // Hide all panels
  const panels = ['topPanel','browsePanel','mirrorsPanel','leaksPanel','alertsPanel',
      'filesPanel','recrawlPanel','languagePanel',
      'telegramPanel','intelPanel','pastesPanel','stealerPanel','ransomwarePanel','archiveImportPanel','bookmarksPanel','noisePanel','canariesPanel'];
  panels.forEach(id=>{ const el=document.getElementById(id); if(el){ el.classList.remove('active'); }});

  const showPanel = (id) => { const el=document.getElementById(id); if(el) el.classList.add('active'); };

  if(tab==='top')        { showPanel('topPanel');       loadTop(); }
  else if(tab==='browse')    { showPanel('browsePanel');    buildCatList(); load(); }
  else if(tab==='bookmarks') { showPanel('bookmarksPanel'); load(); }
  else if(tab==='noise')     { showPanel('noisePanel');     load(); }
  else if(tab==='mirrors')   { showPanel('mirrorsPanel');   loadMirrors(); }
  else if(tab==='leaks')     { showPanel('leaksPanel');     leakPage=1; loadLeaks(); }
  else if(tab==='archiveImport') { showPanel('archiveImportPanel'); loadArchiveImport(); }
  else if(tab==='alerts')    { showPanel('alertsPanel');    loadAlerts(); }
  else if(tab==='files')     { showPanel('filesPanel');     loadFiles(); }
  else if(tab==='recrawl')   { showPanel('recrawlPanel');   loadRecrawl(); }
  else if(tab==='language')  { showPanel('languagePanel');  loadLanguages(); }
  else if(tab==='pastes')    { showPanel('pastesPanel');    loadPastes(); }
  else if(tab==='stealer')   { showPanel('stealerPanel');   loadStealerStats(); }
  else if(tab==='telegram')  { showPanel('telegramPanel');  loadTelegramStats(); loadTelegram(); }
  else if(tab==='intel')     { showPanel('intelPanel');     loadIntelDashboard(); }
  else if(tab==='canaries')    { showPanel('canariesPanel');   loadCanaries(); }
  else if(tab==='ransomware')  { showPanel('ransomwarePanel'); loadRansomware(); }
  else if(tab==='stats')       { showPanel('statsPanel');      loadStats(); }
  else if(tab==='network')     { showPanel('networkPanel');    loadNetwork(); }
}

// ── Load ───────────────────────────────────────────────────────────────────────
async function load(){
  const tab  = currentTab;
  const q    = document.getElementById(tab==='bookmarks'?'bmQ':tab==='noise'?'noiseQ':'q')?.value||'';
  const sort = document.getElementById('sortSel')?.value||'trust';
  const view = tab==='bookmarks'?'bookmarked':tab==='noise'?'noise':'clean';
  const params = new URLSearchParams({q,sort,view,page:currentPage,
    cat:activeCat==='all'?'':activeCat,group:groupByHost?1:0});
  const res = await fetch('/api/sites?'+params).then(r=>r.json()).catch(()=>null);
  if(!res) return;
  res.sites.forEach(s=>_siteCache[s.id]=s);
  totalItems = res.total;
  const shownEl  = document.getElementById('browseShown');
  const totalEl  = document.getElementById('totalShown');
  const shownEl2 = document.getElementById('browseShown2');
  if(shownEl)  shownEl.textContent  = res.sites.length.toLocaleString();
  if(totalEl)  totalEl.textContent  = res.total.toLocaleString();
  if(shownEl2) shownEl2.textContent = res.total.toLocaleString();
  buildCatList(res.cats);
  renderTable(res.sites);
  renderPagination(res.total);
}

async function loadTop(){}

function onSearch(){clearTimeout(searchTimer);searchTimer=setTimeout(()=>{currentPage=1;load();},300);}

// ── Top grid ───────────────────────────────────────────────────────────────────
function renderTopGrid(sites){
  const el=document.getElementById('topGrid');
  if(!el) return;
  if(!sites.length){
    el.innerHTML='<div class="empty"><div class="empty-icon">⭐</div>Start a crawl to discover sites</div>';
    return;
  }
  el.innerHTML='<div class="top-grid">'+sites.map(s=>{
    const title=esc(s.title||'[no title]');
    const url=esc(s.url||'');
    const prev=esc((s.preview||'').substring(0,120));
    const cat=s.category||'Uncategorized';
    const isMirror=!!s.mirror_group;
    const trust=s.trust_score||s.score||0;
    return`<div class="site-card ${s.bookmarked?'bookmarked':''} ${isMirror?'mirror':''}" onclick="openDrawer(${s.id})">
      <div class="card-score">${trust>=0?'+':''}${trust}</div>
      <div class="card-title">${title}${isMirror?'<span class="mirror-chip">🔁 mirror</span>':''}</div>
      <div class="card-url">${url}</div>
      <div class="card-preview">${prev}</div>
      <div class="card-footer">
        <div class="category-badge">${ICONS[cat]||'🌐'} ${cat}</div>
        <div class="card-actions" onclick="event.stopPropagation()">
          <button class="icon-btn ${s.bookmarked?'on':''}" onclick="toggleBm(${s.id},this)" title="Bookmark">🔖</button>
          <a href="${url}" target="_blank" onclick="event.stopPropagation()"><button class="icon-btn" title="Open">↗</button></a>
        </div>
      </div>
    </div>`;
  }).join('')+'</div>';
}

// ── Table ──────────────────────────────────────────────────────────────────────
let expandedMirrors = new Set();

async function toggleGrouping(){
  groupByHost=!groupByHost; expandedHosts.clear(); currentPage=1;
  const btn=document.getElementById("groupToggle");
  if(btn){btn.classList.toggle("on",groupByHost);btn.textContent=groupByHost?"⊞ Grouped":"≡ Flat";}
  load();
}

async function loadSubpages(host, btn){
  const hk=(host||"").replace(/[^a-zA-Z0-9]/g,"_");
  const row=document.getElementById("sub_"+hk);
  const td=row?row.querySelector("td"):null;
  if(!row||!td) return;
  if(expandedHosts.has(host)){
    expandedHosts.delete(host);
    row.style.display="none";
    if(btn){btn.textContent="▶ "+(btn.dataset.count||"?")+" more"; btn.classList.remove("chip-amber"); btn.classList.add("chip-blue");}
    return;
  }
  expandedHosts.add(host);
  if(btn) btn.textContent="loading...";
  const res=await fetch("/api/sites/subpages?host="+encodeURIComponent(host)).then(r=>r.json()).catch(()=>[]);
  row.style.display="";
  if(btn){btn.textContent="▼ collapse"; btn.classList.remove("chip-blue"); btn.classList.add("chip-amber");}
  if(!res.length){td.innerHTML='<div style="padding:8px 28px;font-size:12px;color:var(--text-3);">No subpages found</div>';return;}
  td.innerHTML='<table style="width:100%;">'+res.map(s=>{
    const sc=s.score>=15?"score-hi":s.score>=5?"score-mid":"score-lo";
    const path=esc((s.url||"").replace(/^https?:\/\/[^/]+/,"").substring(0,60)||"/");
    return`<tr class="mirror-row">
      <td class="td-url" style="padding-left:32px;">
        <a href="${esc(s.url||"")}" target="_blank">${path}</a>
      </td>
      <td class="td-title" onclick="openDrawer(${s.id})" style="cursor:pointer;">${esc(s.title||"")}</td>
      <td class="td-cat">${ICONS[s.category||""]||"🌐"} ${esc(s.category||"")}</td>
      <td class="td-score ${sc}">${s.score>=0?"+":""}${s.score}</td>
      <td class="td-preview">${esc((s.preview||"").substring(0,80))}</td>
      <td class="td-actions"><button class="row-btn" onclick="openDrawer(${s.id})">…</button></td>
    </tr>`;
  }).join("")+'</table>';
}

function renderTable(sites){
  const wrap=document.getElementById('tableWrap');
  if(!sites.length){wrap.innerHTML='<div class="empty"><div class="empty-icon">🔍</div>No results</div>';document.getElementById('pgEl').innerHTML='';return;}
  let html='';
  for(const s of sites){
    const sc=s.score>=15?'score-hi':s.score>=5?'score-mid':'score-lo';
    const url=esc(s.url||'');
    const title=esc(s.title||'[no title]');
    const prev=esc((s.preview||'').substring(0,90));
    const cat=s.category||'Uncategorized';
    const mc=s.mirror_count||0;
    const hasMirrors=mc>1;
    const isExpanded=expandedMirrors.has(s.mirror_group);

    // Mirror expand button
    const mirrorBtn=hasMirrors
      ? `<span class="mirror-tag" style="cursor:pointer;border-color:var(--accent2);color:var(--accent2);"
           onclick="event.stopPropagation();toggleMirrorExpand('${s.mirror_group}',${s.id})"
           title="Click to see all ${mc} mirror URLs">
           🔁 ${mc} mirrors ${isExpanded?'▴':'▾'}
         </span>`
      : '';

        const subCount=s.subpage_count||1;
    const hk=(s.host||"").replace(/[^a-zA-Z0-9]/g,"_");
    let subBtn="";
    if(groupByHost&&subCount>1){
      subBtn='<span class="chip chip-blue" style="cursor:pointer;margin-left:6px;" '+
             'id="subbtn_'+hk+'" '+
             'onclick="event.stopPropagation();loadSubpages(\''+esc(s.host||"")+'\',this)" '+
             'data-count="'+( subCount-1 )+'">'+
             ("▶ "+(subCount-1)+" more")+
             '</span>';
    }
html+=`<tr>
      <td class="td-url"><a href="${url}" target="_blank">${url}</a></td>
      <td class="td-title" style="cursor:pointer" onclick="openDrawer(${s.id})">${title} ${mirrorBtn}${subBtn||''}</td>
      <td class="td-cat">${ICONS[cat]||'🌐'} ${cat}</td>
      <td class="td-score ${sc}">${s.score>=0?'+':''}${s.score}</td>
      <td class="td-preview">${prev}</td>
      <td class="td-actions">
        <button class="row-btn ${s.bookmarked?'on':''}" onclick="toggleBm(${s.id},this)">🔖</button>
        <button class="row-btn" onclick="openDrawer(${s.id})">…</button>
      </td>
    </tr>`;
    html+=`<tr id="sub_${hk}" style="display:none;"><td colspan="6" style="padding:0;background:rgba(59,130,246,0.03);"></td></tr>`;

    // Expanded mirror rows
    if(hasMirrors && isExpanded && _mirrorCache[s.mirror_group]){
      for(const murl of _mirrorCache[s.mirror_group]){
        if(murl===s.url)continue;
        html+=`<tr style="background:rgba(0,200,255,.03);">
          <td class="td-url" style="padding-left:24px;border-left:2px solid var(--accent2);">
            <a href="${esc(murl)}" target="_blank">${esc(murl)}</a>
          </td>
          <td colspan="4" style="font-family:Share Tech Mono,monospace;font-size:.62rem;color:var(--dim);">
            ↳ mirror of "${esc(s.title||'')}"
          </td>
          <td></td>
        </tr>`;
      }
    }
  }
  // Target correct wrap based on current tab
  const wrapEl = wrap || document.getElementById('tableWrap');
  if(wrapEl) wrapEl.innerHTML=`<table class="data-table"><thead><tr><th>URL</th><th>Title</th><th>Category</th><th>Score</th><th>Preview</th><th></th></tr></thead><tbody>${html}</tbody></table>`;
}

const _mirrorCache={};

async function toggleMirrorExpand(group, primaryId){
  if(expandedMirrors.has(group)){
    expandedMirrors.delete(group);
  } else {
    expandedMirrors.add(group);
    // Fetch mirror URLs if not cached
    if(!_mirrorCache[group]){
      const res=await fetch('/api/mirrors').then(r=>r.json()).catch(()=>[]);
      for(const g of res){
        _mirrorCache[g.mirror_group]=g.urls;
      }
    }
  }
  // Re-render current page
  load();
}

function renderPagination(total){
  const pages=Math.ceil(total/PER_PAGE);
  const el=document.getElementById('pgEl');
  if(pages<=1){el.innerHTML='';return;}
  let b=`<button class="pg" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>← prev</button>`;
  let s=Math.max(1,currentPage-3),e=Math.min(pages,s+6);
  if(s>1)b+=`<button class="pg" onclick="goPage(1)">1</button><span class="pg-info">…</span>`;
  for(let i=s;i<=e;i++)b+=`<button class="pg ${i===currentPage?'active':''}" onclick="goPage(${i})">${i}</button>`;
  if(e<pages)b+=`<span class="pg-info">…</span><button class="pg" onclick="goPage(${pages})">${pages}</button>`;
  b+=`<button class="pg" onclick="goPage(${currentPage+1})" ${currentPage===pages?'disabled':''}>next →</button>`;
  b+=`<span class="pg-info">page ${currentPage} of ${pages}</span>`;
  el.innerHTML=`<div class="pagination">${b}</div>`;
}

async function goPage(p){
  const pages=Math.ceil(totalItems/PER_PAGE);
  if(p<1||p>pages)return;
  currentPage=p;load();
  document.getElementById('tableWrap').scrollTo({top:0,behavior:'smooth'});
}

// ── Category sidebar ───────────────────────────────────────────────────────────
async function buildCatList(){
  if(currentTab!=='browse')return;
  const cats=await fetch('/api/categories').then(r=>r.json()).catch(()=>[]);
  const total=cats.reduce((a,c)=>a+c.count,0);
  const el=document.getElementById('catList');
  el.innerHTML='';
  const all=document.createElement('div');
  all.className='cat-item'+(activeCat==='all'?' active':'');
  all.innerHTML=`<span class="cat-icon">🌐</span><span class="cat-name">All Sites</span><span class="cat-count">${total.toLocaleString()}</span>`;
  all.onclick=()=>{activeCat='all';currentPage=1;buildCatList();load();};
  el.appendChild(all);
  for(const c of cats){
    const d=document.createElement('div');
    d.className='cat-item'+(activeCat===c.category?' active':'');
    d.innerHTML=`<span class="cat-icon">${ICONS[c.category]||'🌐'}</span><span class="cat-name">${esc(c.category)}</span><span class="cat-count">${c.count.toLocaleString()}</span>`;
    d.onclick=()=>{activeCat=c.category;currentPage=1;buildCatList();load();};
    el.appendChild(d);
  }
}

// ── Mirrors ────────────────────────────────────────────────────────────────────
async function loadMirrors(){
  const el=document.getElementById('mirrorsPanel');
  el.innerHTML='<div class="empty"><div class="empty-icon">⏳</div>Loading mirror groups…</div>';
  const groups=await fetch('/api/mirrors').then(r=>r.json()).catch(()=>[]);
  if(!groups.length){el.innerHTML='<div class="empty"><div class="empty-icon">🔁</div>No mirror groups detected yet</div>';return;}
  el.innerHTML=groups.map(g=>`
    <div class="mirror-group-card">
      <div class="mirror-group-header">
        <div class="mirror-group-title">${esc(g.title)}</div>
        <div class="mirror-count-badge">${g.count} mirrors</div>
        <div style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:var(--accent);margin-left:8px;">+${g.score}</div>
      </div>
      <div class="mirror-urls">
        ${g.urls.map((url,i)=>`
          <div class="mirror-url-row">
            <div class="mirror-url-link"><a href="${esc(url)}" target="_blank">${esc(url)}</a></div>
            ${i===0?'<span style="font-family:\'Share Tech Mono\',monospace;font-size:.6rem;color:var(--accent);padding:1px 5px;border:1px solid var(--accent);">primary</span>':''}
          </div>`).join('')}
      </div>
    </div>`).join('');
}

// ── Leaks ──────────────────────────────────────────────────────────────────────
async function loadLeaks(){
  const q=document.getElementById('leakQ').value;
  const sort=document.getElementById('leakSort').value;
  const params=new URLSearchParams({q,sort,page:leakPage});
  const res=await fetch('/api/leaks?'+params).then(r=>r.json()).catch(()=>null);
  if(!res)return;
  res.leaks.forEach(l=>_leakCache[l.id]=l);
  let leaks=res.leaks;
  if(leakFilters.has('emails')) leaks=leaks.filter(l=>l.has_emails);
  if(leakFilters.has('hashes')) leaks=leaks.filter(l=>l.has_hashes);
  if(leakFilters.has('cve'))    leaks=leaks.filter(l=>JSON.parse(l.cves||'[]').length>0);
  if(leakFilters.has('magnet')) leaks=leaks.filter(l=>l.has_magnet);
  if(leakFilters.has('ssn'))    leaks=leaks.filter(l=>l.has_ssn);
  leakTotal=res.total;
  document.getElementById('leakShown').textContent=leaks.length.toLocaleString();
  document.getElementById('leakTotal').textContent=res.total.toLocaleString();
  renderLeakTable(leaks,res.total);
}

function toggleLeakFilter(f){
  const ids={emails:'fEmails',hashes:'fHashes',cve:'fCve',magnet:'fMagnet',ssn:'fSsn'};
  if(leakFilters.has(f))leakFilters.delete(f);
  else leakFilters.add(f);
  document.getElementById(ids[f]).classList.toggle('primary');
  leakPage=1;loadLeaks();
}

function renderLeakTable(leaks,total){
  const wrap=document.getElementById('leakTableWrap');
  const pgEl=document.getElementById('leakPgEl');
  if(!leaks.length){wrap.innerHTML='<div class="empty"><div class="empty-icon">🔔</div>No leaks found yet</div>';pgEl.innerHTML='';return;}
  const rows=leaks.map(l=>{
    const title=esc(l.title||'[no title]');
    const url=esc(l.url||'');
    const cves=JSON.parse(l.cves||'[]');
    const targets=JSON.parse(l.breach_targets||'[]');
    const records=JSON.parse(l.record_counts||'[]');
    const etypes=JSON.parse(l.exploit_types||'[]');
    const cc=l.confidence>=70?'color:var(--danger)':l.confidence>=45?'color:var(--warn)':'color:var(--accent2)';
    let badges='';
    if(l.has_emails)badges+='<span class="lbadge">📧</span>';
    if(l.has_hashes)badges+='<span class="lbadge">🔑</span>';
    if(l.has_ssn)badges+='<span class="lbadge" style="border-color:var(--danger);color:var(--danger)">🪪</span>';
    if(l.has_magnet)badges+='<span class="lbadge">💾</span>';
    if(cves.length)badges+=cves.map(c=>`<span class="lbadge" style="border-color:var(--warn);color:var(--warn)">${esc(c)}</span>`).join('');
    if(etypes.length)badges+=etypes.map(e=>`<span class="lbadge" style="border-color:var(--accent2);color:var(--accent2)">${esc(e)}</span>`).join('');
    const tgt=targets.length?`<div style="font-size:.62rem;color:var(--text);margin-top:2px;">🎯 ${targets.map(esc).join(', ')}</div>`:'';
    const rec=records.length?`<div style="font-size:.62rem;color:var(--dim);">📊 ${records.map(esc).join(' · ')}</div>`:'';
    return`<tr>
      <td class="td-url"><a href="${url}" target="_blank">${url}</a></td>
      <td class="td-title" style="cursor:pointer" onclick="openLeakDrawer(${l.id})">${title}${tgt}${rec}</td>
      <td style="font-family:Share Tech Mono,monospace;font-size:.7rem;font-weight:bold;${cc};text-align:center;">${l.confidence}%</td>
      <td>${badges}</td>
      <td class="td-actions">
        <button class="row-btn ${l.bookmarked?'on':''}" onclick="toggleLeakBm(${l.id},this)">🔖</button>
        <button class="row-btn" onclick="openLeakDrawer(${l.id})">…</button>
      </td>
    </tr>`;
  }).join('');
  wrap.innerHTML=`<table class="data-table"><thead><tr><th>URL</th><th>Title / Target</th><th>Confidence</th><th>Signals</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  const pages=Math.ceil(total/50);
  if(pages>1){
    let b=`<button class="pg" onclick="goLeakPage(${leakPage-1})" ${leakPage===1?'disabled':''}>← prev</button>`;
    let s=Math.max(1,leakPage-3),e=Math.min(pages,s+6);
    if(s>1)b+=`<button class="pg" onclick="goLeakPage(1)">1</button><span class="pg-info">…</span>`;
    for(let i=s;i<=e;i++)b+=`<button class="pg ${i===leakPage?'active':''}" onclick="goLeakPage(${i})">${i}</button>`;
    if(e<pages)b+=`<span class="pg-info">…</span><button class="pg" onclick="goLeakPage(${pages})">${pages}</button>`;
    b+=`<button class="pg" onclick="goLeakPage(${leakPage+1})" ${leakPage===pages?'disabled':''}>next →</button>`;
    pgEl.innerHTML=`<div class="pagination">${b}</div>`;
  }else{pgEl.innerHTML='';}
}

async function goLeakPage(p){const pages=Math.ceil(leakTotal/50);if(p<1||p>pages)return;leakPage=p;loadLeaks();document.getElementById('leakTableWrap').scrollTo({top:0,behavior:'smooth'});}

async function toggleLeakBm(id,btn){
  const isOn=btn.classList.contains('on');
  await fetch(`/api/leaks/bookmark?id=${id}&val=${isOn?0:1}`);
  btn.classList.toggle('on');
  if(_leakCache[id])_leakCache[id].bookmarked=isOn?0:1;
}

async function searchPersonal(){
  const term=document.getElementById('personalSearch').value.trim();
  if(!term||term.length<3)return;
  const el=document.getElementById('isResults-dump');
  el.style.display='block';
  el.innerHTML='<span style="color:var(--accent)">Searching imported dumps, leaks, and Telegram…</span>';
  const res=await fetch(`/api/intel/search?term=${encodeURIComponent(term)}`).then(r=>r.json()).catch(()=>null);
  if(!res){el.innerHTML='Search failed.';return;}
  if(!res.total){
    el.innerHTML=`<span style="color:var(--accent)">✓ No matches found for "${esc(term)}"</span>`;return;
  }
  const exposureRows=(res.exposures||[]).slice(0,25).map(r=>`<div style="margin-top:4px;padding:4px 8px;border-left:2px solid var(--red);">
      <span style="color:var(--text)">${esc(r.value||'')}</span>
      <span class="chip chip-red">${esc(r.entity_type||'entity')}</span>
      <span style="color:var(--text-3);margin-left:8px;">seen ${(r.times_seen||1).toLocaleString()}x</span>
    </div>`).join('');
  const leakRows=(res.leaks||[]).slice(0,10).map(r=>`<div style="margin-top:4px;padding:4px 8px;border-left:2px solid var(--amber);">
      <span style="color:var(--text)">${esc(r.title||'')}</span>
      <span style="color:var(--text-3);margin-left:8px;font-family:JetBrains Mono,monospace;font-size:11px;">${esc(r.url||'')}</span>
      <span style="color:var(--amber);margin-left:8px;">${r.confidence||0}%</span>
    </div>`).join('');
  const tgRows=(res.telegram||[]).slice(0,10).map(r=>`<div style="margin-top:4px;padding:4px 8px;border-left:2px solid var(--accent);">
      <span style="color:var(--accent-hi)">Telegram: ${esc(r.channel_name||'unknown')}</span>
      <span style="color:var(--text-2);margin-left:8px;">${esc((r.text||'').substring(0,160))}</span>
    </div>`).join('');
  el.innerHTML=`<span style="color:var(--red)">⚠ Found ${res.total.toLocaleString()} match(es)</span>`+
    (exposureRows?`<div style="margin-top:6px;color:var(--text-3);font-size:11px;">Imported dump entities</div>${exposureRows}`:'')+
    (leakRows?`<div style="margin-top:6px;color:var(--text-3);font-size:11px;">Leak pages</div>${leakRows}`:'')+
    (tgRows?`<div style="margin-top:6px;color:var(--text-3);font-size:11px;">Telegram</div>${tgRows}`:'');
}


// ── Archive Import ─────────────────────────────────────────────────────────────
async function queueArchiveImport(){
  const download_url = document.getElementById('archiveUrl').value.trim();
  if(!download_url){ toast('Download URL is required', 'error'); return; }

  const params = new URLSearchParams({
    download_url,
    victim_name: document.getElementById('archiveVictim').value.trim(),
    actor: document.getElementById('archiveActor').value.trim() || 'unknown',
    leak_name: document.getElementById('archiveLeakName').value.trim(),
    source_type: document.getElementById('archiveSourceType').value
  });

  const res = await fetch('/api/archive_import/create?' + params).then(r=>r.json()).catch(e=>({ok:false, reason:String(e)}));
  if(res.ok){
    toast('Archive job queued: #' + res.job_id, 'success');
    document.getElementById('archiveUrl').value='';
    loadArchiveImport();
  } else {
    toast(res.reason || 'Archive queue failed', 'error', 4500);
    loadArchiveImport();
  }
}

async function rerunArchiveJob(id){
  const res = await fetch('/api/archive_import/run?id=' + encodeURIComponent(id)).then(r=>r.json()).catch(e=>({ok:false, reason:String(e)}));
  if(res.ok) toast('Archive job restarted: #' + id, 'success');
  else toast(res.reason || 'Restart failed', 'error', 4500);
  loadArchiveImport();
}

async function uploadArchiveFile(){
  const fileInput = document.getElementById('archiveUploadFile');
  if(!fileInput.files.length){ toast('Select a file first', 'error'); return; }
  const file = fileInput.files[0];
  const prog = document.getElementById('archiveUploadProgress');
  const btn  = document.getElementById('archiveUploadBtn');
  btn.disabled = true;
  prog.style.display = '';
  prog.textContent = 'Uploading ' + file.name + ' (' + (file.size/1024/1024).toFixed(1) + ' MB)...';
  const fd = new FormData();
  fd.append('file',        file);
  fd.append('victim_name', document.getElementById('archiveUploadVictim').value.trim());
  fd.append('actor',       document.getElementById('archiveUploadActor').value.trim() || 'unknown');
  fd.append('leak_name',   document.getElementById('archiveUploadLeakName').value.trim());
  fd.append('source_type', document.getElementById('archiveUploadSourceType').value);
  try {
    const res = await fetch('/api/archive_import/upload', {method:'POST', body:fd}).then(r=>r.json());
    if(res.ok){
      toast('Uploaded & queued job #' + res.job_id, 'success');
      fileInput.value='';
      document.getElementById('archiveUploadVictim').value='';
      document.getElementById('archiveUploadActor').value='';
      document.getElementById('archiveUploadLeakName').value='';
      prog.style.display='none';
      loadArchiveImport();
    } else {
      prog.textContent = 'Error: ' + (res.reason || 'upload failed');
      toast(res.reason || 'Upload failed', 'error', 5000);
    }
  } catch(e){
    prog.textContent = 'Network error: ' + e;
    toast('Upload failed: ' + e, 'error', 5000);
  } finally {
    btn.disabled = false;
  }
}

async function editArchiveJob(id, currentVictim, currentActor, currentLeak){
  const victim = prompt('Victim name:', currentVictim || '');
  if(victim === null) return;
  const actor  = prompt('Actor / threat group:', currentActor || 'unknown');
  if(actor  === null) return;
  const leak   = prompt('Leak name / label:', currentLeak || '');
  if(leak   === null) return;
  const params = new URLSearchParams({
    id, victim_name: victim.trim(), actor: actor.trim() || 'unknown', leak_name: leak.trim()
  });
  const res = await fetch('/api/archive_import/update?' + params).then(r=>r.json()).catch(e=>({ok:false,reason:String(e)}));
  if(res.ok){ toast('Job #' + id + ' updated', 'success'); loadArchiveImport(); }
  else toast(res.reason || 'Update failed', 'error', 4500);
}

async function loadArchiveImport(){
  const wrap = document.getElementById('archiveImportWrap');
  if(!wrap) return;
  wrap.innerHTML = '<div class="empty"><div class="empty-icon">⏳</div>Loading archive jobs…</div>';
  const res = await fetch('/api/archive_import/jobs').then(r=>r.json()).catch(()=>null);
  if(!res || !res.jobs || !res.jobs.length){
    wrap.innerHTML = '<div class="empty"><div class="empty-icon">📦</div>No archive import jobs yet</div>';
    return;
  }

  const statusClass = (s)=>{
    if(['processed'].includes(s)) return 'score-hi';
    if(['infected','infected_extracted','error','worker_missing'].includes(s)) return 'score-lo';
    return 'score-mid';
  };

  const rows = res.jobs.map(j=>{
    const malware = j.malware_signature ? `<span class="chip chip-red">${esc(j.malware_signature)}</span>` : '';
    const err = j.error ? `<div style="color:var(--red);font-size:11px;max-width:260px;white-space:normal;">${esc(j.error)}</div>` : '';
    return `<tr>
      <td class="td-mono">#${j.id}</td>
      <td class="td-url"><a href="${esc(j.download_url||'')}" target="_blank">${esc(j.download_url||'')}</a></td>
      <td class="td-small">${esc(j.victim_name||'')}</td>
      <td class="td-small">${esc(j.actor||'unknown')}</td>
      <td class="td-small">${esc(j.leak_name||'')}</td>
      <td><span class="score-badge ${statusClass(j.status)}">${esc(j.status||'queued')}</span>${malware}${err}</td>
      <td class="td-mono">${j.files_found||0} / ${j.files_processed||0}</td>
      <td class="td-mono">${(j.entities_imported||0).toLocaleString()}</td>
      <td class="td-mono">${esc(j.created_at||'')}</td>
      <td class="td-actions">
        <button class="row-btn" onclick="showArchiveFiles(${j.id})">files</button>
        <button class="row-btn" onclick="rerunArchiveJob(${j.id})">run</button>
        <button class="row-btn" style="color:var(--amber);" onclick="editArchiveJob(${j.id},${JSON.stringify(j.victim_name||'')},${JSON.stringify(j.actor||'unknown')},${JSON.stringify(j.leak_name||'')})">edit</button>
      </td>
    </tr>
    <tr id="archiveFiles_${j.id}" style="display:none;"><td colspan="10" style="padding:0;background:rgba(59,130,246,0.03);"></td></tr>`;
  }).join('');

  wrap.innerHTML = `<table class="data-table">
    <thead><tr>
      <th>ID</th><th>URL</th><th>Victim</th><th>Actor</th><th>Leak</th><th>Status</th><th>Files</th><th>Entities</th><th>Created</th><th></th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

async function showArchiveFiles(id){
  const row = document.getElementById('archiveFiles_' + id);
  if(!row) return;
  const td = row.querySelector('td');
  if(row.style.display !== 'none'){
    row.style.display = 'none';
    return;
  }
  row.style.display = '';
  td.innerHTML = '<div style="padding:10px 16px;color:var(--text-3);">Loading files…</div>';
  const res = await fetch('/api/archive_import/files?id=' + encodeURIComponent(id)).then(r=>r.json()).catch(()=>null);
  if(!res || !res.files || !res.files.length){
    td.innerHTML = '<div style="padding:10px 16px;color:var(--text-3);">No files inventoried yet.</div>';
    return;
  }
  td.innerHTML = `<table style="width:100%;">
    ${res.files.map(f=>`<tr>
      <td class="td-mono" style="padding-left:28px;max-width:480px;">${esc(f.file_path||'')}</td>
      <td class="td-mono">${esc(f.file_ext||'')}</td>
      <td class="td-mono">${(f.size_bytes||0).toLocaleString()} bytes</td>
      <td><span class="score-badge ${f.score>=20?'score-hi':'score-lo'}">${f.score||0}</span></td>
      <td class="td-small">${esc(f.status||'')}</td>
      <td class="td-small">${esc(f.reason||'')}</td>
    </tr>`).join('')}
  </table>`;
}

// ── Alerts ─────────────────────────────────────────────────────────────────────
async function loadAlerts(){
  const res=await fetch('/api/alerts').then(r=>r.json()).catch(()=>[]);
  const el=document.getElementById('alertList');
  if(!res.length){el.innerHTML='<div style="color:var(--dim);font-family:\'Share Tech Mono\',monospace;font-size:.75rem;padding:8px 0;">No alerts set. Add keywords to watch for.</div>';return;}
  el.innerHTML=res.map(a=>`
    <div class="alert-row">
      <div class="alert-kw">${esc(a.keyword)}</div>
      <div class="alert-hits">${a.hit_count||0} hits</div>
      ${a.unseen>0?`<div class="alert-unseen">${a.unseen} new</div>`:''}
      <button class="btn danger" onclick="deleteAlert(${a.id})">✕ remove</button>
    </div>`).join('');
}

async function addAlert(){
  const kw=document.getElementById('alertInput').value.trim();
  if(!kw)return;
  const res=await fetch(`/api/alerts/add?keyword=${encodeURIComponent(kw)}`).then(r=>r.json());
  if(res.ok){document.getElementById('alertInput').value='';toast(`Alert added: ${kw}`, 'success');loadAlerts();}
  else addLog(`Alert error: ${res.error}`,'r');
}

async function deleteAlert(id){
  await fetch(`/api/alerts/delete?id=${id}`);
  addLog('Alert removed.','b');
  loadAlerts();
}

async function loadAlertHits(){
  const hitsEl=document.getElementById('alertHits');
  hitsEl.style.display='';
  const res=await fetch('/api/alerts/hits').then(r=>r.json()).catch(()=>[]);
  document.getElementById('hitList').innerHTML=!res.length
    ?'<div style="color:var(--dim);font-family:\'Share Tech Mono\',monospace;font-size:.72rem;padding:8px 0;">No hits yet.</div>'
    :res.map(h=>`
      <div class="hit-row">
        <div class="hit-kw">${esc(h.keyword)}</div>
        <div style="flex:1;">
          <div class="hit-title">${esc(h.title||'')}</div>
          <div class="hit-url">${esc(h.url||'')}</div>
        </div>
        <span class="hit-type ${h.site_type}">${h.site_type}</span>
      </div>`).join('');
  loadAlerts();
}

// ── Stats ──────────────────────────────────────────────────────────────────────
async function loadStats(){
  const panel=document.getElementById('statsPanel');
  const el=panel.querySelector('.panel-scroll')||panel;
  el.innerHTML='<div class="empty"><div class="empty-icon">⏳</div>Loading stats…</div>';
  const s=await fetch('/api/stats').then(r=>r.json()).catch(()=>null);
  if(!s){el.innerHTML='<div class="empty">Failed to load stats</div>';return;}
  const maxCat=Math.max(...s.categories.map(c=>c.count),1);
  const maxDay=Math.max(...s.daily.map(d=>d.count),1);
  el.innerHTML=`
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-val">${s.total.toLocaleString()}</div><div class="stat-lbl">Clean Sites</div></div>
      <div class="stat-card"><div class="stat-val">${s.noise.toLocaleString()}</div><div class="stat-lbl">Filtered Out</div></div>
      <div class="stat-card"><div class="stat-val">${s.mirrors.toLocaleString()}</div><div class="stat-lbl">Mirror Groups</div></div>
      <div class="stat-card"><div class="stat-val">${s.crawl_log.length}</div><div class="stat-lbl">Crawl Sessions</div></div>
    </div>
    <div class="section-title">Sites by Category</div>
    ${s.categories.map(c=>`
      <div class="bar-row">
        <div class="bar-label">${ICONS[c.category]||'🌐'} ${esc(c.category)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${(c.count/maxCat*100).toFixed(1)}%"></div></div>
        <div class="bar-num">${c.count.toLocaleString()}</div>
      </div>`).join('')}
    <div class="section-title">Sites Found by Day</div>
    ${s.daily.map(d=>`
      <div class="bar-row">
        <div class="bar-label" style="font-size:.6rem;">${d.day}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${(d.count/maxDay*100).toFixed(1)}%;background:linear-gradient(90deg,var(--accent2),var(--accent));"></div></div>
        <div class="bar-num">${d.count.toLocaleString()}</div>
      </div>`).join('')}
    <div class="section-title">Crawl History</div>
    ${s.crawl_log.length?`<table>
      <thead><tr><th>Date</th><th>Sites</th><th>Leaks</th><th>Duration</th></tr></thead>
      <tbody>${s.crawl_log.map(l=>`<tr>
        <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;">${new Date(l.timestamp*1000).toLocaleString()}</td>
        <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:var(--accent);">${l.sites_found.toLocaleString()}</td>
        <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:var(--danger);">${l.leaks_found}</td>
        <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:var(--dim);">${Math.round(l.duration_s/60)}min</td>
      </tr>`).join('')}</tbody>
    </table>`:'<div style="color:var(--dim);font-family:\'Share Tech Mono\',monospace;font-size:.72rem;">No crawl sessions recorded yet.</div>'}
  `;
}

// ── Drawer ─────────────────────────────────────────────────────────────────────
function openDrawer(id){
  const s=_siteCache[id]; if(!s)return;
  drawerSite={...s,_type:'site'};
  document.getElementById('drTitle').textContent=s.title||'[no title]';
  document.getElementById('drUrl').innerHTML=`<a href="${esc(s.url||'')}" target="_blank">${esc(s.url||'')}</a>`;
  document.getElementById('drPreview').textContent=s.preview||'(no preview)';
  document.getElementById('drNote').value=s.notes||'';
  const cc=s.score>=15?'green':s.score>=5?'blue':'';
  document.getElementById('drMeta').innerHTML=
    `<span class="dr-tag ${cc}">Score: ${s.score>=0?'+':''}${s.score}</span>
     <span class="dr-tag blue">${ICONS[s.category]||''} ${esc(s.category)}</span>
     <span class="dr-tag">HTTP ${s.status}</span>`+
    (s.mirror_group?`<span class="dr-tag" style="border-color:var(--accent2);color:var(--accent2)">🔁 mirror group</span>`:'');
  document.getElementById('drBm').textContent=s.bookmarked?'🔖 Saved':'🔖 Bookmark';
  document.getElementById('drBm').className=s.bookmarked?'btn on':'btn';
  document.getElementById('drRv').textContent=s.reviewed?'✓ Reviewed':'✓ Mark Reviewed';
  openDrawerUI();
}

function openLeakDrawer(id){
  const l=_leakCache[id]; if(!l)return;
  drawerSite={...l,_type:'leak'};
  document.getElementById('drTitle').textContent=l.title||'[no title]';
  document.getElementById('drUrl').innerHTML=`<a href="${esc(l.url||'')}" target="_blank">${esc(l.url||'')}</a>`;
  const cves=JSON.parse(l.cves||'[]');
  const targets=JSON.parse(l.breach_targets||'[]');
  const records=JSON.parse(l.record_counts||'[]');
  const etypes=JSON.parse(l.exploit_types||'[]');
  const cc=l.confidence>=70?'var(--danger)':l.confidence>=45?'var(--warn)':'var(--accent2)';
  document.getElementById('drMeta').innerHTML=
    `<span class="dr-tag" style="border-color:${cc};color:${cc}">Confidence: ${l.confidence}%</span>`+
    cves.map(c=>`<span class="dr-tag" style="border-color:var(--warn);color:var(--warn)">${esc(c)}</span>`).join('')+
    (l.has_ssn?'<span class="dr-tag" style="border-color:var(--danger);color:var(--danger)">🪪 SSN patterns</span>':'')+
    (l.has_emails?'<span class="dr-tag green">📧 emails</span>':'')+
    (l.has_hashes?'<span class="dr-tag green">🔑 hashes</span>':'')+
    (l.has_magnet?'<span class="dr-tag blue">💾 download</span>':'');
  let prev='';
  if(targets.length)prev+='Targets: '+targets.join(', ')+'\n';
  if(records.length)prev+='Records: '+records.join(', ')+'\n';
  if(etypes.length) prev+='Exploits: '+etypes.join(', ')+'\n';
  prev+=`
${l.full_text||''}`;
  document.getElementById('drPreview').textContent=prev.trim();
  document.getElementById('drNote').value=l.notes||'';
  document.getElementById('drBm').textContent=l.bookmarked?'🔖 Saved':'🔖 Bookmark';
  document.getElementById('drBm').className=l.bookmarked?'btn on':'btn';
  document.getElementById('drRv').style.display='none';
  openDrawerUI();
}

function closeDrawer(){
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('drawer-overlay').classList.remove('visible');
}
function openDrawerUI(){
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('visible');
}

async function saveNote(){
  if(!drawerSite)return;
  const note=document.getElementById('drNote').value;
  const ep=drawerSite._type==='leak'?'/api/leaks/note':'/api/note';
  await fetch(`${ep}?id=${drawerSite.id}&note=${encodeURIComponent(note)}`);
  if(_siteCache[drawerSite.id])_siteCache[drawerSite.id].notes=note;
  if(_leakCache[drawerSite.id])_leakCache[drawerSite.id].notes=note;
  toast('Note saved', 'success');
}

async function toggleDrawerBm(){
  if(!drawerSite)return;
  const newVal=drawerSite.bookmarked?0:1;
  const ep=drawerSite._type==='leak'?'/api/leaks/bookmark':'/api/bookmark';
  await fetch(`${ep}?id=${drawerSite.id}&val=${newVal}`);
  drawerSite.bookmarked=newVal;
  document.getElementById('drBm').textContent=newVal?'🔖 Saved':'🔖 Bookmark';
  document.getElementById('drBm').className=newVal?'btn on':'btn';
}

async function deleteSite(){
  if(!drawerSite||drawerSite._type!=="site") return;
  if(!confirm("Delete this site? This cannot be undone.")) return;
  const res = await fetch(`/api/site/delete?id=${drawerSite.id}`).then(r=>r.json()).catch(()=>null);
  if(res&&res.ok){
    toast("Site deleted","success");
    closeDrawer();
    delete _siteCache[drawerSite.id];
    if(currentTab==="top") loadTop(); else load();
  } else { toast("Delete failed","error"); }
}

async function scheduleRecrawl(){
  if(!drawerSite||drawerSite._type!=="site")return;
  await addRecrawl(drawerSite.id,24);
  document.getElementById("drRcBtn").textContent="🔄 Scheduled!";
  document.getElementById("drRcBtn").classList.add("primary");
}

async function toggleDrawerRv(){
  if(!drawerSite)return;
  const newVal=drawerSite.reviewed?0:1;
  await fetch(`/api/reviewed?id=${drawerSite.id}&val=${newVal}`);
  drawerSite.reviewed=newVal;
  document.getElementById('drRv').textContent=newVal?'✓ Reviewed':'✓ Mark Reviewed';
}

async function toggleBm(id,btn){
  const isOn=btn.classList.contains('on');
  await fetch(`/api/bookmark?id=${id}&val=${isOn?0:1}`);
  btn.classList.toggle('on');
  btn.textContent=isOn?'🔖 save':'🔖 saved';
  if(_siteCache[id])_siteCache[id].bookmarked=isOn?0:1;
  updateBookmarkCount();
}

// ── Polling ────────────────────────────────────────────────────────────────────
async function startPolling(){
  if(pollTimer) clearInterval(pollTimer);
  _pollInterval = 3000;
  pollTimer = setInterval(poll, _pollInterval);
}

async function poll(){
  const st = await fetch('/api/status').then(r=>r.json()).catch(()=>null);
  if(!st) return;

  updateDot(st.status);
  document.getElementById('hTotal').textContent   = (st.total||0).toLocaleString();
  if(document.getElementById('hLeaks')) document.getElementById('hLeaks').textContent = (st.leaks||0).toLocaleString();
  if(document.getElementById('hTgMsg')) document.getElementById('hTgMsg').textContent = (st.tg_messages||0).toLocaleString();
  if(document.getElementById('hTgLeak')) document.getElementById('hTgLeak').textContent = (st.tg_leaks||0).toLocaleString();

  const hasNew = (st.new||0) > 0 || (st.new_leak||0) > 0;

  if((st.new||0) > 0){
    addLog(`+${st.new} new sites (total: ${st.total.toLocaleString()})`,'g');
    document.getElementById('newBadge').innerHTML=`<span class="new-badge">+${st.new} new</span>`;
  } else {
    document.getElementById('newBadge').innerHTML='';
  }
  if((st.new_leak||0) > 0) addLog(`+${st.new_leak} new leaks detected`,'r');
  if((st.due_recrawl||0) > 0){
    const b=document.getElementById('rcDueBadge');
    if(b) b.innerHTML=`<span class="new-badge" style="background:var(--accent2);">${st.due_recrawl} due</span>`;
  } else { const b=document.getElementById('rcDueBadge'); if(b) b.innerHTML=''; }
  if((st.unseen_alerts||0) > 0){
    const ab=document.getElementById('alertBadge');
    if(ab) ab.innerHTML=`<span class="sev sev-critical" style="font-size:11px;">🔔 ${st.unseen_alerts}</span>`;
    const nb=document.getElementById('alertNavBadge');
    if(nb){ nb.textContent=st.unseen_alerts; nb.style.display=''; }
  } else {
    const ab=document.getElementById('alertBadge'); if(ab) ab.innerHTML='';
    const nb=document.getElementById('alertNavBadge'); if(nb) nb.style.display='none';
  }

  // Only refresh current tab data if something actually changed
  if(hasNew){
    if(currentTab==='top') loadTop();
    if(currentTab==='stats') loadStats();
    _lastSiteCount = st.total;
    // Reset poll interval to fast when active
    _pollInterval = 3000;
  } else if(st.status !== 'running') {
    // Crawler idle — slow down polling to reduce server load
    _pollInterval = Math.min(_pollInterval * 1.5, 15000);
    clearInterval(pollTimer);
    pollTimer = setInterval(poll, _pollInterval);
  }

  // Fetch crawler activity log
  await pollActivity();

  if(st.status==='finished' || st.status==='idle'){
    clearInterval(pollTimer);
    // Keep slow polling so we catch manual file drops
    pollTimer = setInterval(poll, 10000);
    document.getElementById('btnStart').disabled  = false;
    if(document.getElementById('btnStop'))document.getElementById('btnStop').disabled=true;
    document.getElementById('liveInd').style.display = 'none';
  }
}

async function pollActivity(){
  const res = await fetch(`/api/activity?since=${_activitySince}`)
    .then(r=>r.json()).catch(()=>null);
  if(!res || !res.lines.length) return;
  _activitySince = res.total;

  for(const line of res.lines){
    // Colour-code by type
    const type =
      line.includes('[SAVED')   ? 'g' :
      line.includes('[LEAK')    ? 'r' :
      line.includes('[SKIP')    ? ''  :
      line.includes('[BLOCKED') ? ''  :
      line.includes('[QUEUE')   ? 'b' :
      line.includes('ERROR')    ? 'r' :
      line.includes('WARNING')  ? ''  : 'b';
    addLog(line, type);
  }
}

function updateDot(state){
  document.getElementById('dot').className='status-dot '+state;
  document.getElementById('stText').textContent=state==='running'?'Crawling…':state==='finished'?'Finished':'Idle';
}

async function updateBookmarkCount(){
  const r=await fetch('/api/sites?view=bookmarked&q=&page=1').then(r=>r.json()).catch(()=>null);
  // hBookmarks removed
}

async function resetCrawler(){
  if(!confirm('Clear crawler JOBDIR and state? The next Start will begin a fresh crawl.')) return;
  const r = await fetch('/api/reset_crawler').then(r=>r.json()).catch(()=>null);
  if(r && r.ok){
    addLog('Crawler state reset. Click Start to begin a fresh crawl.','b');
    document.getElementById('btnStart').disabled = false;
    if(document.getElementById('btnStop'))document.getElementById('btnStop').disabled=true;
    document.getElementById('liveInd').style.display = 'none';
    updateDot('idle');
  } else {
    addLog(`Reset failed: ${r?.reason || 'unknown error'}`,'r');
  }
}

async function startCrawl(){
  await fetch('/api/start');
  document.getElementById('btnStart').disabled=true;
  if(document.getElementById('btnStop'))document.getElementById('btnStop').disabled=false;
  document.getElementById('liveInd').style.display='';
  addLog('Crawl started…','g');
  startPolling();
}

async function stopCrawl(){
  await fetch('/api/stop');
  document.getElementById('btnStart').disabled=false;
  if(document.getElementById('btnStop'))document.getElementById('btnStop').disabled=true;
  document.getElementById('liveInd').style.display='none';
  addLog('Crawl stopped.','r');
}

function addLog(msg,type=''){
  const el=document.getElementById('log');
  const d=document.createElement('div');
  d.className='ll '+type;
  d.textContent=ts()+msg;
  el.appendChild(d);
  el.scrollTop=el.scrollHeight;
  while(el.children.length>150)el.removeChild(el.firstChild);
}

// ── Files tab ─────────────────────────────────────────────────────────────────
let filePage=1, fileTotal=0;

async function loadFiles(){
  const q   = document.getElementById('fileQ').value;
  const ext = document.getElementById('fileExt').value;
  const res = await fetch(`/api/files?q=${encodeURIComponent(q)}&ext=${encodeURIComponent(ext)}&page=${filePage}`)
    .then(r=>r.json()).catch(()=>null);
  if(!res) return;
  fileTotal = res.total;
  document.getElementById('fileShown').textContent = res.files.length.toLocaleString();
  document.getElementById('fileTotal').textContent  = res.total.toLocaleString();

  // Populate extension filter
  const sel = document.getElementById('fileExt');
  if(sel.options.length <= 1){
    for(const e of res.ext_counts){
      const opt=document.createElement('option');
      opt.value=e.extension; opt.textContent=`${e.extension} (${e.c})`;
      sel.appendChild(opt);
    }
  }

  const wrap = document.getElementById('fileTableWrap');
  if(!res.files.length){
    wrap.innerHTML='<div class="empty"><div class="empty-icon">📁</div>No file links found yet</div>';
    document.getElementById('filePgEl').innerHTML='';
    return;
  }
  const rows = res.files.map(f=>`<tr>
    <td class="td-url"><a href="${esc(f.url||'')}" target="_blank">${esc(f.url||'')}</a></td>
    <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:var(--warn);">${esc(f.extension||'')}</td>
    <td style="font-size:.72rem;color:#8ab4cc;">${esc(f.site_title||'unknown')}</td>
    <td style="font-family:Share Tech Mono,monospace;font-size:.62rem;color:var(--dim);">${new Date((f.timestamp||0)*1000).toLocaleDateString()}</td>
  </tr>`).join('');
  wrap.innerHTML=`<table><thead><tr><th>File URL</th><th>Type</th><th>Found On</th><th>Date</th></tr></thead><tbody>${rows}</tbody></table>`;

  const pages=Math.ceil(res.total/50);
  if(pages>1){
    let b=`<button class="pg" onclick="goFilePage(${filePage-1})" ${filePage===1?'disabled':''}>← prev</button>`;
    for(let i=Math.max(1,filePage-3);i<=Math.min(pages,filePage+3);i++)
      b+=`<button class="pg ${i===filePage?'active':''}" onclick="goFilePage(${i})">${i}</button>`;
    b+=`<button class="pg" onclick="goFilePage(${filePage+1})" ${filePage===pages?'disabled':''}>next →</button>`;
    document.getElementById('filePgEl').innerHTML=`<div class="pagination">${b}</div>`;
  } else { document.getElementById('filePgEl').innerHTML=''; }
}

async function goFilePage(p){const pages=Math.ceil(fileTotal/50);if(p<1||p>pages)return;filePage=p;loadFiles();}

// ── Re-crawl tab ───────────────────────────────────────────────────────────────
async function loadRecrawl(){
  const res=await fetch('/api/recrawl?action=list').then(r=>r.json()).catch(()=>null);
  const el=document.getElementById('recrawlList');
  if(!res||!res.queue.length){
    el.innerHTML='<div style="color:var(--dim);font-family:Share Tech Mono,monospace;font-size:.72rem;">No sites queued. Open any site detail drawer and click Schedule Re-Crawl to add it.</div>';
    return;
  }
  const now=Date.now()/1000;
  el.innerHTML=res.queue.map(r=>{
    const isDue  = r.next_crawl<=now;
    const hoursLeft = Math.round((r.next_crawl-now)/3600);
    const nextStr = isDue
      ? '<span style="color:var(--danger);font-weight:600;">Due now</span>'
      : `<span style="color:var(--dim)">in ${hoursLeft}h</span>`;
    const uptime  = r.uptime_count||1;
    const down    = r.downtime_count||0;
    const total2  = uptime+down;
    const pct     = Math.round(uptime/total2*100);
    const uptimeCol = pct>=80?'var(--accent)':pct>=50?'var(--warn)':'var(--danger)';
    const freq = r.interval_h<=12?'high':r.interval_h<=48?'normal':r.interval_h<=96?'slow':'weekly';
    return`<div class="alert-row">
      <div style="flex:1;">
        <div style="font-size:.78rem;color:#f0f6ff;margin-bottom:2px;">${esc(r.title||'')}
          <span style="font-family:Share Tech Mono,monospace;font-size:.6rem;color:var(--dim);margin-left:6px;">${esc(r.category||'')}</span>
        </div>
        <div style="font-family:Share Tech Mono,monospace;font-size:.6rem;color:var(--accent2);">${esc(r.url||'')}</div>
      </div>
      <div style="font-family:Share Tech Mono,monospace;font-size:.65rem;text-align:right;margin-right:12px;line-height:1.8;">
        <div>every <span style="color:var(--accent2);">${r.interval_h}h</span> <span style="color:var(--dim);">(${freq})</span></div>
        <div>${nextStr}</div>
        <div>uptime <span style="color:${uptimeCol};">${pct}%</span> &bull; <span style="color:var(--warn);">${r.change_count} changes</span></div>
      </div>
      <button class="btn danger" onclick="removeRecrawl(${r.site_id})" style="padding:4px 8px;">&#10005;</button>
    </div>`;
  }).join('');
  if(res.due>0) addLog(`${res.due} sites due for re-crawl`,'r');
}

async function addRecrawl(siteId, hours){
  await fetch(`/api/recrawl?action=add&id=${siteId}&hours=${hours||24}`);
  addLog('Added to re-crawl queue.','g');
  if(currentTab==='recrawl') loadRecrawl();
}

async function removeRecrawl(siteId){
  await fetch(`/api/recrawl?action=remove&id=${siteId}`);
  loadRecrawl();
}

// ── Language tab ───────────────────────────────────────────────────────────────
async function loadLanguages(){
  const res=await fetch('/api/languages').then(r=>r.json()).catch(()=>[]);
  const el=document.getElementById('languageList');
  if(!res.length){
    el.innerHTML='<div style="color:var(--dim);font-family:Share Tech Mono,monospace;font-size:.72rem;">No language data yet. Install langdetect: pip install langdetect</div>';
    return;
  }
  const max=Math.max(...res.map(r=>r.count),1);
  const langNames={'en':'English','ru':'Russian','de':'German','fr':'French',
    'es':'Spanish','zh-cn':'Chinese','pt':'Portuguese','ar':'Arabic',
    'ja':'Japanese','ko':'Korean','it':'Italian','nl':'Dutch','pl':'Polish'};
  el.innerHTML=`
    <div style="margin-bottom:16px;font-family:Share Tech Mono,monospace;font-size:.68rem;color:var(--dim);">
      ${res.reduce((a,r)=>a+r.count,0).toLocaleString()} sites with detected language
    </div>`+
  res.map(r=>`
    <div class="bar-row" style="cursor:pointer;" onclick="filterByLang('${r.language}')">
      <div class="bar-label">${langNames[r.language]||r.language.toUpperCase()}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(r.count/max*100).toFixed(1)}%;background:linear-gradient(90deg,var(--accent2),var(--accent));"></div></div>
      <div class="bar-num">${r.count.toLocaleString()}</div>
    </div>`).join('');
}

function filterByLang(lang){
  // Switch to browse and filter by language
  setTab('browse');
  document.getElementById('q').value=lang;
  currentPage=1; load();
}

// ── Network graph tab ─────────────────────────────────────────────────────────
async function loadNetwork(){
  const res=await fetch('/api/network').then(r=>r.json()).catch(()=>null);
  const panel=document.getElementById('networkPanel');
  const scroll=panel?panel.querySelector('.panel-scroll')||panel:null;
  if(!res||!res.nodes.length){
    if(scroll) scroll.innerHTML=
      '<div class="empty"><div class="empty-icon">🕸</div>Not enough data for network graph yet</div>';
    return;
  }

  const canvas=document.getElementById('networkCanvas');
  if(!canvas) return;
  const ctx=canvas.getContext('2d');
  canvas.width=canvas.offsetWidth;
  canvas.height=canvas.offsetHeight;
  const W=canvas.width, H=canvas.height;

  // Simple force-directed layout
  const nodes=res.nodes.map((n,i)=>({
    id:n.id, count:n.count,
    x:W/2+Math.cos(i/res.nodes.length*Math.PI*2)*180,
    y:H/2+Math.sin(i/res.nodes.length*Math.PI*2)*180,
    vx:0, vy:0
  }));
  const nodeMap={};
  nodes.forEach(n=>nodeMap[n.id]=n);
  const edges=res.edges.filter(e=>nodeMap[e.source_cat]&&nodeMap[e.target_cat]);

  const ICONS_GRAPH={'Search Engines':'🔍','Wikis & Directories':'📖','Forums':'💬',
    'News & Media':'📰','Technology':'⚙️','Privacy Tools':'🔒',
    'Libraries':'📚','Markets':'🛒','Finance & Crypto':'₿','Uncategorized':'❓'};

  let frame=0;
  function draw(){
    ctx.clearRect(0,0,W,H);
    ctx.fillStyle='#080b0f';
    ctx.fillRect(0,0,W,H);

    // Simple spring simulation
    if(frame<120){
      for(const n of nodes){
        n.vx*=0.85; n.vy*=0.85;
        // Repel other nodes
        for(const m of nodes){
          if(n===m)continue;
          const dx=n.x-m.x, dy=n.y-m.y;
          const d=Math.sqrt(dx*dx+dy*dy)||1;
          if(d<150){ n.vx+=dx/d*2; n.vy+=dy/d*2; }
        }
        // Attract to center
        n.vx+=(W/2-n.x)*0.005;
        n.vy+=(H/2-n.y)*0.005;
        n.x+=n.vx; n.y+=n.vy;
      }
      frame++;
    }

    // Draw edges
    const maxW=Math.max(...edges.map(e=>e.weight),1);
    for(const e of edges){
      const a=nodeMap[e.source_cat], b=nodeMap[e.target_cat];
      if(!a||!b||a===b)continue;
      ctx.beginPath();
      ctx.moveTo(a.x,a.y);
      ctx.lineTo(b.x,b.y);
      ctx.strokeStyle=`rgba(0,200,255,${Math.min(e.weight/maxW*0.6,0.5)})`;
      ctx.lineWidth=Math.max(e.weight/maxW*3,0.5);
      ctx.stroke();
    }

    // Draw nodes
    const maxCount=Math.max(...nodes.map(n=>n.count),1);
    for(const n of nodes){
      const r=Math.max(n.count/maxCount*40,12);
      ctx.beginPath();
      ctx.arc(n.x,n.y,r,0,Math.PI*2);
      ctx.fillStyle='rgba(0,255,157,0.15)';
      ctx.fill();
      ctx.strokeStyle='#00ff9d';
      ctx.lineWidth=1;
      ctx.stroke();
      ctx.fillStyle='#e2eaf2';
      ctx.font=`${Math.max(r*0.5,10)}px monospace`;
      ctx.textAlign='center';
      ctx.textBaseline='middle';
      ctx.fillText(ICONS_GRAPH[n.id]||'●',n.x,n.y);
      ctx.font='10px monospace';
      ctx.fillStyle='#7a9ab0';
      ctx.fillText(n.id.split(' ')[0],n.x,n.y+r+12);
    }

    if(frame<120) requestAnimationFrame(draw);
  }
  requestAnimationFrame(draw);
  // Canvas auto-clears when tab changes — no persistent rAF loop
}

// ── Keyword context search ────────────────────────────────────────────────────
async function searchContext(){
  const q = document.getElementById('contextQ').value.trim();
  if(!q || q.length<2) return;
  const el = document.getElementById('isResults-context');
  el.style.display='block';
  el.innerHTML='<span style="color:var(--accent2)">Searching...</span>';
  const res = await fetch(`/api/search/context?q=${encodeURIComponent(q)}&max=20`)
    .then(r=>r.json()).catch(()=>null);
  if(!res||!res.results.length){
    el.innerHTML=`<span style="color:var(--dim)">No matches found for "${esc(q)}"</span>`;
    return;
  }
  el.innerHTML = res.results.map(r=>{
    let snippet = esc(r.snippet||'');
    // Highlight the keyword in the snippet
    if(r.kw_start>=0 && r.kw_end>r.kw_start){
      const before = esc(r.snippet.substring(0,r.kw_start));
      const match  = esc(r.snippet.substring(r.kw_start,r.kw_end));
      const after  = esc(r.snippet.substring(r.kw_end));
      snippet = `${before}<mark style="background:rgba(0,255,157,.3);color:#f0f6ff;padding:0 2px;">${match}</mark>${after}`;
    }
    return`<div style="padding:6px 0;border-bottom:1px solid rgba(28,35,51,.5);">
      <div style="font-size:.72rem;color:#f0f6ff;margin-bottom:2px;">${esc(r.title||'')}</div>
      <div style="font-family:Share Tech Mono,monospace;font-size:.6rem;color:var(--accent2);margin-bottom:4px;">${esc(r.url||'')}</div>
      <div style="font-size:.68rem;color:#8ab4cc;line-height:1.5;">...${snippet}...</div>
    </div>`;
  }).join('');
}

async function runDueNow(){
  const res = await fetch('/api/recrawl?action=run_due').then(r=>r.json()).catch(()=>null);
  if(res) addLog(`Re-crawl ran: ${res.updated} sites updated`,'b');
  loadRecrawl();
}

// ── Canaries tab ──────────────────────────────────────────────────────────────
let canaryPage = 1;

async function loadCanaries(){
  // Show webhook URL
  const webhookEl = document.getElementById("webhookUrl");
  if(webhookEl) webhookEl.textContent = window.location.origin.replace("http://","https://") + "/webhook/canary";

  const res = await fetch(`/api/canary/hits?page=${canaryPage}`).then(r=>r.json()).catch(()=>null);
  if(!res) return;

  const totalEl = document.getElementById("canaryTotal");
  if(totalEl) totalEl.textContent = res.total.toLocaleString();

  const badgeEl = document.getElementById("canaryBadge");
  if(badgeEl && res.total > 0){ badgeEl.textContent=res.total; badgeEl.style.display=""; }

  const wrap = document.getElementById("canaryTableWrap");
  if(!wrap) return;

  if(!res.hits.length){
    wrap.innerHTML='<div class="empty"><div class="empty-icon">🐦</div>No canary hits yet. Create tokens at canarytokens.org and set the webhook URL above.</div>';
    return;
  }

  const rows = res.hits.map(h=>{
    const ts  = h.timestamp ? new Date(h.timestamp*1000).toLocaleString() : "";
    const geo = (() => { try { const g=JSON.parse(h.geo||"{}"); return g.city?(g.city+", "+g.country_code):g.country_code||""; } catch(e){ return ""; } })();
    return`<tr style="vertical-align:top;">
      <td style="padding-top:12px;">
        <span class="sev sev-high">${esc(h.token_type||"")}</span>
      </td>
      <td style="padding:10px 14px;font-size:13px;color:var(--text);font-weight:500;">${esc(h.memo||"unknown token")}</td>
      <td style="font-family:JetBrains Mono,monospace;font-size:12px;color:var(--red);padding-top:12px;">${esc(h.src_ip||"")}</td>
      <td style="font-size:12px;color:var(--text-2);padding-top:12px;">${esc(geo)}</td>
      <td style="font-size:11px;color:var(--text-3);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-top:12px;">${esc(h.useragent||"")}</td>
      <td style="font-family:JetBrains Mono,monospace;font-size:11px;color:var(--text-3);white-space:nowrap;padding-top:12px;">${ts}</td>
    </tr>`;
  }).join("");

  wrap.innerHTML=`<table class="data-table"><thead><tr><th>Type</th><th>Token / Memo</th><th>Attacker IP</th><th>Location</th><th>User Agent</th><th>Time</th></tr></thead><tbody>${rows}</tbody></table>`;

  const pages = Math.ceil(res.total/50);
  const pgEl  = document.getElementById("canaryPgEl");
  if(pgEl && pages > 1){
    let b=`<button class="pg" onclick="goCanaryPage(${canaryPage-1})" ${canaryPage===1?"disabled":""}>prev</button>`;
    for(let i=Math.max(1,canaryPage-2);i<=Math.min(pages,canaryPage+2);i++)
      b+=`<button class="pg ${i===canaryPage?"active":""}" onclick="goCanaryPage(${i})">${i}</button>`;
    b+=`<button class="pg" onclick="goCanaryPage(${canaryPage+1})" ${canaryPage===pages?"disabled":""}>next</button>`;
    pgEl.innerHTML=`<div class="pagination">${b}</div>`;
  } else if(pgEl) { pgEl.innerHTML=""; }
}

function goCanaryPage(p){ const total=parseInt((document.getElementById("canaryTotal")?.textContent||"0").replace(/,/g,""))||0; const pages=Math.ceil(total/50)||1; if(p<1||p>pages)return; canaryPage=p; loadCanaries(); }

// ── Stealer logs tab ──────────────────────────────────────────────────────────
async function loadStealerStats(){
  const s = await fetch('/api/stealer/stats').then(r=>r.json()).catch(()=>null);
  if(!s) return;
  document.getElementById('stLogs').textContent  = (s.total_logs||0).toLocaleString();
  document.getElementById('stCreds').textContent = (s.total_creds||0).toLocaleString();
  const el = document.getElementById('stealerLogs');
  if(!s.recent||!s.recent.length){
    el.innerHTML='<div style="color:var(--dim);font-family:Share Tech Mono,monospace;font-size:.72rem;">No log files parsed yet. Drop .zip or .txt files into stealer_logs/ then run: python stealer_parser.py</div>';
    return;
  }
  el.innerHTML=s.recent.map(l=>`
    <div class="alert-row" style="margin-bottom:8px;">
      <div style="flex:1;">
        <div style="font-size:.78rem;color:#f0f6ff;margin-bottom:2px;">${esc(l.filename||"")}</div>
        <div style="font-family:Share Tech Mono,monospace;font-size:.62rem;color:var(--dim);">${esc(l.log_type||"")} &bull; ${l.parsed_at?new Date(l.parsed_at*1000).toLocaleString():""}</div>
      </div>
      <div style="font-family:Share Tech Mono,monospace;font-size:.72rem;text-align:right;line-height:1.8;">
        <div style="color:var(--danger);">${(l.cred_count||0).toLocaleString()} creds</div>
        ${l.has_ssn?"<div style='color:var(--warn);'>SSN found</div>":""}
      </div>
    </div>`).join("");
}

async function searchStealer(){
  const q  = document.getElementById('stealerQ').value.trim();
  if(!q||q.length<2) return;
  const el = document.getElementById('stealerResults');
  el.innerHTML='<span style="color:var(--accent2);font-family:Share Tech Mono,monospace;font-size:.72rem;">Searching...</span>';
  const res = await fetch(`/api/stealer/search?q=${encodeURIComponent(q)}`).then(r=>r.json()).catch(()=>null);
  if(!res||!res.results.length){
    el.innerHTML=`<span style="color:var(--accent);font-family:Share Tech Mono,monospace;font-size:.72rem;">No matches for "${esc(q)}"</span>`;
    return;
  }
  el.innerHTML=`<div style="color:var(--danger);font-family:Share Tech Mono,monospace;font-size:.72rem;margin-bottom:6px;">Found in ${res.total.toLocaleString()} credential(s)</div>`+
  res.results.map(r=>`
    <div style="padding:5px 8px;border-left:2px solid var(--danger);margin-bottom:4px;background:rgba(255,77,109,.04);">
      <div style="font-family:Share Tech Mono,monospace;font-size:.68rem;color:#f0f6ff;">${esc(r.username||"")} <span style="color:var(--dim);">@ ${esc(r.url||"")}</span></div>
      <div style="font-family:Share Tech Mono,monospace;font-size:.6rem;color:var(--dim);">${esc(r.log_type||"")} &bull; ${esc(r.source||"")}</div>
    </div>`).join("");
}

// ── Pastes tab ────────────────────────────────────────────────────────────────
let pastePage=1, pasteTotal=0;

async function loadPastes(){
  const q    = document.getElementById('pasteQ').value;
  const view = document.getElementById('pasteView').value;
  const res  = await fetch(`/api/pastes?q=${encodeURIComponent(q)}&view=${view}&page=${pastePage}`)
    .then(r=>r.json()).catch(()=>null);
  if(!res) return;

  pasteTotal = res.total;
  document.getElementById('pasteShown').textContent = res.pastes.length.toLocaleString();
  document.getElementById('pasteTotal').textContent  = res.total.toLocaleString();

  // Site badges
  const sitesEl = document.getElementById('pasteSites');
  sitesEl.innerHTML = (res.sites||[]).map(s=>
    `<span style="color:var(--accent2);border:1px solid var(--border);padding:2px 8px;">${esc(s.site_name)} <span style="color:var(--accent);">${s.c}</span></span>`
  ).join('');

  const wrap = document.getElementById('pasteTableWrap');
  const pgEl = document.getElementById('pastePgEl');

  if(!res.pastes.length){
    wrap.innerHTML='<div class="empty"><div class="empty-icon">📋</div>No pastes yet. Run paste_monitor.py to start monitoring.</div>';
    pgEl.innerHTML=''; return;
  }

  const rows = res.pastes.map(p=>{
    const ts      = p.first_seen ? new Date(p.first_seen*1000).toLocaleString() : '';
    const preview = esc((p.content||'').substring(0,150));
    const confCol = p.confidence>=70?'var(--danger)':p.confidence>=45?'var(--warn)':'var(--accent2)';
    return`<tr>
      <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:var(--accent2);white-space:nowrap;">${esc(p.site_name||'')}</td>
      <td class="td-url"><a href="${esc(p.url||'')}" target="_blank">${esc(p.url||'')}</a></td>
      <td style="font-size:.72rem;color:#e2eaf2;max-width:380px;line-height:1.5;">${preview}</td>
      ${p.has_leak?`<td style="font-family:Share Tech Mono,monospace;font-size:.7rem;font-weight:bold;color:${confCol};">${p.confidence}%</td>`:'<td style="color:var(--dim);font-size:.65rem;">-</td>'}
      <td style="font-family:Share Tech Mono,monospace;font-size:.6rem;color:var(--dim);white-space:nowrap;">${ts}</td>
    </tr>`;
  }).join('');

  wrap.innerHTML=`<table><thead><tr><th>Site</th><th>URL</th><th>Content</th><th>Confidence</th><th>Found</th></tr></thead><tbody>${rows}</tbody></table>`;

  const pages = Math.ceil(pasteTotal/50);
  if(pages>1){
    let b=`<button class="pg" onclick="goPastePage(${pastePage-1})" ${pastePage===1?'disabled':''}>prev</button>`;
    for(let i=Math.max(1,pastePage-2);i<=Math.min(pages,pastePage+2);i++)
      b+=`<button class="pg ${i===pastePage?'active':''}" onclick="goPastePage(${i})">${i}</button>`;
    b+=`<button class="pg" onclick="goPastePage(${pastePage+1})" ${pastePage===pages?'disabled':''}>next</button>`;
    pgEl.innerHTML=`<div class="pagination">${b}</div>`;
  }else{pgEl.innerHTML='';}
}

function goPastePage(p){const pages=Math.ceil(pasteTotal/50);if(p<1||p>pages)return;pastePage=p;loadPastes();}

// ── Telegram tab ──────────────────────────────────────────────────────────────
let tgView='leaks', tgPage=1, tgTotal=0;

function setTgTab(v){
  tgView=v; tgPage=1;
  ['leaks','all','channels'].forEach(t=>{
    const el = document.getElementById('tg-tab-'+t);
    if(!el) return;
    el.classList.toggle('on', t===v);
  });
  loadTelegramOptions();
  loadTelegram();
}

async function muteChannel(url, btn){
  if(!url){ toast("No URL for channel","error"); return; }
  const isMuted = btn.textContent.trim() === "🔊";  // 🔊 = currently muted, click to unmute
  const mute = isMuted ? 0 : 1;  // clicking unmute icon sends mute=0, clicking mute icon sends mute=1
  try {
    const res = await fetch("/api/telegram/mute?url="+encodeURIComponent(url)+"&mute="+mute)
      .then(r=>r.json());
    if(res&&res.ok){
      btn.textContent = mute ? "🔊" : "🔇";
      btn.style.borderColor = mute ? "var(--red)" : "";
      btn.style.color = mute ? "var(--red)" : "";
      btn.title = mute ? "Unmute channel" : "Mute channel";
      toast(mute ? "Channel muted" : "Channel unmuted", "info");
    }
  } catch(e){ toast("Mute failed","error"); }
}

function toggleTgMsg(id){
  const s = document.getElementById(id+'-short');
  const f = document.getElementById(id+'-full');
  const b = document.getElementById(id+'-btn');
  if(!s||!f||!b) return;
  const expanded = f.style.display !== 'none';
  s.style.display = expanded ? '' : 'none';
  f.style.display = expanded ? 'none' : '';
  b.textContent   = expanded ? '▼ Show more' : '▲ Show less';
}


function tgIntelBadges(m){
  const tags = m.intel_tags || {};
  const out = [];
  const add = (label, value, conf, cls='') => {
    if(!value) return;
    const c = conf ? ` <span style="opacity:.7">${conf}%</span>` : '';
    out.push(`<span class="mini-badge ${cls}" title="${esc(label)}">${esc(value)}${c}</span>`);
  };
  (tags.actor||[]).slice(0,2).forEach(t=>add('Actor', t.value, t.confidence, 'intel-actor'));
  (tags.threat_type||[]).slice(0,1).forEach(t=>add('Threat Type', t.value, t.confidence, 'intel-threat'));
  (tags.ttp||[]).slice(0,2).forEach(t=>add('TTP', t.value, t.confidence, 'intel-ttp'));
  if(m.intel_ioc_count) add('IOCs', `IOCs:${m.intel_ioc_count}`, null, 'intel-ioc');
  if(m.is_duplicate) add('Duplicate', 'Duplicate', null, 'intel-dupe');
  return out.length ? `<div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:8px;">${out.join('')}</div>` : '';
}

function tgIntelDetails(m){
  const tags = m.intel_tags || {};
  const iocs = m.intel_iocs || {};
  const sections = [];
  const tagOrder = ['actor','threat_type','ttp','ner_ransom_group','ner_threat_actor','ner_malware','ner_exploit'];
  tagOrder.forEach(k=>{
    if(tags[k] && tags[k].length){
      sections.push(`<div><b>${esc(k.replaceAll('_',' '))}</b>: ${tags[k].slice(0,6).map(t=>`${esc(t.value)} <span style="color:var(--text-3);">${t.confidence||50}%</span>`).join(', ')}</div>`);
    }
  });
  Object.keys(iocs).sort().forEach(k=>{
    if(iocs[k] && iocs[k].length){
      sections.push(`<div><b>${esc(k)}</b>: ${iocs[k].slice(0,6).map(x=>esc(x.value)).join(', ')}</div>`);
    }
  });
  if(!sections.length) return '';
  return `<div style="margin-top:8px;padding:8px;border:1px solid var(--border);border-radius:10px;background:rgba(255,255,255,.025);font-size:11px;color:var(--text-2);line-height:1.6;">${sections.join('')}</div>`;
}

let tgOptionsLoaded=false;
const TG_SOURCE_TIERS = ['actor_owned','affiliate','broker','intel_source','news_repost','random','spam','unknown'];
const TG_SOURCE_LABELS = {
  actor_owned:'Actor-owned', affiliate:'Affiliate', broker:'Broker', intel_source:'Intel source',
  news_repost:'News/repost', random:'Random', spam:'Spam', unknown:'Unknown'
};

function fillSelect(id, values, firstLabel){
  const el = document.getElementById(id);
  if(!el) return;
  const current = el.value;
  el.innerHTML = `<option value="">${esc(firstLabel)}</option>` +
    (values||[]).map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');
  if(current && [...el.options].some(o=>o.value===current)) el.value = current;
}

async function loadTelegramOptions(){
  if(tgOptionsLoaded) return;
  const opts = await fetch('/api/telegram/filter_options').then(r=>r.json()).catch(()=>null);
  if(!opts) return;
  fillSelect('tgActor', opts.actors || [], 'All Actors');
  fillSelect('tgThreat', opts.threats || [], 'All Threat Types');
  fillSelect('tgTtp', opts.ttps || [], 'All TTPs');
  fillSelect('tgIoc', opts.ioc_types || [], 'All IOC Types');
  tgOptionsLoaded = true;
}

function resetTelegramFilters(){
  ['tgActor','tgThreat','tgTtp','tgIoc','tgSourceTier','tgMinConf','tgDays'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.value='';
  });
  const hd=document.getElementById('tgHideDupes'); if(hd) hd.checked=false;
  tgPage=1; loadTelegram();
}

function sourceTierBadge(tier){
  const t = tier || 'unknown';
  const label = TG_SOURCE_LABELS[t] || t;
  return `<span class="mini-badge" title="Source tier">${esc(label)}</span>`;
}

function sourceTierSelect(c){
  const current = c.source_tier || 'unknown';
  const opts = TG_SOURCE_TIERS.map(t=>`<option value="${t}" ${t===current?'selected':''}>${esc(TG_SOURCE_LABELS[t]||t)}</option>`).join('');
  return `<select class="select" style="max-width:135px;font-size:11px;padding:5px 8px;" data-url="${esc(c.url||'')}" onchange="updateChannelSourceTier(this)">${opts}</select>`;
}

async function updateChannelSourceTier(sel){
  const url = sel.getAttribute('data-url') || '';
  const tier = sel.value || 'unknown';
  if(!url){ toast('No channel URL','error'); return; }
  const res = await fetch('/api/telegram/source_tier?url='+encodeURIComponent(url)+'&tier='+encodeURIComponent(tier))
    .then(r=>r.json()).catch(()=>null);
  if(res && res.ok){
    tgOptionsLoaded = false;
    toast('Source tier updated','info');
  } else {
    toast((res && res.reason) || 'Source tier update failed','error');
  }
}

function tgFilterParams(){
  const get = id => (document.getElementById(id)||{}).value || '';
  const params = new URLSearchParams({view:tgView, q:(document.getElementById('tgQ')||{}).value||'', page:String(tgPage)});
  const fields = {actor:get('tgActor'), threat:get('tgThreat'), ttp:get('tgTtp'), ioc_type:get('tgIoc'), source_tier:get('tgSourceTier'), min_conf:get('tgMinConf'), days:get('tgDays')};
  Object.entries(fields).forEach(([k,v])=>{ if(v) params.set(k,v); });
  const hd = document.getElementById('tgHideDupes');
  if(hd && hd.checked) params.set('hide_dupes','1');
  return params.toString();
}

async function loadTelegramStats(){
  const s = await fetch('/api/telegram/stats').then(r=>r.json()).catch(()=>null);
  if(!s) return;
  document.getElementById('tgChannels').textContent  = (s.joined_channels||0).toLocaleString();
  document.getElementById('tgMessages').textContent  = (s.total_messages||0).toLocaleString();
  document.getElementById('tgLeaks').textContent     = (s.leak_messages||0).toLocaleString();
  document.getElementById('tgDiscovered').textContent= (s.discovered_channels||0).toLocaleString();
}

async function loadTelegram(){
  await loadTelegramOptions();
  const res = await fetch(`/api/telegram?${tgFilterParams()}`)
    .then(r=>r.json()).catch(()=>null);
  if(!res) return;
  const wrap = document.getElementById('tgTableWrap');
  const pgEl = document.getElementById('tgPgEl');

  if(tgView === 'channels'){
    const channels = res.channels || [];
    document.getElementById('tgShown').textContent = channels.length;
    document.getElementById('tgTotal').textContent = channels.length;
    if(!channels.length){
      wrap.innerHTML='<div class="empty"><div class="empty-icon">📡</div>No channels yet. Run telegram_monitor.py to start monitoring.</div>';
      pgEl.innerHTML=''; return;
    }
    const rows = channels.map(c=>`<tr>
      <td class="td-url"><a href="${esc(c.url||'')}" target="_blank">${esc(c.url||'')}</a></td>
      <td style="font-size:.75rem;color:#f0f6ff;">${esc(c.name||'')}</td>
      <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:var(--dim);">${esc(c.channel_type||'')}</td>
      <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:${c.joined?'var(--accent)':'var(--dim)'};">${c.joined?'joined':'pending'}</td>
      <td>${sourceTierSelect(c)}</td>
      <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:var(--accent2);">${(c.message_count||0).toLocaleString()}</td>
      <td><button class="icon-btn" data-url="${esc(c.url||'')}" onclick="event.stopPropagation();muteChannel(this.getAttribute('data-url'),this)" title="Mute/Unmute channel" style="${!c.active?'border-color:var(--red);color:var(--red);':''}">${c.active?'&#128263;':'&#128266;'}</button></td>
    </tr>`).join('');
    wrap.innerHTML=`<table><thead><tr><th>URL</th><th>Name</th><th>Type</th><th>Status</th><th>Source Tier</th><th>Messages</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
    pgEl.innerHTML='';
    return;
  }

  const messages = res.messages || [];
  tgTotal = res.total || 0;
  document.getElementById('tgShown').textContent = messages.length.toLocaleString();
  document.getElementById('tgTotal').textContent = tgTotal.toLocaleString();

  if(!messages.length){
    wrap.innerHTML=`<div class="empty"><div class="empty-icon">💬</div>${tgView==='leaks'?'No leak hits yet':'No messages yet'}. Run telegram_monitor.py to start.</div>`;
    pgEl.innerHTML=''; return;
  }

  const rows = messages.map(m=>{
    const ts = m.timestamp ? new Date(m.timestamp*1000).toLocaleString() : '';
    const confCol = m.confidence>=70?'var(--danger)':m.confidence>=45?'var(--amber)':'var(--text-3)';
 const fullText = esc(m.text||'');
     const isTruncated = fullText.length > 300;
     const preview = isTruncated ? fullText.substring(0,300) : fullText;
     const msgId = 'tgmsg-'+m.id;
     const chanHandle = esc(m.channel_name||'').replace('https://t.me/','');
     const sevClass = m.confidence>=70?'sev-critical':m.confidence>=45?'sev-high':'sev-medium';
     return`<tr style="vertical-align:top;">
       <td style="font-size:12px;color:var(--text-2);white-space:nowrap;padding-top:14px;width:140px;">
         ${chanHandle}<div style="margin-top:6px;">${sourceTierBadge(m.source_tier)}</div>
       </td>
       <td style="font-size:13px;color:var(--text);line-height:1.6;padding:12px 14px;max-width:500px;">
         <span id="${msgId}-short">${preview}${isTruncated?'<span style="color:var(--text-3);">…</span>':''}</span>
         ${isTruncated?`<span id="${msgId}-full" style="display:none;">${fullText}</span>
         <br><button onclick="toggleTgMsg('${msgId}')" id="${msgId}-btn" style="margin-top:6px;background:none;border:none;color:var(--accent);font-size:11px;cursor:pointer;padding:0;font-family:inherit;">▼ Show more</button>`:''}
         ${tgIntelBadges(m)}
         ${tgIntelDetails(m)}
       </td>
      <td style="padding-top:14px;white-space:nowrap;">
        ${m.has_leak?`<span class="sev ${sevClass}">${m.confidence}%</span>`:'<span style="color:var(--text-3);font-size:12px;">—</span>'}
      </td>
      <td style="font-size:11px;color:var(--text-3);white-space:nowrap;padding-top:14px;">${ts}</td>
    </tr>`;
  }).join('');
  wrap.innerHTML=`<table class="data-table"><thead><tr><th>Channel</th><th>Message</th><th>Confidence</th><th>Time</th></tr></thead><tbody>${rows}</tbody></table>`;

  const pages = Math.ceil(tgTotal/50);
  if(pages>1){
    let b=`<button class="pg" onclick="goTgPage(${tgPage-1})" ${tgPage===1?'disabled':''}>prev</button>`;
    for(let i=Math.max(1,tgPage-2);i<=Math.min(pages,tgPage+2);i++)
      b+=`<button class="pg ${i===tgPage?'active':''}" onclick="goTgPage(${i})">${i}</button>`;
    b+=`<button class="pg" onclick="goTgPage(${tgPage+1})" ${tgPage===pages?'disabled':''}>next</button>`;
    pgEl.innerHTML=`<div class="pagination">${b}</div>`;
  }else{pgEl.innerHTML='';}
}

async function goTgPage(p){const pages=Math.ceil(tgTotal/50);if(p<1||p>pages)return;tgPage=p;loadTelegram();}

// ── Intel Dashboard ───────────────────────────────────────────────────────────
let _intelDashData = null;
let _intelSubTab = 'overview';

function intelList(title, rows, render, empty='No data yet'){
  const body = rows && rows.length ? rows.map(render).join('') : `<div style="padding:14px;color:var(--text-3);font-size:12px;">${empty}</div>`;
  return `<div style="background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:12px;overflow:hidden;min-width:260px;">
    <div style="padding:12px 14px;border-bottom:1px solid var(--border);font-size:12px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.06em;">${title}</div>
    <div>${body}</div>
  </div>`;
}

function intelRow(left, right='', sub=''){
  return `<div style="display:flex;justify-content:space-between;gap:12px;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.05);font-size:12px;">
    <div style="min-width:0;"><div style="color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:520px;">${left}</div>${sub?`<div style="color:var(--text-3);font-size:11px;margin-top:3px;">${sub}</div>`:''}</div>
    <div style="color:var(--accent-hi);font-family:Share Tech Mono,monospace;white-space:nowrap;">${right}</div>
  </div>`;
}

function intelMetric(label, value, sub){
  return `<div style="background:rgba(255,255,255,.035);border:1px solid var(--border);border-radius:12px;padding:14px;">
    <div style="font-size:11px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">${label}</div>
    <div style="font-size:24px;color:var(--text);font-family:Share Tech Mono,monospace;margin-top:6px;">${Number(value||0).toLocaleString()}</div>
    <div style="font-size:11px;color:var(--text-3);margin-top:3px;">${sub}</div>
  </div>`;
}

function showIntelSubTab(tab){
  _intelSubTab = tab || 'overview';
  const ids = {overview:'intelTabOverview', actors:'intelTabActors', iocs:'intelTabIocs', channels:'intelTabChannels', recent:'intelTabRecent'};
  Object.entries(ids).forEach(([key,id]) => {
    const el = document.getElementById(id);
    if(el) el.classList.toggle('active', key === _intelSubTab);
  });
  if(_intelDashData) renderIntelDashboard();
}

async function loadIntelDashboard(force=false){
  const days = document.getElementById('intelDays')?.value || '7';
  const wrap = document.getElementById('intelDashWrap');
  if(!wrap) return;
  wrap.innerHTML = '<div class="empty"><div class="empty-icon">&#8987;</div>Loading intel dashboard...</div>';
  const data = await fetch(`/api/intel/dashboard?days=${encodeURIComponent(days)}${force?'&force=1':''}`).then(r=>r.json()).catch(()=>null);
  if(!data){
    wrap.innerHTML = '<div class="empty"><div class="empty-icon">&#9888;</div>Could not load intel dashboard.</div>';
    return;
  }
  _intelDashData = data;
  const s = data.summary || {};
  const iocsEl = document.getElementById('intelIocs');
  const tagsEl = document.getElementById('intelTags');
  const dupesEl = document.getElementById('intelDupes');
  const queueEl = document.getElementById('intelQueue');
  if(iocsEl) iocsEl.textContent = (s.iocs||0).toLocaleString();
  if(tagsEl) tagsEl.textContent = (s.tags||0).toLocaleString();
  if(dupesEl) dupesEl.textContent = (s.duplicates||0).toLocaleString();
  if(queueEl) queueEl.textContent = (s.queue||0).toLocaleString();
  renderIntelDashboard();
}

function renderIntelDashboard(){
  const data = _intelDashData || {};
  const wrap = document.getElementById('intelDashWrap');
  if(!wrap) return;
  const s = data.summary || {};

  const summary = `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;">
    ${intelMetric('Messages',(s.messages||0),'Total Telegram messages')}
    ${intelMetric('Processed',(s.processed||0),'Enriched by worker')}
    ${intelMetric('Queue',(s.queue||0),'Waiting for enrichment')}
    ${intelMetric('Duplicates',(s.duplicates||0),'Reposts/mirrors detected')}
    ${intelMetric('IOCs',(s.iocs||0),'Unique indicators')}
    ${intelMetric('Tags',(s.tags||0),'Actor/TTP/threat tags')}
  </div>`;

  const actors = intelList('Top Actors', data.top_actors||[], r=>intelRow(esc(r.name), `${r.count||0}`, `avg confidence ${r.avg_conf||0}%`));
  const threats = intelList('Threat Types', data.threat_types||[], r=>intelRow(esc(r.name), `${r.count||0}`, `avg confidence ${r.avg_conf||0}%`));
  const ttps = intelList('Top TTPs', data.top_ttps||[], r=>intelRow(esc(r.name), `${r.count||0}`, `avg confidence ${r.avg_conf||0}%`));
  const cves = intelList('Trending CVEs', data.top_cves||[], r=>intelRow(esc(r.value), `${r.times_seen||0}x`, `quality ${r.quality||0}`));
  const iocs = intelList('Hot IOCs', data.hot_iocs||[], r=>intelRow(`<span style="color:var(--text-3);">${esc(r.type)}</span> ${esc(r.value)}`, `${r.times_seen||0}x`, `quality ${r.quality||0}`));
  const channels = intelList('Top Telegram Sources', data.top_channels||[], r=>intelRow(esc(r.name||r.channel_id||'unknown'), `${r.messages||0}`, `${sourceTierBadge(r.source_tier)} leak hits: ${r.leaks||0}`));

  const recent = data.recent_messages && data.recent_messages.length ? data.recent_messages.map(m=>{
    const t = m.timestamp ? new Date(m.timestamp*1000).toLocaleString() : '';
    const txt = esc(m.text||'').slice(0,320);
    return `<div style="padding:12px 14px;border-bottom:1px solid rgba(255,255,255,.06);">
      <div style="display:flex;justify-content:space-between;gap:10px;margin-bottom:6px;">
        <div style="font-size:12px;color:var(--accent-hi);">${esc(m.channel_name||'unknown')}</div>
        <div style="font-size:11px;color:var(--text-3);white-space:nowrap;">${t}</div>
      </div>
      <div style="font-size:12px;color:var(--text);line-height:1.5;">${txt}${(m.text||'').length>320?'&hellip;':''}</div>
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">${m.confidence?`<span class="tag-pill">confidence ${m.confidence}%</span>`:''}${tgIntelBadges(m)}</div>
    </div>`;
  }).join('') : '<div style="padding:14px;color:var(--text-3);font-size:12px;">No recent high-confidence messages.</div>';

  if(_intelSubTab === 'actors'){
    wrap.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;">${actors}${threats}${ttps}</div>`;
  } else if(_intelSubTab === 'iocs'){
    wrap.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;">${cves}${iocs}</div>`;
  } else if(_intelSubTab === 'channels'){
    wrap.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;">${channels}</div>`;
  } else if(_intelSubTab === 'recent'){
    wrap.innerHTML = `<div style="background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <div style="padding:12px 14px;border-bottom:1px solid var(--border);font-size:12px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.06em;">Recent High-Confidence Telegram Messages</div>
      ${recent}
    </div>`;
  } else {
    wrap.innerHTML = `${summary}<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;margin-top:14px;">${actors}${threats}${cves}${channels}</div>`;
  }
}

// ── Init ───────────────────────────────────────────────────────────────────────
(async function init(){
  const st=await fetch('/api/status').then(r=>r.json()).catch(()=>null);
  if(st){
    if(document.getElementById('hLeaks')) document.getElementById('hLeaks').textContent=(st.leaks||0).toLocaleString();
    if(document.getElementById('hTgMsg')) document.getElementById('hTgMsg').textContent=(st.tg_messages||0).toLocaleString();
    if(document.getElementById('hTgLeak')) document.getElementById('hTgLeak').textContent=(st.tg_leaks||0).toLocaleString();
  }
  await updateBookmarkCount();

  // Check if we landed on /group/{name} — open that group directly
  const groupMatch = window.location.pathname.match(/^\/group\/(.+)$/);
  if (groupMatch) {
    const groupName = decodeURIComponent(groupMatch[1]);
    await setTab('ransomware');
    startPolling();
    await rwOpenDetail(groupName);
  } else {
    setTab('leaks');
    startPolling();
  }

  if(st&&st.status==='running'){
    document.getElementById('btnStart').disabled=true;
    if(document.getElementById('btnStop'))document.getElementById('btnStop').disabled=false;
    document.getElementById('liveInd').style.display='';
    addLog('Crawl already running — reconnected.','g');
  }else{
    addLog(`Database ready. ${(st&&st.total)||0} clean sites.`,'b');
  }

  // Handle browser back/forward through group pages
  window.addEventListener('popstate', function(e) {
    const m = window.location.pathname.match(/^\/group\/(.+)$/);
    if (m) {
      const name = decodeURIComponent(m[1]);
      setTab('ransomware').then(() => rwOpenDetail(name));
    } else {
      if (_rwDetail) { _rwDetail = null; renderRwGrid(_rwCache || []); }
    }
  });
})();


















// ── Ransomware Groups tab (ransomware.live API) ──────────────────────────────
let _rwCache   = null;
let _rwDetail  = null;
let _rwVictims = [];

function rwVictimNum(g) {
  const raw = g?.victims ?? g?.total_victims ?? g?.victim_count ?? 0;
  const n = Number(String(raw).replace(/[^0-9.-]/g, ''));
  return Number.isFinite(n) ? n : 0;
}

function rwNormalizeStatus(g) {
  const explicit = (g?.status ?? g?.active_status ?? g?.state ?? '').toString().trim();
  if (explicit) {
    const sl = explicit.toLowerCase();
    if (['active','up','online','running','live','1','true'].includes(sl)) return 'Active';
    if (['inactive','down','offline','retired','closed','dead','0','false'].includes(sl)) return 'Inactive';
    return explicit.charAt(0).toUpperCase() + explicit.slice(1);
  }
  // ransomware.live /groups exposes victims as the number of active victims.
  // If no explicit status is returned, use that count as the safest status signal.
  return rwVictimNum(g) > 0 ? 'Active' : 'Inactive';
}

async function loadRansomware(force=false) {
  if (_rwCache && !force) { renderRwGrid(_rwCache); return; }
  const el = document.getElementById('rwContent');
  el.innerHTML = '<div class="empty"><div class="empty-icon">⏳</div>Loading from ransomware.live…</div>';
  try {
    const data = await fetch('/api/ransomware/groups').then(r => r.json());
    if (data.error) {
      el.innerHTML = `<div class="empty"><div class="empty-icon">⚠️</div>${esc(data.error)}</div>`;
      return;
    }
    const raw = Array.isArray(data) ? data : (data.groups || Object.values(data));
    // Normalise ALL field names once here — everything else just uses these
    _rwCache = raw.map(g => ({
      ...g,
      name:        g.name        || g.group       || '',
      status:      rwNormalizeStatus(g),
      victims:     rwVictimNum(g),
      firstseen:   g.firstseen   || g.first_seen  || '',
      lastseen:    g.lastseen    || g.last_seen    || '',
      description: g.description || g.summary     || '',
    }));
    updateRwStats(_rwCache);
    renderRwGrid(_rwCache);
  } catch(e) {
    el.innerHTML = `<div class="empty"><div class="empty-icon">⚠️</div>Failed: ${esc(String(e))}</div>`;
  }
}

function updateRwStats(groups) {
  document.getElementById('rwGangCount').textContent   = groups.length;
  const active = groups.filter(g => rwNormalizeStatus(g).toLowerCase() === 'active').length;
  document.getElementById('rwActiveCount').textContent  = active;
  const totalVictims = groups.reduce((a,g) => a + (typeof g.victims === 'number' ? g.victims : 0), 0);
  document.getElementById('rwVictimCount').textContent = totalVictims.toLocaleString();
  const badge = document.getElementById('rwBadge');
  if (badge && totalVictims > 0) { badge.textContent = totalVictims.toLocaleString(); badge.style.display = ''; }
}

function filterRansomware() {
  if (!_rwCache) return;
  if (_rwDetail) { renderRwDetail(_rwDetail); return; }
  renderRwGrid(_rwCache);
}

function setRwTab(tab) {
  // sub-tabs are no longer used in live-API mode — just refresh
  renderRwGrid(_rwCache || []);
}

function renderRwGrid(groups) {
  if (_rwDetail) return;
  const q      = (document.getElementById('rwQ')?.value || '').toLowerCase();
  const el     = document.getElementById('rwContent');
  const status = document.getElementById('rwStatus')?.value || '';

  const filtered = (groups || []).filter(g => {
    const name = (g.name||'').toLowerCase();
    const st   = rwNormalizeStatus(g);
    return (!q || name.includes(q)) && (!status || st === status);
  });

  document.getElementById('rwShown').textContent = filtered.length + ' groups';

  if (!filtered.length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">☠️</div>No groups found.</div>';
    return;
  }

  const statusColor = s => {
    const sl = (s||'').toLowerCase();
    return sl==='active' ? 'var(--red)' : sl==='inactive' ? 'var(--text-3)' : 'var(--amber)';
  };
  const statusDot = s => {
    const sl = (s||'').toLowerCase();
    return sl==='active' ? '🔴' : sl==='inactive' ? '⚫' : '🟡';
  };

  const cards = filtered.map(g => {
    const name    = g.name || '?';
    const status2 = rwNormalizeStatus(g);
    const victims = g.victims != null ? g.victims : '?';
    const since   = (g.firstseen||'').split('T')[0];
    const last    = (g.lastseen||'').split('T')[0];
    const desc    = (g.description||'').slice(0,100);

    return `<div onclick="rwOpenDetail('${jsEsc(name)}')"
      style="background:var(--surface);border:1px solid var(--border);border-top:2px solid ${statusColor(status2)};
             border-radius:10px;padding:14px 16px;cursor:pointer;
             transition:border-color 180ms var(--ease-out),background 180ms;"
      onmouseover="this.style.background='var(--surface2)'"
      onmouseout="this.style.background='var(--surface)'">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:6px;">
        <div style="font-weight:600;font-size:13px;color:var(--text);font-family:'JetBrains Mono',monospace;
                    text-transform:uppercase;letter-spacing:.04em;word-break:break-word;">${esc(name)}</div>
        <div style="font-size:10px;color:${statusColor(status2)};white-space:nowrap;flex-shrink:0;">
          ${statusDot(status2)} ${esc(status2)}
        </div>
      </div>
      ${desc ? `<div style="font-size:11px;color:var(--text-3);line-height:1.5;margin-bottom:10px;
                              display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">
                  ${esc(desc)}</div>` : ''}
      <div style="display:flex;gap:12px;font-size:11px;font-family:'JetBrains Mono',monospace;
                  border-top:1px solid var(--border);padding-top:8px;margin-top:4px;">
        <div><span style="color:var(--text-3);">victims </span>
             <span style="color:var(--red);font-weight:600;">${esc(String(victims))}</span></div>
        ${since ? `<div><span style="color:var(--text-3);">since </span>
                        <span style="color:var(--text-2);">${esc(since)}</span></div>` : ''}
        ${last  ? `<div><span style="color:var(--text-3);">last </span>
                        <span style="color:var(--text-2);">${esc(last)}</span></div>`  : ''}
      </div>
    </div>`;
  }).join('');

  el.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));
                               gap:12px;padding:16px;align-content:start;">${cards}</div>`;
}

// ── Group detail page ─────────────────────────────────────────────────────────
async function rwOpenDetail(name) {
  _rwDetail = name;
  // Update URL so this page is bookmarkable / shareable
  history.pushState({group: name}, '', '/group/' + encodeURIComponent(name.toLowerCase().trim()));
  document.title = name.toUpperCase() + ' — Dark Crawler';

  const el = document.getElementById('rwContent');
  el.innerHTML = `<div style="padding:16px;"><button class="btn" onclick="rwCloseDetail()" style="margin-bottom:16px;">← Back</button>
    <div style="color:var(--text-3);font-family:'JetBrains Mono',monospace;font-size:.8rem;">Loading ${esc(name)}…</div></div>`;

  try {
    const d = await fetch(`/api/ransomware/group?name=${encodeURIComponent(name.toLowerCase().trim())}`).then(r => r.json());
    renderRwDetail(d);
  } catch(e) {
    el.innerHTML = `<div style="padding:16px;"><button class="btn" onclick="rwCloseDetail()">← Back</button>
      <div style="color:var(--red);margin-top:12px;">Error: ${esc(String(e))}</div></div>`;
  }
}

function renderRwDetail(d) {
  const el = document.getElementById('rwContent');

  // /group/{name} returns the group object directly (or array-wrapped)
  const _d = Array.isArray(d) ? d[0] : d;

  const status   = rwNormalizeStatus(_d);
  const victims  = rwVictimNum(_d);
  const since    = (_d.firstseen || _d.first_seen || '').split('T')[0];
  const last     = (_d.lastseen  || _d.last_seen  || '').split('T')[0];
  const locations    = _d.locations    || [];
  const ttps         = _d.ttps         || [];
  const vulns        = _d.vulnerabilities || [];
  const tools        = _d.tools        || [];

  const statusColor = s => {
    const sl = (s||'').toLowerCase();
    return sl==='active' ? 'var(--red)' : sl==='inactive' ? 'var(--text-3)' : 'var(--amber)';
  };

  const pill = (label, val, col='var(--text-2)') =>
    `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px 14px;min-width:100px;">
       <div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px;">${label}</div>
       <div style="font-size:16px;font-weight:600;color:${col};font-family:'JetBrains Mono',monospace;">${esc(String(val))}</div>
     </div>`;

  const tag = (t, bc='var(--border2)', tc='var(--text-2)') =>
    `<span style="background:var(--surface2);border:1px solid ${bc};color:${tc};
                  padding:3px 10px;border-radius:4px;font-size:11px;
                  font-family:'JetBrains Mono',monospace;white-space:nowrap;">${esc(String(t))}</span>`;

  const section = (title, body) =>
    `<div style="margin-bottom:24px;">
       <div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;
                   color:var(--text-3);margin-bottom:10px;padding-bottom:6px;
                   border-bottom:1px solid var(--border);">${title}</div>
       ${body}
     </div>`;

  // ── Sticky header bar ──
  let html = `
  <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;
              background:var(--surface);border-bottom:1px solid var(--border);
              position:sticky;top:0;z-index:10;flex-wrap:wrap;">
    <button class="btn" onclick="rwCloseDetail()" style="font-size:11px;padding:4px 10px;">← Back to Groups</button>
    <div style="font-size:18px;font-weight:700;font-family:'JetBrains Mono',monospace;
                text-transform:uppercase;letter-spacing:.06em;color:var(--text);flex:1;">${esc(_d.name||'')}</div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <span style="font-size:12px;padding:4px 12px;border-radius:20px;
                   border:1px solid ${statusColor(status)};color:${statusColor(status)};">${esc(status)}</span>
      ${_d.has_negotiations ? '<span style="font-size:11px;padding:3px 10px;border-radius:20px;background:rgba(59,130,246,.1);border:1px solid var(--accent);color:var(--accent-hi);">💬 Chat Logs</span>' : ''}
      ${_d.has_ransomnote   ? '<span style="font-size:11px;padding:3px 10px;border-radius:20px;background:rgba(245,158,11,.1);border:1px solid var(--amber);color:var(--amber);">📄 Ransom Notes</span>' : ''}
      <button class="btn" onclick="loadRansomware(true)" style="font-size:11px;padding:4px 10px;" title="Refresh from API">↻</button>
    </div>
  </div>

  <div style="padding:20px;">

  <!-- Stat pills row -->
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px;">
    ${pill('Total Victims', typeof victims==='number' ? victims.toLocaleString() : victims, 'var(--red)')}
    ${since ? pill('First Seen', since) : ''}
    ${last  ? pill('Last Active', last) : ''}
    ${_d.negotiation_count ? pill('Negotiations', _d.negotiation_count, 'var(--amber)') : ''}
    ${_d.ransomnotes_count  ? pill('Ransom Notes',  _d.ransomnotes_count,  'var(--amber)') : ''}
  </div>`;

  // ── Description ──
  if (_d.description) {
    html += section('Description',
      `<div style="font-size:13px;color:var(--text-2);line-height:1.75;max-width:860px;">${esc(_d.description)}</div>`);
  }

  // ── Leak site URLs (locations array) ──
  // Each location object has: fqdn, title, available, url, screenshot_url, ...
  if (locations.length) {
    const linkRows = locations.map(loc => {
      const url   = loc.fqdn || loc.url || '';
      const title = loc.title || '';
      const up    = loc.available;
      const isTor = url.includes('.onion');
      const upBadge = up===true  ? '<span style="color:var(--green);font-size:10px;margin-left:6px;">● online</span>'
                    : up===false ? '<span style="color:var(--red);font-size:10px;margin-left:6px;">● offline</span>'
                    : '';
      return `<div style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04);">
        <span style="font-size:10px;padding:1px 6px;border-radius:3px;flex-shrink:0;
                     border:1px solid ${isTor?'var(--accent)':'var(--accent2)'};
                     color:${isTor?'var(--accent)':'var(--accent2)'};">${isTor?'TOR':'WEB'}</span>
        <div style="flex:1;min-width:0;">
          <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent-hi);
                      overflow-wrap:break-word;word-break:break-all;">${esc(url)}${upBadge}</div>
          ${title ? `<div style="font-size:11px;color:var(--text-3);margin-top:2px;">${esc(title)}</div>` : ''}
        </div>
      </div>`;
    }).join('');
    html += section(`Leak Site URLs (${locations.length})`,
      `<div style="display:flex;flex-direction:column;">${linkRows}</div>`);
  }

  // ── MITRE ATT&CK TTPs ──
  // Each ttp object has: tid (e.g. "T1486"), tactic, technique
  if (ttps.length) {
    const ttpRows = ttps.map(t => {
      const tid  = t.tid || t.id || t.technique_id || '';
      const name = t.technique || t.name || '';
      const tact = t.tactic || '';
      return `<div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.04);">
        <span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent);
                     flex-shrink:0;min-width:80px;">${esc(tid)}</span>
        <div>
          ${name ? `<div style="font-size:12px;color:var(--text);">${esc(name)}</div>` : ''}
          ${tact ? `<div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.05em;margin-top:2px;">${esc(tact)}</div>` : ''}
        </div>
      </div>`;
    }).join('');
    html += section(`MITRE ATT&CK TTPs (${ttps.length})`, ttpRows);
  }

  // ── CVEs / Vulnerabilities ──
  // Each vuln object has: CVE, CVSS (score), description
  if (vulns.length) {
    const vulnRows = vulns.map(v => {
      const id   = v.CVE || v.cve_id || v.id || '';
      const cvss = v.CVSS || v.cvss_score || '';
      const desc = v.description || '';
      const sevColor = cvss >= 9 ? 'var(--red)' : cvss >= 7 ? 'var(--amber)' : cvss >= 4 ? 'var(--accent-hi)' : 'var(--text-3)';
      return `<div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.04);">
        <a href="https://nvd.nist.gov/vuln/detail/${esc(id)}" target="_blank"
           style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--amber);
                  flex-shrink:0;min-width:140px;text-decoration:none;">${esc(id)} ↗</a>
        ${cvss ? `<span style="font-size:11px;font-family:'JetBrains Mono',monospace;color:${sevColor};flex-shrink:0;">CVSS ${cvss}</span>` : ''}
        ${desc ? `<span style="font-size:11px;color:var(--text-2);">${esc(String(desc).substring(0,120))}${String(desc).length>120?'…':''}</span>` : ''}
      </div>`;
    }).join('');
    html += section(`Exploited CVEs (${vulns.length})`, vulnRows);
  }

  // ── Tools & Malware ──
  // Each tool object has: tool (name string)
  if (tools.length) {
    const toolTags = tools.map(t => {
      const name = t.tool || t.name || (typeof t==='string' ? t : '');
      return name ? tag(name, 'rgba(59,130,246,.4)', 'var(--accent-hi)') : '';
    }).join(' ');
    html += section(`Tools & Malware Families (${tools.length})`,
      `<div style="display:flex;flex-wrap:wrap;gap:6px;">${toolTags}</div>`);
  }

  html += section('Telegram Correlation', `<div id="rwCorrelation" style="font-size:12px;color:var(--text-3);">Loading Telegram correlation...</div>`);

  html += section('Victim Timeline Correlation', `<div id="rwVictimTimeline" style="font-size:12px;color:var(--text-3);">Checking ransomware.live victim fields...</div>`);

  html += '</div>'; // close padding div
  el.innerHTML = html;
  loadRwCorrelation(_d.name || _rwDetail || '');
  renderRwVictimTimelineBox(_d.name || _rwDetail || '', _d);
}


async function loadRwCorrelation(name){
  const el = document.getElementById('rwCorrelation');
  if(!el || !name) return;
  const data = await fetch('/api/ransomware/correlation?name='+encodeURIComponent(name))
    .then(r=>r.json()).catch(e=>({error:String(e)}));
  if(!data || data.error){
    el.innerHTML = `<div style="color:var(--amber);">No correlation data available${data&&data.error?': '+esc(data.error):''}</div>`;
    return;
  }
  const lastSeen = data.last_seen ? new Date(data.last_seen*1000).toLocaleString() : 'Never';
  const metric = (label,val,color='var(--accent-hi)') => `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:9px 12px;min-width:110px;"><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px;">${label}</div><div style="font-family:JetBrains Mono,monospace;font-size:16px;font-weight:700;color:${color};">${esc(String(val))}</div></div>`;
  const tinyTable = (headers, rows) => {
    if(!rows || !rows.length) return '<div style="color:var(--text-3);font-size:12px;">No matches yet.</div>';
    return `<table class="data-table" style="font-size:12px;"><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
  };
  const channels = tinyTable(['Channel','Tier','Mentions','Last Seen'], (data.top_channels||[]).map(c=>`
    <tr><td>${esc(c.channel_name||'unknown')}</td><td>${esc(c.source_tier||'unknown')}</td><td>${c.mentions||0}</td><td>${c.last_seen?new Date(c.last_seen*1000).toLocaleString():''}</td></tr>`));
  const ttps = (data.top_ttps||[]).length ? `<div style="display:flex;gap:6px;flex-wrap:wrap;">${data.top_ttps.map(t=>`<span class="mini-badge intel-ttp">${esc(t.tag_value)} <span style="opacity:.65">${t.mentions}x</span></span>`).join('')}</div>` : '<div style="color:var(--text-3);font-size:12px;">No TTP tags yet.</div>';
  const cves = (data.related_cves||[]).length ? `<div style="display:flex;gap:6px;flex-wrap:wrap;">${data.related_cves.map(c=>`<span class="mini-badge intel-ioc">${esc(c.cve)} <span style="opacity:.65">${c.mentions}x</span></span>`).join('')}</div>` : '<div style="color:var(--text-3);font-size:12px;">No CVEs tied to this group yet.</div>';
  const iocs = (data.related_iocs||[]).length ? `<div style="display:flex;gap:6px;flex-wrap:wrap;">${data.related_iocs.map(i=>`<span class="mini-badge intel-ioc" title="${esc(i.value)}">${esc(i.type)}:${esc(String(i.value).slice(0,42))}${String(i.value).length>42?'...':''} <span style="opacity:.65">${i.mentions}x</span></span>`).join('')}</div>` : '<div style="color:var(--text-3);font-size:12px;">No related high-signal IOCs yet.</div>';
  const recent = (data.recent_messages||[]).length ? data.recent_messages.map(m=>{
    const ts = m.timestamp ? new Date(m.timestamp*1000).toLocaleString() : '';
    const text = esc((m.text||'').slice(0,260));
    return `<div style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,.05);">
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:5px;"><span style="color:var(--accent-hi);font-family:JetBrains Mono,monospace;font-size:11px;">${esc(m.channel_name||'unknown')}</span><span style="color:var(--text-3);font-size:11px;">${ts}</span>${m.confidence?`<span class="mini-badge intel-threat">${m.confidence}%</span>`:''}</div>
      <div style="color:var(--text-2);font-size:12px;line-height:1.55;">${text}${(m.text||'').length>260?'...':''}</div>
      ${tgIntelBadges(m)}
    </div>`;
  }).join('') : '<div style="color:var(--text-3);font-size:12px;">No recent Telegram messages found for this group.</div>';

  el.innerHTML = `
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;">
      ${metric('Mentions', (data.mentions||0).toLocaleString(), 'var(--red)')}
      ${metric('24h', (data.mentions_24h||0).toLocaleString(), 'var(--amber)')}
      ${metric('7d', (data.mentions_7d||0).toLocaleString(), 'var(--accent-hi)')}
      ${metric('Last Seen', lastSeen, 'var(--text-2)')}
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:16px;">
      <div><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">Top Telegram Channels</div>${channels}</div>
      <div><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">Top TTPs</div>${ttps}<div style="height:12px"></div><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">Related CVEs</div>${cves}</div>
    </div>
    <div style="margin-bottom:16px;"><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">Related IOCs</div>${iocs}</div>
    <div><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">Recent Telegram Messages</div>${recent}</div>
  `;
}


function rwCandidateVictimArrays(d){
  const arrays = [];
  const keys = ['posts','victims_list','recent_victims','group_posts','victim_posts','victims'];
  for(const k of keys){ if(Array.isArray(d && d[k])) arrays.push(d[k]); }
  if(d && d.data){ for(const k of keys){ if(Array.isArray(d.data[k])) arrays.push(d.data[k]); } }
  return arrays;
}

function rwExtractVictims(d){
  const seen = new Set();
  const out = [];
  const arrays = rwCandidateVictimArrays(d);
  for(const arr of arrays){
    for(const item of arr){
      if(!item || typeof item !== 'object') continue;
      const name = item.victim || item.victim_name || item.company || item.name || item.post_title || item.title || item.target || '';
      if(!name || typeof name !== 'string') continue;
      const clean = name.trim();
      if(clean.length < 3) continue;
      const domain = item.domain || item.website || item.url || item.fqdn || '';
      const country = item.country || item.country_code || item.location || '';
      const sector = item.sector || item.industry || item.activity || '';
      const publishedRaw = item.published || item.published_at || item.discovered || item.discovered_at || item.date || item.created_at || item.updated_at || '';
      let publishedTs = 0;
      if(typeof publishedRaw === 'number') publishedTs = publishedRaw;
      else if(publishedRaw){
        const dt = Date.parse(String(publishedRaw));
        if(!Number.isNaN(dt)) publishedTs = Math.floor(dt/1000);
      }
      const key = (clean+'|'+domain).toLowerCase();
      if(seen.has(key)) continue;
      seen.add(key);
      out.push({name:clean, domain:String(domain||''), country:String(country||''), sector:String(sector||''), published_ts:publishedTs});
      if(out.length >= 25) return out;
    }
  }
  return out;
}

function renderRwVictimTimelineBox(groupName, d){
  const el = document.getElementById('rwVictimTimeline');
  if(!el) return;
  _rwVictims = rwExtractVictims(d);
  if(!_rwVictims.length){
    el.innerHTML = `<div style="color:var(--text-3);line-height:1.6;">No victim list was returned by this ransomware.live group detail response. If the API provides victims from another endpoint later, this section can use it without changing the Telegram worker.</div>`;
    return;
  }
  const rows = _rwVictims.slice(0,15).map((v,i)=>{
    const date = v.published_ts ? new Date(v.published_ts*1000).toLocaleDateString() : '';
    return `<tr>
      <td style="font-weight:600;color:var(--text);">${esc(v.name)}</td>
      <td>${esc(v.domain||'')}</td>
      <td>${esc(v.country||'')}</td>
      <td>${esc(v.sector||'')}</td>
      <td>${esc(date)}</td>
      <td><button class="btn rw-victim-btn" data-index="${i}" style="font-size:11px;padding:3px 8px;">Check Telegram</button></td>
    </tr>`;
  }).join('');
  el.innerHTML = `
    <div style="margin-bottom:10px;color:var(--text-3);line-height:1.6;">Found ${_rwVictims.length} victim records from ransomware.live for this group. Pick one to search Telegram before/after the ransomware post.</div>
    <table class="data-table" style="font-size:12px;margin-bottom:14px;">
      <thead><tr><th>Victim</th><th>Domain</th><th>Country</th><th>Sector</th><th>Published</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div id="rwVictimTimelineResult"></div>
  `;
  el.querySelectorAll('.rw-victim-btn').forEach(btn=>{
    btn.addEventListener('click',()=>{
      const idx = parseInt(btn.getAttribute('data-index')||'0',10);
      rwLoadVictimTimeline(groupName, _rwVictims[idx]);
    });
  });
}

async function rwLoadVictimTimeline(groupName, victim){
  const el = document.getElementById('rwVictimTimelineResult');
  if(!el || !victim) return;
  el.innerHTML = `<div style="color:var(--text-3);font-size:12px;">Searching Telegram for ${esc(victim.name)}...</div>`;
  const qs = new URLSearchParams({
    group: groupName || '',
    victim: victim.name || '',
    domain: victim.domain || '',
    published: String(victim.published_ts || 0)
  });
  const data = await fetch('/api/ransomware/victim_timeline?'+qs.toString())
    .then(r=>r.json()).catch(e=>({error:String(e)}));
  if(!data || data.error){
    el.innerHTML = `<div style="color:var(--amber);">No timeline data available${data&&data.error?': '+esc(data.error):''}</div>`;
    return;
  }
  const metric = (label,val,color='var(--accent-hi)') => `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:9px 12px;min-width:110px;"><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px;">${label}</div><div style="font-family:JetBrains Mono,monospace;font-size:16px;font-weight:700;color:${color};">${esc(String(val))}</div></div>`;
  const published = data.published_ts ? new Date(data.published_ts*1000).toLocaleString() : 'Unknown';
  const channels = (data.top_channels||[]).length ? `<table class="data-table" style="font-size:12px;"><thead><tr><th>Channel</th><th>Tier</th><th>Mentions</th><th>Last Seen</th></tr></thead><tbody>${data.top_channels.map(c=>`<tr><td>${esc(c.channel_name||'unknown')}</td><td>${esc(c.source_tier||'unknown')}</td><td>${c.mentions||0}</td><td>${c.last_seen?new Date(c.last_seen*1000).toLocaleString():''}</td></tr>`).join('')}</tbody></table>` : '<div style="color:var(--text-3);font-size:12px;">No Telegram channel matches.</div>';
  const cves = (data.related_cves||[]).length ? `<div style="display:flex;gap:6px;flex-wrap:wrap;">${data.related_cves.map(c=>`<span class="mini-badge intel-ioc">${esc(c.cve)} <span style="opacity:.65">${c.mentions}x</span></span>`).join('')}</div>` : '<div style="color:var(--text-3);font-size:12px;">No CVEs found in matched messages.</div>';
  const iocs = (data.related_iocs||[]).length ? `<div style="display:flex;gap:6px;flex-wrap:wrap;">${data.related_iocs.map(i=>`<span class="mini-badge intel-ioc" title="${esc(i.value)}">${esc(i.type)}:${esc(String(i.value).slice(0,42))}${String(i.value).length>42?'...':''} <span style="opacity:.65">${i.mentions}x</span></span>`).join('')}</div>` : '<div style="color:var(--text-3);font-size:12px;">No high-signal IOCs found in matched messages.</div>';
  const timeline = (data.timeline||[]).length ? data.timeline.map(m=>{
    const ts = m.timestamp ? new Date(m.timestamp*1000).toLocaleString() : '';
    const rel = m.timeline_relation === 'before' ? `Before post${m.days_from_publish!=null?` (${m.days_from_publish}d)`:''}` : m.timeline_relation === 'after' ? `After post${m.days_from_publish!=null?` (${m.days_from_publish}d)`:''}` : 'Seen';
    const relColor = m.timeline_relation === 'before' ? 'var(--amber)' : m.timeline_relation === 'after' ? 'var(--accent-hi)' : 'var(--text-3)';
    const text = esc((m.text||'').slice(0,320));
    return `<div style="position:relative;padding:12px 0 12px 18px;border-left:2px solid var(--border);border-bottom:1px solid rgba(255,255,255,.04);">
      <div style="position:absolute;left:-6px;top:17px;width:10px;height:10px;border-radius:999px;background:${relColor};"></div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:5px;">
        <span style="color:${relColor};font-family:JetBrains Mono,monospace;font-size:11px;">${esc(rel)}</span>
        <span style="color:var(--accent-hi);font-family:JetBrains Mono,monospace;font-size:11px;">${esc(m.channel_name||'unknown')}</span>
        <span style="color:var(--text-3);font-size:11px;">${ts}</span>
        ${m.confidence?`<span class="mini-badge intel-threat">${m.confidence}%</span>`:''}
      </div>
      <div style="color:var(--text-2);font-size:12px;line-height:1.55;">${text}${(m.text||'').length>320?'...':''}</div>
      ${tgIntelBadges(m)}
    </div>`;
  }).join('') : '<div style="color:var(--text-3);font-size:12px;">No Telegram messages matched this victim/domain.</div>';
  el.innerHTML = `
    <div style="background:rgba(59,130,246,.04);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:14px;">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
        <div><div style="font-size:15px;font-weight:700;color:var(--text);">${esc(data.victim||victim.name)}</div><div style="font-size:11px;color:var(--text-3);margin-top:3px;">Published: ${esc(published)} ${data.domain?`&nbsp; Domain: ${esc(data.domain)}`:''}</div></div>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
        ${metric('Mentions', (data.mentions||0).toLocaleString(), 'var(--red)')}
        ${metric('Before', (data.before||0).toLocaleString(), 'var(--amber)')}
        ${metric('After', (data.after||0).toLocaleString(), 'var(--accent-hi)')}
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:14px;">
        <div><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">Top Channels</div>${channels}</div>
        <div><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">Related CVEs</div>${cves}<div style="height:12px"></div><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">Related IOCs</div>${iocs}</div>
      </div>
      <div><div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">Timeline</div>${timeline}</div>
    </div>
  `;
}

function rwCloseDetail() {
  _rwDetail = null;
  history.pushState({}, '', '/');
  document.title = 'Dark Crawler';
  renderRwGrid(_rwCache || []);
}


</script>
</body>
</html>
"""

if __name__ == "__main__":
    ensure_db()
    ensure_indexes()
    print("  Dark Crawler")
    print("  ----------------------------")
    print("  http://localhost:" + str(PORT))
    print("  Ctrl+C to stop.\n")
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.allow_reuse_address = True
        try: httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")
            stop_crawler()