"""
server_v2.py — Dark Crawler dashboard backed by SQLite
"""
import http.server, socketserver, threading, subprocess
import json, sys, sqlite3, time, hashlib, re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote_plus

BASE_DIR   = Path(__file__).parent
DB_PATH    = BASE_DIR / "crawler.db"
RESULTS    = BASE_DIR / "results.jsonl"
LEAKS_FILE = BASE_DIR / "leaks.jsonl"
_STATE_FILE= BASE_DIR / ".crawler_state.json"
PORT       = 8765

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
    """)
    con.commit(); con.close()

def ensure_db():
    if not DB_PATH.exists() and RESULTS.exists():
        import migrate_to_db
        migrate_to_db.main()
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
    ''')
    # Auto-queue all clean high-score sites for re-crawl if queue is empty
    # Uses tiered intervals — high-activity categories checked more often
    count = con.execute("SELECT COUNT(*) FROM recrawl_queue").fetchone()[0]
    if count == 0:
        now = int(time.time())
        sites = con.execute(
            "SELECT id,url,category FROM sites WHERE noise=0 AND score>=10 LIMIT 500"
        ).fetchall()
        for s in sites:
            interval_h = RECRAWL_INTERVALS.get(s['category'], 48)
            con.execute(
                "INSERT OR IGNORE INTO recrawl_queue "
                "(site_id,url,interval_h,last_crawled,next_crawl) VALUES(?,?,?,?,?)",
                (s['id'], s['url'], interval_h, now, now + interval_h * 3600))
    con.commit()
    con.close()

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

# ── State persistence ──────────────────────────────────────────────────────────
def _load_state():
    try:
        s = json.loads(_STATE_FILE.read_text())
        return s.get("results_pos",0), s.get("leaks_pos",0)
    except: return 0, 0

def _save_state():
    try:
        _STATE_FILE.write_text(json.dumps({
            "results_pos": _results_pos,
            "leaks_pos":   _leaks_pos,
        }))
    except: pass

_results_pos, _leaks_pos = _load_state()
_mirror_batch = 0

# ── Ingest ─────────────────────────────────────────────────────────────────────
def ingest_new():
    global _results_pos, _mirror_batch
    if not RESULTS.exists(): return [], 0
    con = db()
    new_ids, new_count = [], 0
    try:
        with open(RESULTS, encoding='utf-8') as f:
            f.seek(_results_pos)
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    e   = json.loads(line)
                    url = e.get('url','')
                    if not url: continue
                    host  = url.split('/')[2] if '//' in url else url
                    s     = base_score(e)
                    # Hard reject CSAM — never save, never show
                    if is_csam(e.get('title',''), e.get('body_preview','')):
                        continue

                    noise = 1 if (e.get('status')!=200 or
                                  len((e.get('body_preview') or '').strip())<20 or
                                  s<-5) else 0
                    chash = content_hash(e.get('body_preview',''))
                    lang  = detect_language(e.get('body_preview',''))
                    now   = int(time.time())
                    # Skip if identical content already exists (mirror/repost)
                    if chash and con.execute(
                        "SELECT id FROM sites WHERE content_hash=? AND noise=0 LIMIT 1",
                        (chash,)).fetchone():
                        continue
                    con.execute('''INSERT OR IGNORE INTO sites
                        (url,host,title,status,preview,category,score,trust_score,
                         noise,bookmarked,reviewed,notes,timestamp,last_seen,
                         content_hash,language)
                        VALUES (?,?,?,?,?,?,?,0,?,0,0,"",?,?,?,?)''',
                        (url,host,e.get('title',''),e.get('status',0),
                         e.get('body_preview',''),categorize(e),s,noise,
                         e.get('timestamp',now),now,chash,lang))
                    if con.lastrowid:
                        rowid = con.lastrowid
                        con.execute(
                            "INSERT INTO sites_fts(rowid,url,title,preview,category) VALUES(?,?,?,?,?)",
                            (rowid,url,e.get('title',''),e.get('body_preview',''),categorize(e)))
                        # Save file links
                        for fl in json.loads(e.get('file_links','[]') or '[]'):
                            try:
                                con.execute(
                                    "INSERT OR IGNORE INTO file_links (site_id,url,extension,timestamp) VALUES(?,?,?,?)",
                                    (rowid,fl[0],fl[1],now))
                            except: pass
                        new_ids.append(rowid)
                        new_count += 1
                except: pass
        # Save position at end of file
        with open(RESULTS, encoding='utf-8') as f:
            f.seek(0,2); _results_pos = f.tell()
        _save_state()
    except Exception as ex:
        pass
    con.commit()
    con.close()
    if new_ids:
        _mirror_batch += len(new_ids)
        if _mirror_batch >= 50:
            group_mirrors()
            _mirror_batch = 0
        update_trust_scores()
        run_alerts(new_ids, [])
        # Auto-queue new high-score sites for re-crawl
        _auto_queue_recrawl(new_ids)
    return new_ids, new_count

def ingest_new_leaks():
    global _leaks_pos
    if not LEAKS_FILE.exists(): return [], 0
    con = db()
    new_ids, new_count = [], 0
    try:
        with open(LEAKS_FILE, encoding='utf-8') as f:
            f.seek(_leaks_pos)
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    e   = json.loads(line)
                    url = e.get('url','')
                    if not url: continue
                    now = int(time.time())
                    con.execute('''INSERT OR IGNORE INTO leaks
                        (url,title,confidence,full_text,cves,breach_targets,
                         record_counts,exploit_types,has_emails,has_hashes,
                         has_ssn,has_magnet,timestamp)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (url,e.get('title',''),e.get('confidence',0),
                         e.get('full_text',''),e.get('cves','[]'),
                         e.get('breach_targets','[]'),e.get('record_counts','[]'),
                         e.get('exploit_types','[]'),e.get('has_emails',0),
                         e.get('has_hashes',0),e.get('has_ssn',0),
                         e.get('has_magnet',0),e.get('timestamp',now)))
                    if con.lastrowid:
                        rowid = con.lastrowid
                        con.execute(
                            "INSERT INTO leaks_fts(rowid,url,title,full_text,cves,breach_targets) VALUES(?,?,?,?,?,?)",
                            (rowid,url,e.get('title',''),e.get('full_text','')[:500],
                             e.get('cves','[]'),e.get('breach_targets','[]')))
                        new_ids.append(rowid)
                        new_count += 1
                except: pass
        with open(LEAKS_FILE, encoding='utf-8') as f:
            f.seek(0,2); _leaks_pos = f.tell()
        _save_state()
    except: pass
    con.commit()
    con.close()
    if new_ids: run_alerts([], new_ids)
    return new_ids, new_count

# Tiered re-crawl intervals by category
RECRAWL_INTERVALS = {
    "Forums":          12,   # high activity — check twice daily
    "News & Media":    12,   # high activity
    "Chat & Messaging":12,
    "Wikis & Directories": 72,   # moderate — every 3 days
    "Search Engines":  72,
    "Blogs":           72,
    "Libraries":       168,  # weekly — rarely changes
    "Whistleblower":   168,
    "Technology":      48,   # every 2 days
    "Privacy Tools":   48,
    "Finance & Crypto":48,
    "Email":           48,
    "Markets":         48,
    "Hosting":         96,   # every 4 days
    "Uncategorized":   48,   # default
}

def _interval_for(category):
    return RECRAWL_INTERVALS.get(category, 48)

def _auto_queue_recrawl(new_ids):
    """Automatically add high-score new sites to re-crawl queue with tiered intervals."""
    con = db()
    now = int(time.time())
    for sid in new_ids:
        s = con.execute(
            "SELECT url,score,category FROM sites WHERE id=?", (sid,)
        ).fetchone()
        if s and s['score'] >= 10:
            interval_h = _interval_for(s['category'])
            con.execute(
                "INSERT OR IGNORE INTO recrawl_queue "
                "(site_id,url,interval_h,last_crawled,next_crawl) VALUES(?,?,?,?,?)",
                (sid, s['url'], interval_h, now, now + interval_h * 3600))
    con.commit()
    con.close()

def run_recrawl_due():
    """Check recrawl_queue and re-fetch sites that are due.
    
    Batching strategy:
    - If main crawl is running: only check 5 sites (don't compete)
    - If crawler is idle: check up to 25 sites per run
    - Space requests 3s apart to avoid hammering Tor
    - Prioritise high-trust sites first
    """
    con = db()
    now = int(time.time())
    # Reduce batch if main crawl is active
    batch = 5 if crawler_status() == "running" else 25
    due = con.execute(
        "SELECT r.*,s.trust_score FROM recrawl_queue r "
        "JOIN sites s ON s.id=r.site_id "
        "WHERE r.next_crawl<=? "
        "ORDER BY s.trust_score DESC LIMIT ?",
        (now, batch)
    ).fetchall()
    con.close()
    if not due: return 0
    # We don't re-run Scrapy for individual sites — instead we update
    # their last_seen and uptime stats via a lightweight requests check
    import requests
    updated = 0
    for row in due:
        try:
            proxies = {"http":"socks5h://127.0.0.1:9050","https":"socks5h://127.0.0.1:9050"}
            resp = requests.get(row['url'], proxies=proxies, timeout=20)
            status = resp.status_code
            new_hash = content_hash(resp.text[:500])
            con = db()
            old = con.execute("SELECT content_hash,uptime_count,downtime_count FROM sites WHERE id=?",
                              (row['site_id'],)).fetchone()
            changed = 0
            if old:
                if status == 200:
                    new_up = (old['uptime_count'] or 0) + 1
                    con.execute("UPDATE sites SET last_seen=?,uptime_count=?,status=? WHERE id=?",
                                (now, new_up, status, row['site_id']))
                    if old['content_hash'] and old['content_hash'] != new_hash:
                        changed = 1
                        con.execute("UPDATE sites SET content_hash=? WHERE id=?",
                                    (new_hash, row['site_id']))
                else:
                    new_down = (old['downtime_count'] or 0) + 1
                    con.execute("UPDATE sites SET downtime_count=? WHERE id=?",
                                (new_down, row['site_id']))
                con.execute("INSERT INTO site_history (site_id,timestamp,status,content_changed) VALUES(?,?,?,?)",
                            (row['site_id'], now, status, changed))
                con.execute(
                    "UPDATE recrawl_queue SET last_crawled=?,next_crawl=?,change_count=change_count+? WHERE site_id=?",
                    (now, now+row['interval_h']*3600, changed, row['site_id']))
            con.commit()
            con.close()
            updated += 1
            time.sleep(3)  # space requests to avoid hammering Tor
        except: pass
    if updated > 0:
        update_trust_scores()
    return updated

# ── Background recrawl thread ──────────────────────────────────────────────────
def _recrawl_loop():
    """Background re-crawl loop.
    
    Timing:
    - Checks every 60 minutes normally
    - If main crawl is running, waits an extra 30 min before checking
      to avoid competing for Tor bandwidth
    """
    while True:
        try:
            # If main crawl is running, back off an extra 30 min
            extra_wait = 1800 if crawler_status() == "running" else 0
            time.sleep(3600 + extra_wait)
            n = run_recrawl_due()
            if n > 0:
                print(f"[RECRAWL] Updated {n} sites")
        except: pass

_recrawl_thread = threading.Thread(target=_recrawl_loop, daemon=True)

# ── Crawler process ────────────────────────────────────────────────────────────
crawler_process  = None
crawler_lock     = threading.Lock()
crawl_start_time = None
crawl_activity   = []
ACTIVITY_MAX     = 200

def _read_crawler_output(proc):
    global crawl_activity
    try:
        for raw in proc.stderr:
            line = raw.decode('utf-8', errors='replace').strip()
            if not line: continue
            keep = any(tag in line for tag in [
                '[SAVED','[LEAK','[QUEUE','[SKIP','[BLOCKED','[FAIL','[SEED',
                'Crawled','ERROR','WARNING','Closing spider','Spider opened','items/min',
            ])
            if keep:
                ts = time.strftime('%H:%M:%S')
                crawl_activity.append(f"[{ts}] {line}")
                if len(crawl_activity) > ACTIVITY_MAX:
                    crawl_activity.pop(0)
    except: pass

def crawler_status():
    with crawler_lock:
        if crawler_process is None: return "idle"
        return "running" if crawler_process.poll() is None else "finished"

def start_crawler():
    global crawler_process, crawl_start_time, crawl_activity
    with crawler_lock:
        if crawler_process and crawler_process.poll() is None:
            return {"status":"already_running"}
        crawl_activity = []
        job_dir = BASE_DIR / "crawl_job"
        job_dir.mkdir(exist_ok=True)
        crawler_process = subprocess.Popen(
            [sys.executable,"-m","scrapy","crawl","onion_spider",
             "-s",f"JOBDIR={job_dir}"],
            cwd=str(BASE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE)
        crawl_start_time = int(time.time())
        threading.Thread(target=_read_crawler_output,
                         args=(crawler_process,), daemon=True).start()
        return {"status":"started"}

def stop_crawler():
    global crawler_process, crawl_start_time
    with crawler_lock:
        if crawler_process and crawler_process.poll() is None:
            crawler_process.terminate()
            if crawl_start_time:
                con = db()
                total = con.execute("SELECT COUNT(*) FROM sites WHERE noise=0").fetchone()[0]
                leaks = con.execute("SELECT COUNT(*) FROM leaks").fetchone()[0]
                con.execute(
                    "INSERT INTO crawl_log (timestamp,sites_found,leaks_found,duration_s) VALUES(?,?,?,?)",
                    (int(time.time()),total,leaks,int(time.time())-crawl_start_time))
                con.commit(); con.close()
            return {"status":"stopped"}
        return {"status":"not_running"}



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
        """Handle POST requests — webhook receives canarytoken alerts."""
        if self.path.startswith("/webhook/"):
            self.do_GET()
        else:
            self.send_response(405)
            self.end_headers()

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)
        g  = lambda k,d="": qs.get(k,[d])[0]

        if p.path == "/":
            body = DASHBOARD_HTML.encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",len(body))
            self.end_headers()
            self.wfile.write(body)
            return

        elif p.path == "/api/start":  self.send_json(start_crawler())
        elif p.path == "/api/stop":   self.send_json(stop_crawler())

        elif p.path == "/api/status":
            _, new      = ingest_new()
            _, new_leak = ingest_new_leaks()
            con = db()
            total   = con.execute("SELECT COUNT(*) FROM sites WHERE noise=0").fetchone()[0]
            cats    = con.execute("SELECT COUNT(DISTINCT category) FROM sites WHERE noise=0").fetchone()[0]
            leaks_c = con.execute("SELECT COUNT(*) FROM leaks").fetchone()[0]
            mirrors = con.execute("SELECT COUNT(DISTINCT mirror_group) FROM sites WHERE mirror_group IS NOT NULL").fetchone()[0]
            unseen  = con.execute("SELECT COUNT(*) FROM alert_hits WHERE seen=0").fetchone()[0]
            due_rc  = con.execute("SELECT COUNT(*) FROM recrawl_queue WHERE next_crawl<=?",(int(time.time()),)).fetchone()[0]
            con.close()
            self.send_json({"status":crawler_status(),"total":total,"cats":cats,
                           "new":new,"new_leak":new_leak,"leaks":leaks_c,
                           "mirrors":mirrors,"unseen_alerts":unseen,"due_recrawl":due_rc})

        elif p.path == "/api/sites":
            q        = g("q"); cat=g("cat"); view=g("view","clean")
            sort     = g("sort","trust"); page=int(g("page","1"))
            per_page = 50; offset=(page-1)*per_page
            con      = db()
            where, params = [], []
            if view=="clean":       where.append("noise=0")
            elif view=="noise":     where.append("noise=1")
            elif view=="bookmarked":where.append("bookmarked=1")
            elif view=="reviewed":  where.append("reviewed=1")
            if cat and cat!="all":  where.append("category=?"); params.append(cat)
            if q:
                where.append("id IN (SELECT rowid FROM sites_fts WHERE sites_fts MATCH ?)")
                params.append(q+"*")
            w     = ("WHERE "+" AND ".join(where)) if where else ""
            order = {"trust":"trust_score DESC,score DESC",
                     "score":"score DESC","newest":"timestamp DESC",
                     "alpha":"title ASC"}.get(sort,"trust_score DESC")
            group_by_host = g("group","1") == "1"  # default: group by host
            if view == "clean":
                mf = ("AND (mirror_group IS NULL OR id IN ("
                      "SELECT id FROM sites s2 WHERE s2.mirror_group=sites.mirror_group "
                      "ORDER BY s2.trust_score DESC LIMIT 1))")
                if group_by_host and not q:
                    # Fast grouped query using pre-aggregated host counts
                    # Step 1: get best site_id per host
                    noise_clause = "AND s2.noise=0" if view=="clean" else ""
                    host_query = (
                        f"SELECT MIN(id) as id, host, COUNT(*) as subpage_count "
                        f"FROM sites WHERE noise=0 "
                        f"GROUP BY host"
                    )
                    total = con.execute(
                        f"SELECT COUNT(DISTINCT host) FROM sites WHERE noise=0", []).fetchone()[0]
                    rows = con.execute(
                        f"SELECT s.*, h.subpage_count, 0 as mirror_count "
                        f"FROM sites s "
                        f"JOIN ({host_query}) h ON h.id=s.id "
                        f"WHERE s.noise=0 "
                        f"ORDER BY {order} LIMIT ? OFFSET ?",
                        [per_page, offset]).fetchall()
                else:
                    total = con.execute(f"SELECT COUNT(*) FROM sites {w} {mf}", params).fetchone()[0]
                    rows  = con.execute(
                        f"SELECT sites.*, 1 as subpage_count, 0 as mirror_count "
                        f"FROM sites {w} {mf} ORDER BY {order} LIMIT ? OFFSET ?",
                        params+[per_page, offset]).fetchall()
            else:
                total = con.execute(f"SELECT COUNT(*) FROM sites {w}", params).fetchone()[0]
                rows  = con.execute(
                    f"SELECT sites.*,0 as mirror_count,"
                    f"(SELECT COUNT(*) FROM sites s2 WHERE s2.host=sites.host AND s2.noise=0) as subpage_count "
                    f"FROM sites {w} ORDER BY {order} LIMIT ? OFFSET ?",
                    params+[per_page,offset]).fetchall()
            con.close()
            self.send_json({"sites":[dict(r) for r in rows],"total":total,"grouped":group_by_host})

        elif p.path == "/api/search/context":
            # Keyword context — returns snippets with keyword highlighted
            q      = g("q","").strip()
            max_r  = min(int(g("max","20")), 50)
            if not q or len(q) < 2:
                self.send_json({"results":[]})
                return
            con  = db()
            rows = con.execute(
                "SELECT id,url,title,preview,category,trust_score FROM sites "
                "WHERE noise=0 AND (title LIKE ? OR preview LIKE ?) "
                "ORDER BY trust_score DESC LIMIT ?",
                (f"%{q}%",f"%{q}%",max_r)).fetchall()
            results = []
            for r in rows:
                # Extract snippet around keyword
                preview = r['preview'] or ''
                title   = r['title'] or ''
                idx = preview.lower().find(q.lower())
                if idx >= 0:
                    start   = max(0, idx-60)
                    end     = min(len(preview), idx+len(q)+60)
                    snippet = preview[start:end]
                    # Mark the keyword position for frontend highlighting
                    kw_start = idx - start
                    kw_end   = kw_start + len(q)
                else:
                    snippet  = preview[:120]
                    kw_start = -1
                    kw_end   = -1
                results.append({
                    "id":       r['id'],
                    "url":      r['url'],
                    "title":    title,
                    "snippet":  snippet,
                    "kw_start": kw_start,
                    "kw_end":   kw_end,
                    "category": r['category'],
                    "trust":    r['trust_score'],
                })
            con.close()
            self.send_json({"results":results,"query":q})

        elif p.path == "/api/mirrors":
            con = db()
            groups = con.execute('''
                SELECT mirror_group, COUNT(*) as count,
                       MIN(title) as title,
                       MAX(trust_score) as trust,
                       GROUP_CONCAT(url,"|||") as urls,
                       GROUP_CONCAT(id,",") as ids
                FROM sites WHERE mirror_group IS NOT NULL AND noise=0
                GROUP BY mirror_group ORDER BY count DESC, trust DESC
            ''').fetchall()
            con.close()
            self.send_json([{
                "mirror_group": g2["mirror_group"],
                "count":  g2["count"],
                "title":  g2["title"],
                "trust":  g2["trust"],
                "urls":   g2["urls"].split("|||") if g2["urls"] else [],
                "ids":    [int(i) for i in g2["ids"].split(",") if i],
            } for g2 in groups])

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
                "crawl_log":  [dict(r) for r in con.execute("SELECT * FROM crawl_log ORDER BY timestamp DESC LIMIT 30").fetchall()],
                "categories": [dict(r) for r in con.execute("SELECT category,COUNT(*) as count FROM sites WHERE noise=0 GROUP BY category ORDER BY count DESC").fetchall()],
                "daily":      [dict(r) for r in con.execute('SELECT DATE(timestamp,"unixepoch") as day,COUNT(*) as count FROM sites WHERE noise=0 GROUP BY day ORDER BY day DESC LIMIT 30').fetchall()],
                "mirrors":    con.execute("SELECT COUNT(DISTINCT mirror_group) FROM sites WHERE mirror_group IS NOT NULL").fetchone()[0],
                "total":      con.execute("SELECT COUNT(*) FROM sites WHERE noise=0").fetchone()[0],
                "noise":      con.execute("SELECT COUNT(*) FROM sites WHERE noise=1").fetchone()[0],
                "recrawl":    con.execute("SELECT COUNT(*) FROM recrawl_queue").fetchone()[0],
                "due":        con.execute("SELECT COUNT(*) FROM recrawl_queue WHERE next_crawl<=?",(int(time.time()),)).fetchone()[0],
                "avg_trust":  con.execute("SELECT AVG(trust_score) FROM sites WHERE noise=0").fetchone()[0] or 0,
            })
            con.close()

        elif p.path == "/api/activity":
            since = int(g("since","0"))
            self.send_json({"lines":crawl_activity[since:],"total":len(crawl_activity)})

        elif p.path == "/api/files":
            q=g("q"); ext=g("ext"); page=int(g("page","1")); per_page=50; offset=(page-1)*per_page
            con=db(); where2,params2=[],[]
            if ext: where2.append("extension=?"); params2.append(ext)
            if q:   where2.append("url LIKE ?"); params2.append(f"%{q}%")
            w2    = ("WHERE "+" AND ".join(where2)) if where2 else ""
            total = con.execute("SELECT COUNT(*) FROM file_links "+w2,params2).fetchone()[0]
            rows  = con.execute("SELECT f.*,s.title as site_title FROM file_links f LEFT JOIN sites s ON s.id=f.site_id "+w2+" ORDER BY f.timestamp DESC LIMIT ? OFFSET ?",params2+[per_page,offset]).fetchall()
            exts  = con.execute("SELECT extension,COUNT(*) as c FROM file_links GROUP BY extension ORDER BY c DESC").fetchall()
            con.close()
            self.send_json({"files":[dict(r) for r in rows],"total":total,"ext_counts":[dict(r) for r in exts]})

        elif p.path == "/api/recrawl":
            action=g("action","list"); con=db()
            if action=="add":
                sid=int(g("id","0")); hours=int(g("hours","24"))
                site=con.execute("SELECT url FROM sites WHERE id=?",(sid,)).fetchone()
                if site:
                    now=int(time.time())
                    con.execute("INSERT OR REPLACE INTO recrawl_queue (site_id,url,interval_h,last_crawled,next_crawl) VALUES(?,?,?,?,?)",(sid,site["url"],hours,now,now+hours*3600))
                    con.commit(); self.send_json({"ok":True})
                else: self.send_json({"ok":False})
            elif action=="remove":
                sid=int(g("id","0"))
                con.execute("DELETE FROM recrawl_queue WHERE site_id=?",(sid,))
                con.commit(); self.send_json({"ok":True})
            elif action=="run_due":
                n = run_recrawl_due()
                self.send_json({"updated":n})
            else:
                rows=con.execute("SELECT r.*,s.title,s.trust_score,s.category,s.uptime_count,s.downtime_count FROM recrawl_queue r JOIN sites s ON s.id=r.site_id ORDER BY r.next_crawl ASC").fetchall()
                due=con.execute("SELECT COUNT(*) FROM recrawl_queue WHERE next_crawl<=?",(int(time.time()),)).fetchone()[0]
                self.send_json({"queue":[dict(r) for r in rows],"due":due})
            con.close()

        elif p.path == "/api/languages":
            con=db()
            rows=con.execute("SELECT language,COUNT(*) as count FROM sites WHERE noise=0 AND language!='unknown' GROUP BY language ORDER BY count DESC").fetchall()
            con.close()
            self.send_json([dict(r) for r in rows])

        elif p.path == "/api/network":
            con=db()
            nodes=con.execute("SELECT category as id,COUNT(*) as count FROM sites WHERE noise=0 GROUP BY category").fetchall()
            edges=con.execute('''SELECT s1.category as source_cat,s2.category as target_cat,COUNT(*) as weight
                FROM sites s1 JOIN sites s2 ON s1.mirror_group=s2.mirror_group AND s1.id!=s2.id
                WHERE s1.noise=0 AND s2.noise=0 GROUP BY source_cat,target_cat LIMIT 200''').fetchall()
            con.close()
            self.send_json({"nodes":[dict(r) for r in nodes],"edges":[dict(r) for r in edges]})

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
            con  = db()
            if view == "channels":
                rows = con.execute(
                    "SELECT * FROM telegram_channels ORDER BY message_count DESC LIMIT 200"
                ).fetchall()
                self.send_json({"channels":[dict(r) for r in rows]})
            elif view == "leaks":
                where = "WHERE has_leak=1"
                params = []
                if q:
                    where += " AND text LIKE ?"
                    params.append(f"%{q}%")
                total = con.execute(f"SELECT COUNT(*) FROM telegram_messages {where}",params).fetchone()[0]
                rows  = con.execute(
                    f"SELECT * FROM telegram_messages {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    params+[per_page,offset]).fetchall()
                self.send_json({"messages":[dict(r) for r in rows],"total":total})
            else:
                where = "WHERE 1=1"
                params = []
                if q:
                    where += " AND text LIKE ?"
                    params.append(f"%{q}%")
                total = con.execute(f"SELECT COUNT(*) FROM telegram_messages {where}",params).fetchone()[0]
                rows  = con.execute(
                    f"SELECT * FROM telegram_messages {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    params+[per_page,offset]).fetchall()
                self.send_json({"messages":[dict(r) for r in rows],"total":total})
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

        elif p.path == "/api/pastes":
            q        = g("q"); view=g("view","leaks")
            page     = int(g("page","1")); per_page=50; offset=(page-1)*per_page
            con      = db()
            try:
                where, params = [], []
                if view == "leaks": where.append("has_leak=1")
                if q: where.append("content LIKE ?"); params.append(f"%{q}%")
                w     = ("WHERE "+" AND ".join(where)) if where else ""
                total = con.execute(f"SELECT COUNT(*) FROM paste_items {w}",params).fetchone()[0]
                rows  = con.execute(
                    f"SELECT * FROM paste_items {w} ORDER BY first_seen DESC LIMIT ? OFFSET ?",
                    params+[per_page,offset]).fetchall()
                sites = con.execute(
                    "SELECT site_name, COUNT(*) as c FROM paste_items GROUP BY site_name ORDER BY c DESC"
                ).fetchall()
                self.send_json({"pastes":[dict(r) for r in rows],"total":total,
                               "sites":[dict(r) for r in sites]})
            except:
                self.send_json({"pastes":[],"total":0,"sites":[]})
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

        elif p.path == "/api/stealer/stats":
            try:
                con = db()
                total_logs  = con.execute("SELECT COUNT(*) FROM stealer_logs").fetchone()[0]
                total_creds = con.execute("SELECT COUNT(*) FROM stealer_credentials").fetchone()[0]
                types  = con.execute("SELECT log_type,COUNT(*) as c FROM stealer_logs GROUP BY log_type ORDER BY c DESC").fetchall()
                recent = con.execute("SELECT * FROM stealer_logs ORDER BY parsed_at DESC LIMIT 5").fetchall()
                con.close()
                self.send_json({"total_logs":total_logs,"total_creds":total_creds,
                               "types":[dict(r) for r in types],"recent":[dict(r) for r in recent]})
            except:
                self.send_json({"total_logs":0,"total_creds":0,"types":[],"recent":[]})

        elif p.path == "/api/stealer/search":
            q    = g("q","").strip()
            page = int(g("page","1")); per_page=50; offset=(page-1)*per_page
            if not q or len(q) < 2:
                self.send_json({"results":[],"total":0}); return
            try:
                con  = db()
                rows = con.execute(
                    "SELECT c.*,l.log_type,l.filename,l.source "
                    "FROM stealer_credentials c "
                    "JOIN stealer_logs l ON l.id=c.log_id "
                    "WHERE c.username LIKE ? OR c.url LIKE ? "
                    "ORDER BY c.found_at DESC LIMIT ? OFFSET ?",
                    (f"%{q}%",f"%{q}%",per_page,offset)).fetchall()
                total = con.execute(
                    "SELECT COUNT(*) FROM stealer_credentials WHERE username LIKE ? OR url LIKE ?",
                    (f"%{q}%",f"%{q}%")).fetchone()[0]
                con.close()
                self.send_json({"results":[dict(r) for r in rows],"total":total})
            except:
                self.send_json({"results":[],"total":0})

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
      <span>Sites</span>
      <span class="val" id="hTotal">—</span>
    </div>
    <div class="stat-pill">
      <span>Leaks</span>
      <span class="val" id="hLeaks" style="color:var(--red);">—</span>
    </div>
    <div class="stat-pill">
      <span>Mirrors</span>
      <span class="val" id="hMirrors" style="color:var(--amber);">—</span>
    </div>
    <div class="stat-pill">
      <span>Bookmarked</span>
      <span class="val" id="hBookmarks">—</span>
    </div>
    <div id="alertBadge"></div>
    <div id="newBadge"></div>
  </div>

  <div class="topbar-actions">
    <button class="btn primary" id="btnStart" onclick="startCrawl()">▶ Start Crawl</button>
    <button class="btn danger"  id="btnStop"  onclick="stopCrawl()" disabled>■ Stop</button>
  </div>
</header>

<!-- App body -->
<div class="app-body">

  <!-- Left nav -->
  <nav class="nav">
    <div class="nav-section-label">Intelligence</div>
    <div class="nav-item active" onclick="setTab('top')"       id="tab-top">
      <span class="nav-icon">⭐</span> Top Picks
    </div>
    <div class="nav-item" onclick="setTab('leaks')"     id="tab-leaks">
      <span class="nav-icon">🔓</span> Leaks & Exploits
    </div>
    <div class="nav-item" onclick="setTab('telegram')"  id="tab-telegram">
      <span class="nav-icon">📱</span> Telegram
      <span class="nav-badge blue" id="tgBadge" style="display:none">0</span>
    </div>
    <div class="nav-item" onclick="setTab('pastes')"    id="tab-pastes">
      <span class="nav-icon">📋</span> Paste Sites
    </div>
    <div class="nav-item" onclick="setTab('stealer')"   id="tab-stealer">
      <span class="nav-icon">🔑</span> Stealer Logs
    </div>

    <div class="nav-divider"></div>
    <div class="nav-section-label">Discovery</div>

    <div class="nav-item" onclick="setTab('browse')"    id="tab-browse">
      <span class="nav-icon">🔍</span> Browse Sites
    </div>
    <div class="nav-item" onclick="setTab('mirrors')"   id="tab-mirrors">
      <span class="nav-icon">🔁</span> Mirrors
    </div>
    <div class="nav-item" onclick="setTab('files')"     id="tab-files">
      <span class="nav-icon">📁</span> File Links
    </div>
    <div class="nav-item" onclick="setTab('language')"  id="tab-language">
      <span class="nav-icon">🌐</span> Languages
    </div>

    <div class="nav-divider"></div>
    <div class="nav-section-label">Management</div>

    <div class="nav-item" onclick="setTab('alerts')"    id="tab-alerts">
      <span class="nav-icon">🔔</span> Alerts
      <span class="nav-badge" id="alertNavBadge" style="display:none">0</span>
    </div>
    <div class="nav-item" onclick="setTab('recrawl')"   id="tab-recrawl">
      <span class="nav-icon">🔄</span> Re-Crawl
    </div>
    <div class="nav-item" onclick="setTab('bookmarks')" id="tab-bookmarks">
      <span class="nav-icon">🔖</span> Bookmarks
    </div>
    <div class="nav-item" onclick="setTab('noise')"     id="tab-noise">
      <span class="nav-icon">🗑</span> Filtered
    </div>
  </nav>

  <!-- Main -->
  <div class="main">

    <!-- TOP PICKS -->
    <div class="panel active" id="topPanel">
      <div class="content-header">
        <div class="content-title">Top Picks <span class="content-subtitle" id="shown">—</span></div>
        <div style="margin-left:auto;font-size:12px;color:var(--text-3);">Sorted by trust score</div>
      </div>
      <div class="panel-scroll" id="topGrid"></div>
    </div>

    <!-- BROWSE -->
    <div class="panel" id="browsePanel">
      <div class="content-header">
        <div class="content-title">Browse</div>
        <div class="search-bar">
          <input type="text" id="q" placeholder="Search titles, URLs, previews…" oninput="onSearch()">
        </div>
        <select class="select" id="sortSel" onchange="load()">
          <option value="trust">Trust score</option>
          <option value="score">Keyword match</option>
          <option value="newest">Newest</option>
          <option value="alpha">A → Z</option>
        </select>
        <button class="filter-btn on" id="groupToggle" onclick="toggleGrouping()" title="Group subpages by host">⊞ Grouped</button>
        <div class="result-count">showing <span id="browseShown">—</span> / <span id="totalShown">—</span></div>
      </div>
      <div class="browse-layout">
        <div class="cat-sidebar" id="catList"></div>
        <div style="flex:1;display:flex;flex-direction:column;overflow:hidden;">
          <div class="panel-scroll" style="padding:0;" id="tableWrap"></div>
          <div id="pgEl"></div>
        </div>
      </div>
    </div>

    <!-- MIRRORS -->
    <div class="panel" id="mirrorsPanel">
      <div class="content-header">
        <div class="content-title">Mirror Groups</div>
        <div class="result-count"><span id="mirrorCount">—</span> groups detected</div>
      </div>
      <div class="panel-scroll" id="mirrorsContent"></div>
    </div>

    <!-- LEAKS -->
    <div class="panel" id="leaksPanel">
      <div class="content-header">
        <div class="content-title">Leaks & Exploits</div>
        <div class="search-bar">
          <input type="text" id="leakQ" placeholder="Search CVEs, targets, domains…" oninput="loadLeaks()">
        </div>
        <select class="select" id="leakSort" onchange="loadLeaks()">
          <option value="confidence">Highest confidence</option>
          <option value="newest">Newest</option>
        </select>
        <div class="filter-row">
          <button class="filter-btn" id="fEmails"  onclick="toggleLeakFilter('emails')">📧 Emails</button>
          <button class="filter-btn" id="fHashes"  onclick="toggleLeakFilter('hashes')">🔑 Hashes</button>
          <button class="filter-btn" id="fCve"     onclick="toggleLeakFilter('cve')">🐛 CVE</button>
          <button class="filter-btn" id="fMagnet"  onclick="toggleLeakFilter('magnet')">💾 Files</button>
          <button class="filter-btn" id="fSsn"     onclick="toggleLeakFilter('ssn')">🪪 SSN</button>
        </div>
        <div class="result-count"><span id="leakShown">—</span> / <span id="leakTotal">—</span></div>
      </div>
      <!-- Personal search -->
      <div style="padding:10px 20px;border-bottom:1px solid var(--border);background:rgba(239,68,68,0.04);flex-shrink:0;">
        <div style="font-size:11px;font-weight:600;color:var(--red);text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;">⚠ Personal Data Search</div>
        <div style="display:flex;gap:8px;">
          <div class="search-bar" style="max-width:320px;flex:1;">
            <input type="text" id="personalSearch" placeholder="email, username, SSN…">
          </div>
          <button class="btn danger" onclick="searchPersonal()">Search All Leaks</button>
        </div>
        <div id="personalResults" style="margin-top:8px;font-size:12px;"></div>
      </div>
      <!-- Context search -->
      <div style="padding:10px 20px;border-bottom:1px solid var(--border);background:rgba(59,130,246,0.03);flex-shrink:0;">
        <div style="font-size:11px;font-weight:600;color:var(--accent-hi);text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;">Keyword Context Search</div>
        <div style="display:flex;gap:8px;">
          <div class="search-bar" style="max-width:320px;flex:1;">
            <input type="text" id="contextQ" placeholder="company, CVE, username…" onkeydown="if(event.key==='Enter')searchContext()">
          </div>
          <button class="btn" style="border-color:var(--accent);color:var(--accent-hi);" onclick="searchContext()">Search with Context</button>
        </div>
        <div id="contextResults" style="margin-top:8px;max-height:180px;overflow-y:auto;"></div>
      </div>
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
        <button class="filter-btn on" onclick="setTgTab('leaks')"    id="tg-tab-leaks"    style="border-radius:0;border-bottom:2px solid var(--accent);margin-bottom:-1px;">🔓 Leak Hits</button>
        <button class="filter-btn"    onclick="setTgTab('all')"      id="tg-tab-all"      style="border-radius:0;border-bottom:2px solid transparent;margin-bottom:-1px;">💬 All Messages</button>
        <button class="filter-btn"    onclick="setTgTab('channels')" id="tg-tab-channels" style="border-radius:0;border-bottom:2px solid transparent;margin-bottom:-1px;">📡 Channels</button>
      </div>
      <div class="panel-scroll" style="padding:0;" id="tgTableWrap"></div>
      <div id="tgPgEl"></div>
    </div>

    <!-- PASTES -->
    <div class="panel" id="pastesPanel">
      <div class="content-header">
        <div class="content-title">Paste Sites</div>
        <div class="search-bar">
          <input type="text" id="pasteQ" placeholder="Search paste content…" oninput="loadPastes()">
        </div>
        <select class="select" id="pasteView" onchange="loadPastes()">
          <option value="leaks">Leak Hits Only</option>
          <option value="all">All Pastes</option>
        </select>
        <div class="result-count"><span id="pasteShown">—</span> / <span id="pasteTotal">—</span></div>
      </div>
      <div id="pasteSites" style="display:flex;gap:6px;padding:8px 20px;border-bottom:1px solid var(--border);flex-wrap:wrap;flex-shrink:0;"></div>
      <div class="panel-scroll" style="padding:0;" id="pasteTableWrap"></div>
      <div id="pastePgEl"></div>
    </div>

    <!-- STEALER LOGS -->
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

    <!-- FILES -->
    <div class="panel" id="filesPanel">
      <div class="content-header">
        <div class="content-title">File Links</div>
        <div class="search-bar">
          <input type="text" id="fileQ" placeholder="Search file URLs…" oninput="loadFiles()">
        </div>
        <select class="select" id="fileExt" onchange="loadFiles()"><option value="">All types</option></select>
        <div class="result-count"><span id="fileShown">—</span> / <span id="fileTotal">—</span></div>
      </div>
      <div class="panel-scroll" style="padding:0;" id="fileTableWrap"></div>
      <div id="filePgEl"></div>
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

    <!-- RECRAWL -->
    <div class="panel" id="recrawlPanel">
      <div class="content-header">
        <div class="content-title">Re-Crawl Schedule</div>
        <button class="btn primary" onclick="runDueNow()">▶ Run Due Now</button>
        <span id="rcDueBadge" style="margin-left:6px;"></span>
      </div>
      <div class="panel-scroll">
        <div style="font-size:12px;color:var(--text-3);margin-bottom:16px;">Sites scoring ≥10 are auto-queued. Background re-crawls run every 30 minutes.</div>
        <div id="recrawlList"></div>
      </div>
    </div>

    <!-- LANGUAGE -->
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

    <!-- NOISE/FILTERED -->
    <div class="panel" id="noisePanel">
      <div class="content-header">
        <div class="content-title">Filtered Sites</div>
        <div class="search-bar">
          <input type="text" id="noiseQ" placeholder="Search filtered…" oninput="onSearch()">
        </div>
      </div>
      <div class="panel-scroll" style="padding:0;" id="noiseTableWrap"></div>
      <div id="noisePgEl"></div>
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
      <button class="btn" id="drRcBtn" onclick="scheduleRecrawl()">🔄 Schedule</button>
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
const _siteCache={}, _leakCache={};

// Tab data cache — avoid re-fetching unchanged data
const _tabCache={};
let _lastSiteCount=0;
let _activitySince=0;
let _pollInterval=3000;  // starts at 3s, slows to 15s when idle

function esc(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
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
    'telegramPanel','pastesPanel','stealerPanel','bookmarksPanel','noisePanel','canariesPanel'];
  panels.forEach(id=>{ const el=document.getElementById(id); if(el){ el.classList.remove('active'); }});

  const showPanel = (id) => { const el=document.getElementById(id); if(el) el.classList.add('active'); };

  if(tab==='top')        { showPanel('topPanel');       loadTop(); }
  else if(tab==='browse')    { showPanel('browsePanel');    buildCatList(); load(); }
  else if(tab==='bookmarks') { showPanel('bookmarksPanel'); load(); }
  else if(tab==='noise')     { showPanel('noisePanel');     load(); }
  else if(tab==='mirrors')   { showPanel('mirrorsPanel');   loadMirrors(); }
  else if(tab==='leaks')     { showPanel('leaksPanel');     leakPage=1; loadLeaks(); }
  else if(tab==='alerts')    { showPanel('alertsPanel');    loadAlerts(); }
  else if(tab==='files')     { showPanel('filesPanel');     loadFiles(); }
  else if(tab==='recrawl')   { showPanel('recrawlPanel');   loadRecrawl(); }
  else if(tab==='language')  { showPanel('languagePanel');  loadLanguages(); }
  else if(tab==='pastes')    { showPanel('pastesPanel');    loadPastes(); }
  else if(tab==='stealer')   { showPanel('stealerPanel');   loadStealerStats(); }
  else if(tab==='telegram')  { showPanel('telegramPanel');  loadTelegramStats(); loadTelegram(); }
  else if(tab==='canaries')  { showPanel('canariesPanel');  loadCanaries(); }
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

async function loadTop(){
  const res = await fetch('/api/top').then(r=>r.json()).catch(()=>null);
  if(!res) return;
  res.forEach(s=>_siteCache[s.id]=s);
  const shownEl = document.getElementById('shown');
  if(shownEl) shownEl.textContent = res.length.toLocaleString()+' sites';
  renderTopGrid(res);
}

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
  if(!leaks.length){wrap.innerHTML='<div class="empty"><div class="empty-icon">🔓</div>No leaks found yet</div>';pgEl.innerHTML='';return;}
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
  const el=document.getElementById('personalResults');
  el.innerHTML='<span style="color:var(--accent)">Searching…</span>';
  const res=await fetch(`/api/leaks/search?term=${encodeURIComponent(term)}`).then(r=>r.json()).catch(()=>null);
  if(!res){el.innerHTML='Search failed.';return;}
  if(!res.results.length){
    el.innerHTML=`<span style="color:var(--accent)">✓ No matches found for "${esc(term)}"</span>`;return;
  }
  el.innerHTML=`<span style="color:var(--danger)">⚠ Found in ${res.results.length} leak(s):</span><br>`+
    res.results.map(r=>`<div style="margin-top:4px;padding:4px 8px;border-left:2px solid var(--danger);">
      <span style="color:var(--text)">${esc(r.title||'')}</span>
      <span style="color:var(--dim);margin-left:8px;font-family:Share Tech Mono,monospace;font-size:.65rem;">${esc(r.url||'')}</span>
      <span style="color:var(--warn);margin-left:8px;">confidence: ${r.confidence}%</span>
    </div>`).join('');
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
  const el=document.getElementById('statsPanel');
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
  document.getElementById('hLeaks').textContent   = (st.leaks||0).toLocaleString();
  document.getElementById('hMirrors').textContent = (st.mirrors||0).toLocaleString();

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
    document.getElementById('btnStop').disabled   = true;
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
  if(r)document.getElementById('hBookmarks').textContent=r.total.toLocaleString();
}

async function startCrawl(){
  await fetch('/api/start');
  document.getElementById('btnStart').disabled=true;
  document.getElementById('btnStop').disabled=false;
  document.getElementById('liveInd').style.display='';
  addLog('Crawl started…','g');
  startPolling();
}

async function stopCrawl(){
  await fetch('/api/stop');
  document.getElementById('btnStart').disabled=false;
  document.getElementById('btnStop').disabled=true;
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
  if(!res||!res.nodes.length){
    document.getElementById('networkPanel').innerHTML=
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
  const el = document.getElementById('contextResults');
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

function goCanaryPage(p){ const pages=Math.ceil(document.getElementById("canaryTotal")?.textContent.replace(/,/g,"")||1/50); if(p<1)return; canaryPage=p; loadCanaries(); }

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

async function setTgTab(v){
  tgView=v; tgPage=1;
  ['leaks','all','channels'].forEach(t=>{
    const el = document.getElementById('tg-tab-'+t);
    if(!el) return;
    const isActive = t===v;
    el.classList.toggle('active', isActive);
    // Update inline style underline indicator
    el.style.borderBottom = isActive ? '2px solid var(--accent)' : '';
    el.style.marginBottom = isActive ? '-1px' : '';
    el.style.color = isActive ? 'var(--accent-hi)' : '';
  });
  loadTelegram();
}

async function muteChannel(url, btn){
  if(!url){ toast("No URL for channel","error"); return; }
  const isActive = btn.textContent.trim() === "🔇";
  const mute = isActive ? 1 : 0;  // 🔇 means currently active, click to mute
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

async function loadTelegramStats(){
  const s = await fetch('/api/telegram/stats').then(r=>r.json()).catch(()=>null);
  if(!s) return;
  document.getElementById('tgChannels').textContent  = (s.joined_channels||0).toLocaleString();
  document.getElementById('tgMessages').textContent  = (s.total_messages||0).toLocaleString();
  document.getElementById('tgLeaks').textContent     = (s.leak_messages||0).toLocaleString();
  document.getElementById('tgDiscovered').textContent= (s.discovered_channels||0).toLocaleString();
}

async function loadTelegram(){
  const q = document.getElementById('tgQ').value;
  const res = await fetch(`/api/telegram?view=${tgView}&q=${encodeURIComponent(q)}&page=${tgPage}`)
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
      <td style="font-family:Share Tech Mono,monospace;font-size:.65rem;color:var(--accent2);">${(c.message_count||0).toLocaleString()}</td>
      <td><button class="icon-btn" data-url="${esc(c.url||'')}" onclick="event.stopPropagation();muteChannel(this.getAttribute('data-url'),this)" title="Mute/Unmute channel" style="${!c.active?'border-color:var(--red);color:var(--red);':''}">${c.active?'🔇':'🔊'}</button></td>
    </tr>`).join('');
    wrap.innerHTML=`<table><thead><tr><th>URL</th><th>Name</th><th>Type</th><th>Status</th><th>Messages</th></tr></thead><tbody>${rows}</tbody></table>`;
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
    const preview = esc((m.text||'').substring(0,300));
    const chanHandle = esc(m.channel_name||'').replace('https://t.me/','');
    const sevClass = m.confidence>=70?'sev-critical':m.confidence>=45?'sev-high':'sev-medium';
    return`<tr style="vertical-align:top;">
      <td style="font-size:12px;color:var(--text-2);white-space:nowrap;padding-top:14px;width:140px;">
        ${chanHandle}
      </td>
      <td style="font-size:13px;color:var(--text);line-height:1.6;padding:12px 14px;max-width:500px;">
        ${preview}
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

// ── Init ───────────────────────────────────────────────────────────────────────
(async function init(){
  const st=await fetch('/api/status').then(r=>r.json()).catch(()=>null);
  if(st){updateDot(st.status);document.getElementById('hTotal').textContent=(st.total||0).toLocaleString();document.getElementById('hLeaks').textContent=(st.leaks||0).toLocaleString();document.getElementById('hMirrors').textContent=(st.mirrors||0).toLocaleString();}
  await updateBookmarkCount();
  setTab('top');
  startPolling();
  if(st&&st.status==='running'){
    document.getElementById('btnStart').disabled=true;
    document.getElementById('btnStop').disabled=false;
    document.getElementById('liveInd').style.display='';
    addLog('Crawl already running — reconnected.','g');
  }else{
    addLog(`Database ready. ${(st&&st.total)||0} clean sites.`,'b');
  }
})();


















</script>
</body>
</html>
"""

if __name__ == "__main__":
    ensure_db()
    ensure_indexes()
    _recrawl_thread.start()
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
