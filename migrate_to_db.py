"""
migrate_to_db.py
────────────────
Run once to convert results.jsonl → crawler.db

Usage:
    python migrate_to_db.py
    python migrate_to_db.py --input results.jsonl --output crawler.db
"""
import json, sqlite3, time, argparse
from pathlib import Path

NOISE_KWS = [
    'gift card','clone card','bitcoin generator','cashgod','buy money',
    'stolen','bazaar plastic','seized by','403 forbidden','index of /',
    'queue','redirect shortly','link disabled','ddos protection',
    'buy cheap','sell','vendor','escrow marketplace','darkweb shop',
    'buy now','add to cart','checkout','order now','our products',
    'exploit for sale','hacked accounts','dumps','cvv','fullz',
]
BOOST_KWS = {
    'library':6,'archive':6,'securedrop':8,'whistleblower':8,'wiki':4,
    'research':5,'journalism':7,'pgp':5,'encryption':4,'forum':3,
    'community':3,'blog':2,'news':4,'tails':5,'whonix':5,
    'documentation':5,'guide':3,'tutorial':3,'privacy':3,'anonymous':2,
    'search engine':4,'directory':3,'open source':4,'chat':2,
    'email':2,'hosting':2,'leaked':3,'database':3,
}
CATEGORY_RULES = [
    ("Search Engines",     ["search engine","index","ahmia","torch","haystack","searx"]),
    ("Wikis & Directories",["wiki","hidden wiki","link list","onion list","catalog","directory"]),
    ("Forums",             ["forum","board","thread","community","discussion","chan","bbs"]),
    ("News & Media",       ["news","article","press","journalist","media","report","bbc"]),
    ("Chat & Messaging",   ["chat","jabber","xmpp","irc","messenger"]),
    ("Email",              ["email","mail","smtp","webmail"]),
    ("Blogs",              ["blog","personal","diary","journal","portfolio"]),
    ("Markets",            ["market","shop","store","buy","sell","vendor","listing"]),
    ("Technology",         ["security","hacking","exploit","ctf","tech","software","code"]),
    ("Privacy Tools",      ["privacy","anonymous","vpn","tor","encryption","pgp","tails","whonix"]),
    ("Libraries",          ["library","archive","book","ebook","pdf","document","collection"]),
    ("Whistleblower",      ["leak","whistle","securedrop","classified","disclosure"]),
    ("Finance & Crypto",   ["bitcoin","crypto","wallet","exchange","monero","finance"]),
    ("Hosting",            ["hosting","host","server","vps","domain"]),
]

def categorize(e):
    text = f"{e.get('title','')} {e.get('body_preview','')}".lower()
    for cat, kws in CATEGORY_RULES:
        if any(kw in text for kw in kws): return cat
    return "Uncategorized"

def score_entry(e):
    title   = (e.get('title') or '').lower()
    preview = (e.get('body_preview') or '').lower()
    text    = f"{title} {preview}"
    s = 0
    if any(kw in text for kw in NOISE_KWS): s -= 50
    for kw, pts in BOOST_KWS.items():
        if kw in text: s += pts
    plen = len(preview)
    if plen > 250: s += 5
    elif plen > 100: s += 2
    elif plen < 30: s -= 5
    if title and title not in ('[no title]','403 forbidden','404','index of /'): s += 3
    if e.get('status') == 200: s += 2
    else: s -= 10
    scam = ['bitcoin generator','cashgod','buy money','stolen crypto','gift card','clone card','seized','queue']
    if any(t in title for t in scam): s -= 30
    return max(s, -99)

def is_noise(e, sc):
    title = (e.get('title') or '').lower()
    preview = (e.get('body_preview') or '').lower()
    return (
        e.get('status') != 200 or
        len(preview.strip()) < 20 or
        title in ('[no title]','403 forbidden','404 not found','index of /') or
        sc < -5
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input',  default='results.jsonl')
    parser.add_argument('--output', default='crawler.db')
    args = parser.parse_args()

    entries = []
    with open(args.input, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try: entries.append(json.loads(line))
                except: pass

    # Dedup by host
    seen, deduped = set(), []
    for e in entries:
        url  = e.get('url','')
        host = url.split('/')[2] if '//' in url else url
        if host not in seen:
            seen.add(host)
            deduped.append(e)

    Path(args.output).unlink(missing_ok=True)
    con = sqlite3.connect(args.output)
    cur = con.cursor()
    cur.executescript('''
    CREATE TABLE sites (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        url        TEXT UNIQUE,
        host       TEXT,
        title      TEXT,
        status     INTEGER,
        preview    TEXT,
        category   TEXT,
        score      INTEGER,
        noise      INTEGER DEFAULT 0,
        bookmarked INTEGER DEFAULT 0,
        reviewed   INTEGER DEFAULT 0,
        notes      TEXT DEFAULT '',
        timestamp  INTEGER
    );
    CREATE INDEX idx_score    ON sites(score DESC);
    CREATE INDEX idx_category ON sites(category);
    CREATE INDEX idx_bookmark ON sites(bookmarked);
    CREATE INDEX idx_noise    ON sites(noise);
    CREATE VIRTUAL TABLE sites_fts USING fts5(
        url, title, preview, category,
        content=sites, content_rowid=id
    );
    ''')

    rows = []
    for e in deduped:
        url  = e.get('url','')
        host = url.split('/')[2] if '//' in url else url
        sc   = score_entry(e)
        rows.append((
            url, host, e.get('title',''), e.get('status',0),
            e.get('body_preview',''), categorize(e), sc,
            1 if is_noise(e, sc) else 0,
            0, 0, '', e.get('timestamp', int(time.time()))
        ))

    cur.executemany('''
    INSERT OR IGNORE INTO sites
    (url,host,title,status,preview,category,score,noise,bookmarked,reviewed,notes,timestamp)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    ''', rows)
    cur.execute('INSERT INTO sites_fts(rowid,url,title,preview,category) SELECT id,url,title,preview,category FROM sites')
    con.commit()

    total = cur.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
    clean = cur.execute("SELECT COUNT(*) FROM sites WHERE noise=0").fetchone()[0]
    print(f"Done. {total} sites in {args.output} ({clean} clean, {total-clean} filtered as noise)")
    con.close()

if __name__ == '__main__':
    main()
