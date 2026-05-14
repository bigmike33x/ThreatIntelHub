"""
V2 — Dark Crawler dashboard backed by SQLite
───────────────────────────────────────────────────────
Run:  python server.py
Open: http://localhost:8765
"""
import http.server, socketserver, threading, subprocess
import json, sys, sqlite3, time
from pathlib import Path
from urllib.parse import urlparse, parse_qs

BASE_DIR = Path(__file__).parent
DB_PATH  = BASE_DIR / "crawler.db"
RESULTS  = BASE_DIR / "results.jsonl"
PORT     = 8765

crawler_process = None
crawler_lock    = threading.Lock()

# ── DB helpers ─────────────────────────────────────────────────────────────────
def db():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    return con

def ensure_db():
    """Create DB from results.jsonl if it doesn't exist yet."""
    if not DB_PATH.exists() and RESULTS.exists():
        import migrate_to_db
        migrate_to_db.main()

def ingest_new():
    """Append any new lines from results.jsonl into the DB."""
    if not RESULTS.exists(): return 0
    import time as _time

    NOISE_KWS = ['gift card','clone card','bitcoin generator','cashgod','seized by',
                 '403 forbidden','index of /','redirect shortly','link disabled',
                 'buy now','add to cart','checkout','exploit for sale','cvv','fullz']
    BOOST_KWS = {'library':6,'archive':6,'securedrop':8,'wiki':4,'research':5,
                 'journalism':7,'pgp':5,'encryption':4,'forum':3,'news':4,
                 'tails':5,'whonix':5,'privacy':3,'open source':4,'directory':3}
    CATEGORY_RULES = [
        ("Search Engines",     ["search engine","index","ahmia","torch","searx"]),
        ("Wikis & Directories",["wiki","hidden wiki","link list","catalog","directory"]),
        ("Forums",             ["forum","board","thread","community","chan","bbs"]),
        ("News & Media",       ["news","article","press","journalist","media","bbc"]),
        ("Chat & Messaging",   ["chat","jabber","xmpp","irc","messenger"]),
        ("Email",              ["email","mail","smtp","webmail"]),
        ("Blogs",              ["blog","personal","diary","journal"]),
        ("Markets",            ["market","shop","store","buy","sell","vendor"]),
        ("Technology",         ["security","hacking","ctf","tech","software","code"]),
        ("Privacy Tools",      ["privacy","anonymous","vpn","encryption","pgp","tails","whonix"]),
        ("Libraries",          ["library","archive","book","ebook","pdf","document"]),
        ("Whistleblower",      ["leak","whistle","securedrop","classified"]),
        ("Finance & Crypto",   ["bitcoin","crypto","wallet","exchange","monero"]),
        ("Hosting",            ["hosting","host","server","vps","domain"]),
    ]
    def cat(e):
        text = f"{e.get('title','')} {e.get('body_preview','')}".lower()
        for c, kws in CATEGORY_RULES:
            if any(kw in text for kw in kws): return c
        return "Uncategorized"
    def sc(e):
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

    con = db()
    cur = con.cursor()
    existing = set(r[0] for r in cur.execute("SELECT url FROM sites").fetchall())
    new_count = 0
    with open(RESULTS, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                e = json.loads(line)
                url = e.get('url','')
                if not url or url in existing: continue
                host = url.split('/')[2] if '//' in url else url
                s = sc(e)
                noise = 1 if (e.get('status')!=200 or len((e.get('body_preview') or '').strip())<20 or s<-5) else 0
                cur.execute('''INSERT OR IGNORE INTO sites
                    (url,host,title,status,preview,category,score,noise,bookmarked,reviewed,notes,timestamp)
                    VALUES (?,?,?,?,?,?,?,?,0,0,'',?)''',
                    (url,host,e.get('title',''),e.get('status',0),
                     e.get('body_preview',''),cat(e),s,noise,
                     e.get('timestamp',int(_time.time()))))
                if cur.lastrowid:
                    cur.execute('INSERT INTO sites_fts(rowid,url,title,preview,category) VALUES (?,?,?,?,?)',
                        (cur.lastrowid,url,e.get('title',''),e.get('body_preview',''),cat(e)))
                    new_count += 1
                    existing.add(url)
            except: pass
    con.commit()
    con.close()
    return new_count

def crawler_status():
    with crawler_lock:
        if crawler_process is None: return "idle"
        return "running" if crawler_process.poll() is None else "finished"

def start_crawler():
    global crawler_process
    with crawler_lock:
        if crawler_process and crawler_process.poll() is None:
            return {"status":"already_running"}
        crawler_process = subprocess.Popen(
            [sys.executable,"-m","scrapy","crawl","onion_spider"],
            cwd=str(BASE_DIR), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"status":"started"}

def stop_crawler():
    global crawler_process
    with crawler_lock:
        if crawler_process and crawler_process.poll() is None:
            crawler_process.terminate()
            return {"status":"stopped"}
        return {"status":"not_running"}

# ── HTTP handler ────────────────────────────────────────────────────────────────
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

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)
        g  = lambda k,d="": qs.get(k,[d])[0]

        if p.path == "/":
            body = DASHBOARD_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",len(body))
            self.end_headers()
            self.wfile.write(body)

        elif p.path == "/api/start":  self.send_json(start_crawler())
        elif p.path == "/api/stop":   self.send_json(stop_crawler())

        elif p.path == "/api/status":
            new = ingest_new()
            con = db()
            total = con.execute("SELECT COUNT(*) FROM sites WHERE noise=0").fetchone()[0]
            cats  = con.execute("SELECT COUNT(DISTINCT category) FROM sites WHERE noise=0").fetchone()[0]
            con.close()
            self.send_json({"status":crawler_status(),"total":total,"cats":cats,"new":new})

        elif p.path == "/api/sites":
            q        = g("q")
            cat      = g("cat")
            view     = g("view","clean")   # clean|noise|bookmarked|reviewed
            sort     = g("sort","score")   # score|newest|alpha
            page     = int(g("page","1"))
            per_page = 50
            offset   = (page-1)*per_page

            con = db()
            where, params = [], []

            if view == "clean":      where.append("noise=0")
            elif view == "noise":    where.append("noise=1")
            elif view == "bookmarked": where.append("bookmarked=1")
            elif view == "reviewed": where.append("reviewed=1")

            if cat and cat != "all": where.append("category=?"); params.append(cat)

            if q:
                where.append("id IN (SELECT rowid FROM sites_fts WHERE sites_fts MATCH ?)")
                params.append(q + "*")

            w = ("WHERE " + " AND ".join(where)) if where else ""

            order = {"score":"score DESC,title ASC","newest":"timestamp DESC","alpha":"title ASC"}.get(sort,"score DESC")

            total = con.execute(f"SELECT COUNT(*) FROM sites {w}", params).fetchone()[0]
            rows  = con.execute(f"SELECT * FROM sites {w} ORDER BY {order} LIMIT ? OFFSET ?",
                                params+[per_page,offset]).fetchall()
            sites = [dict(r) for r in rows]
            con.close()
            self.send_json({"sites":sites,"total":total,"page":page,"per_page":per_page})

        elif p.path == "/api/categories":
            con = db()
            rows = con.execute('''SELECT category, COUNT(*) as count
                FROM sites WHERE noise=0 GROUP BY category ORDER BY count DESC''').fetchall()
            con.close()
            self.send_json([dict(r) for r in rows])

        elif p.path == "/api/bookmark":
            site_id = int(g("id","0"))
            val     = int(g("val","1"))
            con = db()
            con.execute("UPDATE sites SET bookmarked=? WHERE id=?", (val,site_id))
            con.commit(); con.close()
            self.send_json({"ok":True})

        elif p.path == "/api/reviewed":
            site_id = int(g("id","0"))
            val     = int(g("val","1"))
            con = db()
            con.execute("UPDATE sites SET reviewed=? WHERE id=?", (val,site_id))
            con.commit(); con.close()
            self.send_json({"ok":True})

        elif p.path == "/api/note":
            site_id = int(g("id","0"))
            note    = g("note","")
            con = db()
            con.execute("UPDATE sites SET notes=? WHERE id=?", (note,site_id))
            con.commit(); con.close()
            self.send_json({"ok":True})

        elif p.path == "/api/top":
            con = db()
            rows = con.execute('''SELECT * FROM sites WHERE noise=0
                ORDER BY score DESC LIMIT 30''').fetchall()
            con.close()
            self.send_json([dict(r) for r in rows])

        else:
            self.send_response(404); self.end_headers()


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dark Crawler</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600&display=swap');
:root{
  --bg:#080b0f;--surface:#0d1117;--surface2:#111820;--border:#1c2333;
  --accent:#00ff9d;--accent2:#00c8ff;--danger:#ff4d6d;--warn:#ffaa00;
  --text:#b8ccd8;--dim:#3a5060;--dim2:#2a3848;

  /* Custom easing curves — avoid built-in easings */
  --ease-out:   cubic-bezier(0.23, 1, 0.32, 1);
  --ease-in-out:cubic-bezier(0.77, 0, 0.175, 1);
  --ease-drawer:cubic-bezier(0.32, 0.72, 0, 1);
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Exo 2',sans-serif;font-weight:300;height:100vh;display:flex;flex-direction:column;overflow:hidden;}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.05) 2px,rgba(0,0,0,.05) 4px);pointer-events:none;z-index:9999;}

/* ── HEADER ── */
header{display:flex;align-items:center;gap:16px;padding:12px 28px;border-bottom:1px solid var(--border);background:linear-gradient(90deg,rgba(0,255,157,.04),transparent);flex-shrink:0;}
.logo{font-family:'Share Tech Mono',monospace;font-size:1.2rem;color:var(--accent);letter-spacing:.15em;text-shadow:0 0 16px rgba(0,255,157,.3);}
.logo span{color:var(--dim);}
.hstats{display:flex;gap:24px;margin-left:auto;}
.hstat-val{font-family:'Share Tech Mono',monospace;font-size:1.2rem;color:var(--accent2);}
.hstat-lbl{font-size:.62rem;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;}

/* ── STATUS BAR ── */
.sbar{display:flex;align-items:center;gap:10px;padding:8px 28px;border-bottom:1px solid var(--border);background:rgba(0,0,0,.2);font-family:'Share Tech Mono',monospace;font-size:.72rem;flex-shrink:0;}
.dot{width:7px;height:7px;border-radius:50%;background:var(--dim);}
.dot.running{background:var(--accent);box-shadow:0 0 7px var(--accent);animation:pulse 1.2s infinite;}
.dot.finished{background:var(--accent2);}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* Buttons — scale on :active, fast feedback (120ms ease-out) */
.btn{
  background:transparent;border:1px solid var(--border);color:var(--dim);
  font-family:'Share Tech Mono',monospace;font-size:.72rem;padding:5px 14px;
  cursor:pointer;
  transition:border-color 150ms var(--ease-out),
             color        150ms var(--ease-out),
             transform    120ms var(--ease-out),
             opacity      120ms var(--ease-out);
}
.btn:hover{border-color:var(--accent);color:var(--accent);}
/* Physical press feedback */
@media (hover: hover) and (pointer: fine) {
  .btn:active{transform:scale(0.97);}
}
.btn.primary{border-color:var(--accent);color:var(--accent);}
.btn.danger:hover{border-color:var(--danger);color:var(--danger);}
.new-badge{background:var(--accent);color:#000;font-size:.62rem;padding:1px 7px;font-weight:700;letter-spacing:.04em;
  animation:badgePop 250ms var(--ease-out);}
@keyframes badgePop{from{opacity:0;transform:scale(0.7)}to{opacity:1;transform:scale(1)}}

/* ── TABS ── */
.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);flex-shrink:0;background:var(--surface);}
.tab{
  padding:9px 22px;font-family:'Share Tech Mono',monospace;font-size:.72rem;
  cursor:pointer;color:var(--dim);border-bottom:2px solid transparent;
  letter-spacing:.05em;
  transition:color 150ms var(--ease-out), border-color 150ms var(--ease-out);
}
/* Only show hover on real pointer devices */
@media (hover: hover) and (pointer: fine) {
  .tab:hover{color:var(--text);}
}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);}

/* ── LAYOUT ── */
.layout{display:flex;flex:1;overflow:hidden;}

/* SIDEBAR */
.sidebar{width:210px;border-right:1px solid var(--border);overflow-y:auto;flex-shrink:0;background:var(--surface);}
.sb-title{font-size:.6rem;color:var(--dim);letter-spacing:.12em;text-transform:uppercase;padding:10px 14px 6px;}
.cat-item{
  display:flex;align-items:center;gap:7px;padding:7px 14px;
  cursor:pointer;border-left:2px solid transparent;
  transition:background 120ms var(--ease-out), border-color 120ms var(--ease-out);
}
@media (hover: hover) and (pointer: fine) {
  .cat-item:hover{background:rgba(0,255,157,.03);}
}
.cat-item.active{border-left-color:var(--accent);background:rgba(0,255,157,.05);}
.cat-icon{font-size:.9rem;width:18px;text-align:center;}
.cat-name{font-size:.72rem;flex:1;color:var(--text);}
.cat-count{font-family:'Share Tech Mono',monospace;font-size:.68rem;color:var(--accent2);}
.cat-item.active .cat-name{color:var(--accent);}

/* MAIN */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0;}

/* TOOLBAR */
.toolbar{display:flex;gap:8px;align-items:center;padding:10px 18px;border-bottom:1px solid var(--border);flex-shrink:0;flex-wrap:wrap;}
.sw{position:relative;flex:1;min-width:180px;max-width:380px;}
.sw input{
  width:100%;background:var(--surface2);border:1px solid var(--border);
  color:var(--text);font-family:'Share Tech Mono',monospace;font-size:.78rem;
  padding:7px 10px 7px 30px;outline:none;
  transition:border-color 150ms var(--ease-out), box-shadow 150ms var(--ease-out);
}
.sw input:focus{border-color:var(--accent);box-shadow:0 0 8px rgba(0,255,157,.07);}
.sw::before{content:'⌕';position:absolute;left:9px;top:50%;transform:translateY(-50%);color:var(--dim);pointer-events:none;}
.sel{
  background:var(--surface2);border:1px solid var(--border);color:var(--text);
  font-family:'Share Tech Mono',monospace;font-size:.7rem;padding:7px 9px;
  outline:none;cursor:pointer;
  transition:border-color 150ms var(--ease-out);
}
.shown{font-family:'Share Tech Mono',monospace;font-size:.68rem;color:var(--dim);margin-left:auto;white-space:nowrap;}
.shown span{color:var(--accent);}
.live{font-size:.62rem;color:var(--accent);font-family:'Share Tech Mono',monospace;animation:pulse 1.5s infinite;}

/* CONTENT AREA */
.content{flex:1;overflow:hidden;display:flex;flex-direction:column;}

/* TOP PICKS panel */
#topPanel{display:none;flex:1;overflow-y:auto;padding:18px 22px;}
.top-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;}

/* Cards — enter with stagger, hover lifts smoothly */
.top-card{
  background:var(--surface);border:1px solid var(--border);padding:14px;
  cursor:pointer;position:relative;
  transition:border-color 180ms var(--ease-out),
             transform    180ms var(--ease-out),
             box-shadow   180ms var(--ease-out);
  /* Entry animation */
  opacity:0;transform:translateY(6px);
  animation:cardIn 280ms var(--ease-out) forwards;
}
@keyframes cardIn{to{opacity:1;transform:translateY(0);}}

/* Stagger delays for grid entries */
.top-card:nth-child(1){animation-delay:0ms;}
.top-card:nth-child(2){animation-delay:40ms;}
.top-card:nth-child(3){animation-delay:80ms;}
.top-card:nth-child(4){animation-delay:120ms;}
.top-card:nth-child(5){animation-delay:160ms;}
.top-card:nth-child(6){animation-delay:200ms;}
.top-card:nth-child(7){animation-delay:240ms;}
.top-card:nth-child(8){animation-delay:280ms;}
.top-card:nth-child(n+9){animation-delay:300ms;}

@media (hover: hover) and (pointer: fine) {
  .top-card:hover{
    border-color:var(--accent);
    transform:translateY(-2px);
    box-shadow:0 6px 24px rgba(0,255,157,.07);
  }
}
.top-card.bookmarked{border-color:var(--warn);}
.top-score{position:absolute;top:10px;right:10px;font-family:'Share Tech Mono',monospace;font-size:.7rem;color:var(--accent);background:rgba(0,255,157,.07);padding:2px 7px;border-radius:2px;}
.top-title{font-size:.85rem;font-weight:600;color:var(--text);margin-bottom:6px;padding-right:50px;line-height:1.3;}
.top-url{font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--accent2);margin-bottom:7px;word-break:break-all;}
.top-preview{font-size:.72rem;color:var(--dim);line-height:1.5;margin-bottom:8px;}
.top-cat{font-size:.62rem;color:var(--dim);letter-spacing:.05em;}
.top-actions{display:flex;gap:6px;margin-top:8px;}
.act-btn{
  background:transparent;border:1px solid var(--border);color:var(--dim);
  font-family:'Share Tech Mono',monospace;font-size:.62rem;padding:3px 8px;
  cursor:pointer;
  transition:border-color 150ms var(--ease-out),
             color        150ms var(--ease-out),
             transform    120ms var(--ease-out);
}
@media (hover: hover) and (pointer: fine) {
  .act-btn:hover{border-color:var(--accent);color:var(--accent);}
  .act-btn:active{transform:scale(0.96);}
}
.act-btn.on{border-color:var(--warn);color:var(--warn);}
.act-btn.rev.on{border-color:var(--accent2);color:var(--accent2);}

/* TABLE panel */
#tablePanel{flex:1;overflow:hidden;display:flex;flex-direction:column;}
.table-wrap{flex:1;overflow-y:auto;}
table{width:100%;border-collapse:collapse;font-size:.77rem;}
th{text-align:left;padding:7px 14px;font-family:'Share Tech Mono',monospace;font-size:.6rem;color:var(--dim);text-transform:uppercase;letter-spacing:.09em;border-bottom:1px solid var(--border);background:rgba(0,0,0,.28);position:sticky;top:0;z-index:10;}
td{padding:7px 14px;border-bottom:1px solid rgba(28,35,51,.55);vertical-align:top;line-height:1.5;}

/* Row hover — only on pointer devices */
@media (hover: hover) and (pointer: fine) {
  tr:hover td{background:rgba(0,255,157,.02);}
}

/* New row highlight — fades out using ease-out, not ease-in */
tr.new-row td{animation:hl 1.4s var(--ease-out) forwards;}
@keyframes hl{from{background:rgba(0,255,157,.13)}to{background:transparent}}

.td-url{font-family:'Share Tech Mono',monospace;font-size:.63rem;color:var(--accent2);word-break:break-all;max-width:200px;}
.td-url a{
  color:inherit;text-decoration:none;
  transition:color 120ms var(--ease-out);
}
@media (hover: hover) and (pointer: fine) {
  .td-url a:hover{color:var(--accent);}
}
.td-title{max-width:170px;color:var(--text);font-size:.78rem;}
.td-cat{font-size:.63rem;color:var(--dim);white-space:nowrap;}
.td-score{font-family:'Share Tech Mono',monospace;font-size:.68rem;text-align:center;}
.score-hi{color:var(--accent);}
.score-mid{color:var(--accent2);}
.score-lo{color:var(--dim);}
.td-preview{color:var(--dim);font-size:.68rem;max-width:280px;}
.td-actions{white-space:nowrap;}
.row-btn{
  background:transparent;border:1px solid var(--border);color:var(--dim);
  font-size:.6rem;padding:2px 6px;cursor:pointer;
  font-family:'Share Tech Mono',monospace;
  transition:border-color 120ms var(--ease-out),
             color        120ms var(--ease-out),
             transform    100ms var(--ease-out);
}
@media (hover: hover) and (pointer: fine) {
  .row-btn:hover{border-color:var(--accent);color:var(--accent);}
  .row-btn:active{transform:scale(0.95);}
}
.row-btn.on{border-color:var(--warn);color:var(--warn);}
.row-btn.rev.on{border-color:var(--accent2);color:var(--accent2);}

/* DETAIL DRAWER — iOS-like curve, 280ms */
#drawer{
  position:fixed;right:0;top:0;bottom:0;width:380px;
  background:var(--surface);border-left:1px solid var(--border);
  z-index:100;display:flex;flex-direction:column;
  transform:translateX(100%);
  transition:transform 280ms var(--ease-drawer);
}
#drawer.open{transform:translateX(0);}
.dr-header{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:10px;}
.dr-title{font-size:.95rem;font-weight:600;color:var(--text);flex:1;line-height:1.4;}
.dr-close{
  background:transparent;border:none;color:var(--dim);font-size:1.2rem;
  cursor:pointer;padding:0 4px;
  transition:color 120ms var(--ease-out), transform 120ms var(--ease-out);
}
@media (hover: hover) and (pointer: fine) {
  .dr-close:hover{color:var(--accent);}
  .dr-close:active{transform:scale(0.9);}
}
.dr-body{flex:1;overflow-y:auto;padding:16px 18px;}
.dr-url{font-family:'Share Tech Mono',monospace;font-size:.68rem;color:var(--accent2);margin-bottom:12px;word-break:break-all;}
.dr-url a{color:inherit;}
.dr-meta{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;}
.dr-tag{
  font-size:.62rem;padding:2px 8px;border:1px solid var(--border);
  color:var(--dim);font-family:'Share Tech Mono',monospace;
  /* Tags stagger in when drawer opens */
  opacity:0;animation:tagIn 200ms var(--ease-out) forwards;
}
.dr-tag:nth-child(1){animation-delay:60ms;}
.dr-tag:nth-child(2){animation-delay:100ms;}
.dr-tag:nth-child(3){animation-delay:140ms;}
@keyframes tagIn{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:translateY(0)}}
.dr-tag.green{border-color:var(--accent);color:var(--accent);}
.dr-tag.blue{border-color:var(--accent2);color:var(--accent2);}
.dr-section{font-size:.62rem;color:var(--dim);text-transform:uppercase;letter-spacing:.1em;margin:14px 0 6px;}
.dr-preview{font-size:.78rem;color:var(--text);line-height:1.7;white-space:pre-wrap;}
.dr-actions{display:flex;gap:8px;margin-top:14px;}
.dr-note{
  width:100%;background:var(--surface2);border:1px solid var(--border);
  color:var(--text);font-family:'Share Tech Mono',monospace;font-size:.72rem;
  padding:8px;resize:vertical;outline:none;margin-top:6px;min-height:70px;
  transition:border-color 150ms var(--ease-out);
}
.dr-note:focus{border-color:var(--accent);}
.dr-save{margin-top:6px;}

/* PAGINATION */
.pagination{display:flex;align-items:center;justify-content:center;gap:4px;padding:9px;border-top:1px solid var(--border);flex-shrink:0;}
.pg{
  background:transparent;border:1px solid var(--border);color:var(--dim);
  font-family:'Share Tech Mono',monospace;font-size:.66rem;padding:4px 9px;
  cursor:pointer;
  transition:border-color 120ms var(--ease-out),
             color        120ms var(--ease-out),
             transform    100ms var(--ease-out);
}
@media (hover: hover) and (pointer: fine) {
  .pg:hover{border-color:var(--accent);color:var(--accent);}
  .pg:active{transform:scale(0.95);}
}
.pg.active{border-color:var(--accent);color:var(--accent);background:rgba(0,255,157,.06);}
.pg:disabled{opacity:.3;cursor:default;}
.pg-info{font-family:'Share Tech Mono',monospace;font-size:.66rem;color:var(--dim);}

/* LOG */
.log{height:90px;overflow-y:auto;background:rgba(0,0,0,.3);padding:5px 18px;font-family:'Share Tech Mono',monospace;font-size:.63rem;color:var(--dim);flex-shrink:0;border-top:1px solid var(--border);}
.ll{padding:1px 0;animation:llIn 200ms var(--ease-out);}
@keyframes llIn{from{opacity:0;transform:translateX(-4px)}to{opacity:1;transform:translateX(0)}}
.ll.g{color:var(--accent);}
.ll.b{color:var(--accent2);}
.ll.r{color:var(--danger);}

.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:10px;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:.8rem;}
.empty-icon{font-size:2.2rem;opacity:.25;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.cur{animation:blink 1s infinite;color:var(--accent);}

/* Respect prefers-reduced-motion */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
</style>
</head>
<body>

<header>
  <div class="logo">DARK<span>/</span>CRAWLER <span class="cur">█</span></div>
  <div class="hstats">
    <div><div class="hstat-val" id="hTotal">—</div><div class="hstat-lbl">clean sites</div></div>
    <div><div class="hstat-val" id="hBookmarks">—</div><div class="hstat-lbl">bookmarked</div></div>
    <div><div class="hstat-val" id="hCats">—</div><div class="hstat-lbl">categories</div></div>
  </div>
</header>

<div class="sbar">
  <div class="dot idle" id="dot"></div>
  <span id="stText">Idle</span>
  <span id="newBadge"></span>
  <div style="margin-left:auto;display:flex;gap:6px;">
    <button class="btn primary" id="btnStart" onclick="startCrawl()">▶ Start</button>
    <button class="btn danger"  id="btnStop"  onclick="stopCrawl()" disabled>■ Stop</button>
  </div>
</div>

<div class="tabs">
  <div class="tab active" onclick="setTab('top')"    id="tab-top">⭐ Top Picks</div>
  <div class="tab"        onclick="setTab('browse')" id="tab-browse">🔍 Browse</div>
  <div class="tab"        onclick="setTab('bookmarks')" id="tab-bookmarks">🔖 Bookmarks</div>
  <div class="tab"        onclick="setTab('noise')"  id="tab-noise">🗑 Filtered Out</div>
</div>

<div class="layout">
  <div class="sidebar" id="sidebar">
    <div class="sb-title">Categories</div>
    <div id="catList"></div>
  </div>

  <div class="main">
    <div class="toolbar">
      <div class="sw"><input type="text" id="q" placeholder="search titles, urls, previews…" oninput="onSearch()"></div>
      <span class="live" id="liveInd" style="display:none">● LIVE</span>
      <select class="sel" id="sortSel" onchange="load()">
        <option value="score">Best match</option>
        <option value="newest">Newest</option>
        <option value="alpha">A → Z</option>
      </select>
      <div class="shown">showing <span id="shown">—</span> / <span id="totalShown">—</span></div>
    </div>

    <div class="content">
      <!-- Top picks grid -->
      <div id="topPanel"></div>
      <!-- Browse table -->
      <div id="tablePanel" style="display:none;">
        <div class="table-wrap" id="tableWrap"></div>
        <div id="pgEl"></div>
      </div>
    </div>

    <div class="log" id="log"></div>
  </div>
</div>

<!-- Detail drawer -->
<div id="drawer">
  <div class="dr-header">
    <div class="dr-title" id="drTitle">—</div>
    <button class="dr-close" onclick="closeDrawer()">✕</button>
  </div>
  <div class="dr-body">
    <div class="dr-url" id="drUrl"></div>
    <div class="dr-meta" id="drMeta"></div>
    <div class="dr-section">Preview</div>
    <div class="dr-preview" id="drPreview"></div>
    <div class="dr-section">Notes</div>
    <textarea class="dr-note" id="drNote" placeholder="Add your notes here…"></textarea>
    <div class="dr-actions">
      <button class="btn dr-save" onclick="saveNote()">Save Note</button>
      <button class="btn" id="drBm" onclick="toggleDrawerBookmark()">🔖 Bookmark</button>
      <button class="btn" id="drRv" onclick="toggleDrawerReviewed()">✓ Reviewed</button>
    </div>
  </div>
</div>

<script>
const ICONS = {
  "Search Engines":"🔍","Wikis & Directories":"📖","Forums":"💬",
  "News & Media":"📰","Chat & Messaging":"💭","Email":"✉️",
  "Blogs":"✍️","Markets":"🛒","Technology":"⚙️","Privacy Tools":"🔒",
  "Libraries":"📚","Whistleblower":"📡","Finance & Crypto":"₿",
  "Hosting":"🖥️","Uncategorized":"❓"
};

let currentTab  = 'top';
let activeCat   = 'all';
let currentPage = 1;
let totalItems  = 0;
let pollTimer   = null;
let drawerSite  = null;
let searchTimer = null;

const PER_PAGE = 50;

// ── Tab switching ──────────────────────────────────────────────────────────────
function setTab(tab) {
  currentTab = tab;
  currentPage = 1;
  activeCat = 'all';
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-'+tab).classList.add('active');
  const showSidebar = (tab === 'browse');
  document.getElementById('sidebar').style.display = showSidebar ? '' : 'none';
  document.getElementById('topPanel').style.display   = (tab === 'top') ? '' : 'none';
  document.getElementById('tablePanel').style.display = (tab !== 'top') ? '' : 'none';
  buildCatList();
  load();
}

// ── Load data ──────────────────────────────────────────────────────────────────
async function load() {
  if (currentTab === 'top') { loadTop(); return; }
  const q    = document.getElementById('q').value;
  const sort = document.getElementById('sortSel').value;
  const view = currentTab === 'bookmarks' ? 'bookmarked' :
               currentTab === 'noise'     ? 'noise' : 'clean';

  const params = new URLSearchParams({q, sort, view, page:currentPage,
    cat: activeCat === 'all' ? '' : activeCat});
  const res = await fetch('/api/sites?' + params).then(r=>r.json()).catch(()=>null);
  if (!res) return;

  totalItems = res.total;
  document.getElementById('shown').textContent      = res.sites.length.toLocaleString();
  document.getElementById('totalShown').textContent = res.total.toLocaleString();
  renderTable(res.sites);
  renderPagination(res.total);
}

async function loadTop() {
  const res = await fetch('/api/top').then(r=>r.json()).catch(()=>null);
  if (!res) return;
  document.getElementById('shown').textContent      = res.length;
  document.getElementById('totalShown').textContent = res.length;
  renderTopGrid(res);
}

// ── Top picks grid ─────────────────────────────────────────────────────────────
function renderTopGrid(sites) {
  const el = document.getElementById('topPanel');
  if (!sites.length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">⭐</div>No top picks yet — start a crawl</div>';
    return;
  }
  el.innerHTML = '<div class="top-grid">' + sites.map(s => {
    const title   = esc(s.title || '[no title]');
    const url     = esc(s.url || '');
    const preview = esc((s.preview || '').substring(0, 140));
    const cat     = s.category || 'Uncategorized';
    const bm      = s.bookmarked ? 'on' : '';
    const rv      = s.reviewed   ? 'rev on' : 'rev';
    return `<div class="top-card ${s.bookmarked?'bookmarked':''}" onclick="openDrawer(${s.id})">
      <div class="top-score">+${s.score}</div>
      <div class="top-title">${title}</div>
      <div class="top-url">${url}</div>
      <div class="top-preview">${preview}</div>
      <div class="top-cat">${ICONS[cat]||'🌐'} ${cat}</div>
      <div class="top-actions" onclick="event.stopPropagation()">
        <button class="act-btn ${bm}" onclick="toggleBm(${s.id},this)">🔖 ${s.bookmarked?'saved':'save'}</button>
        <button class="act-btn ${rv}" onclick="toggleRv(${s.id},this)">✓ ${s.reviewed?'reviewed':'mark read'}</button>
        <a href="${url}" target="_blank" onclick="event.stopPropagation()"><button class="act-btn">↗ open</button></a>
      </div>
    </div>`;
  }).join('') + '</div>';
}

// ── Table ──────────────────────────────────────────────────────────────────────
function renderTable(sites) {
  const wrap = document.getElementById('tableWrap');
  if (!sites.length) {
    wrap.innerHTML = `<div class="empty"><div class="empty-icon">🔍</div>No results found</div>`;
    return;
  }
  const rows = sites.map(s => {
    const sc    = s.score >= 15 ? 'score-hi' : s.score >= 5 ? 'score-mid' : 'score-lo';
    const url   = esc(s.url || '');
    const title = esc(s.title || '[no title]');
    const prev  = esc((s.preview || '').substring(0,100));
    const cat   = s.category || 'Uncategorized';
    const bm    = s.bookmarked ? 'on' : '';
    const rv    = s.reviewed   ? 'rev on' : 'rev';
    return `<tr>
      <td class="td-url"><a href="${url}" target="_blank">${url}</a></td>
      <td class="td-title" style="cursor:pointer" onclick="openDrawer(${s.id})">${title}</td>
      <td class="td-cat">${ICONS[cat]||'🌐'} ${cat}</td>
      <td class="td-score ${sc}">${s.score >= 0 ? '+' : ''}${s.score}</td>
      <td class="td-preview">${prev}</td>
      <td class="td-actions">
        <button class="row-btn ${bm}" onclick="toggleBm(${s.id},this)">🔖</button>
        <button class="row-btn ${rv}" onclick="toggleRv(${s.id},this)">✓</button>
        <button class="row-btn" onclick="openDrawer(${s.id})">detail</button>
      </td>
    </tr>`;
  }).join('');
  wrap.innerHTML = `<table>
    <thead><tr><th>URL</th><th>Title</th><th>Category</th><th>Score</th><th>Preview</th><th></th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

// ── Pagination ─────────────────────────────────────────────────────────────────
function renderPagination(total) {
  const pages = Math.ceil(total / PER_PAGE);
  const el = document.getElementById('pgEl');
  if (pages <= 1) { el.innerHTML=''; return; }
  let b = `<button class="pg" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>← prev</button>`;
  let s=Math.max(1,currentPage-3), e=Math.min(pages,s+6);
  if(s>1) b+=`<button class="pg" onclick="goPage(1)">1</button><span class="pg-info">…</span>`;
  for(let i=s;i<=e;i++) b+=`<button class="pg ${i===currentPage?'active':''}" onclick="goPage(${i})">${i}</button>`;
  if(e<pages) b+=`<span class="pg-info">…</span><button class="pg" onclick="goPage(${pages})">${pages}</button>`;
  b+=`<button class="pg" onclick="goPage(${currentPage+1})" ${currentPage===pages?'disabled':''}>next →</button>`;
  b+=`<span class="pg-info">page ${currentPage} of ${pages}</span>`;
  el.innerHTML = `<div class="pagination">${b}</div>`;
}

function goPage(p) {
  const pages = Math.ceil(totalItems/PER_PAGE);
  if(p<1||p>pages) return;
  currentPage=p; load();
  document.getElementById('tableWrap').scrollTo({top:0,behavior:'smooth'});
}

// ── Category sidebar ───────────────────────────────────────────────────────────
async function buildCatList() {
  if (currentTab !== 'browse') return;
  const cats = await fetch('/api/categories').then(r=>r.json()).catch(()=>[]);
  const total = cats.reduce((a,c)=>a+c.count,0);
  const el = document.getElementById('catList');
  el.innerHTML = '';
  const all = document.createElement('div');
  all.className = 'cat-item'+(activeCat==='all'?' active':'');
  all.innerHTML = `<span class="cat-icon">🌐</span><span class="cat-name">All Sites</span><span class="cat-count">${total.toLocaleString()}</span>`;
  all.onclick = () => { activeCat='all'; currentPage=1; buildCatList(); load(); };
  el.appendChild(all);
  for (const c of cats) {
    const d = document.createElement('div');
    d.className = 'cat-item'+(activeCat===c.category?' active':'');
    d.innerHTML = `<span class="cat-icon">${ICONS[c.category]||'🌐'}</span><span class="cat-name">${c.category}</span><span class="cat-count">${c.count.toLocaleString()}</span>`;
    d.onclick = () => { activeCat=c.category; currentPage=1; buildCatList(); load(); };
    el.appendChild(d);
  }
}

// ── Detail drawer ──────────────────────────────────────────────────────────────
async function openDrawer(id) {
  const res = await fetch(`/api/sites?view=all&q=&page=1`).then(r=>r.json()).catch(()=>null);
  // Fetch all views to find by id
  const r = await fetch(`/api/sites?view=clean&sort=score&page=1&per_page=9999`).then(r=>r.json()).catch(()=>null);
  // simpler: refetch with direct id approach via search
  drawerSite = {id};
  // Use a bookmark toggle as a proxy to get site data — instead fetch from top or current table
  // Actually just find it in DOM data we already have by re-querying
  const data = await fetch(`/api/sites?view=clean&sort=score&q=`).then(r=>r.json()).catch(()=>null);
  // Best approach: store sites in memory
  showDrawerById(id);
}

let _siteCache = {};
function cacheSites(sites){ sites.forEach(s => _siteCache[s.id]=s); }

async function showDrawerById(id) {
  let s = _siteCache[id];
  if (!s) {
    // fallback: we don't have it cached, just show id
    addLog(`Opening site ${id}…`,'b');
    return;
  }
  drawerSite = s;
  document.getElementById('drTitle').textContent   = s.title || '[no title]';
  document.getElementById('drUrl').innerHTML       = `<a href="${esc(s.url)}" target="_blank">${esc(s.url)}</a>`;
  document.getElementById('drPreview').textContent = s.preview || '(no preview)';
  document.getElementById('drNote').value          = s.notes || '';
  const bm = s.bookmarked ? 'on' : '';
  const rv = s.reviewed   ? 'rev on' : '';
  document.getElementById('drBm').className = `btn ${bm}`;
  document.getElementById('drBm').textContent = s.bookmarked ? '🔖 Saved' : '🔖 Bookmark';
  document.getElementById('drRv').className = `btn ${rv}`;
  document.getElementById('drRv').textContent = s.reviewed ? '✓ Reviewed' : '✓ Mark Reviewed';
  const sc = s.score >= 15 ? 'green' : s.score >= 5 ? 'blue' : '';
  document.getElementById('drMeta').innerHTML =
    `<span class="dr-tag ${sc}">Score: ${s.score>=0?'+':''}${s.score}</span>
     <span class="dr-tag blue">${ICONS[s.category]||''} ${s.category}</span>
     <span class="dr-tag">HTTP ${s.status}</span>`;
  document.getElementById('drawer').classList.add('open');
}

function closeDrawer(){ document.getElementById('drawer').classList.remove('open'); }

async function saveNote() {
  if (!drawerSite) return;
  const note = document.getElementById('drNote').value;
  await fetch(`/api/note?id=${drawerSite.id}&note=${encodeURIComponent(note)}`);
  if (_siteCache[drawerSite.id]) _siteCache[drawerSite.id].notes = note;
  addLog('Note saved.','g');
}

async function toggleDrawerBookmark() {
  if (!drawerSite) return;
  const newVal = drawerSite.bookmarked ? 0 : 1;
  await fetch(`/api/bookmark?id=${drawerSite.id}&val=${newVal}`);
  drawerSite.bookmarked = newVal;
  if (_siteCache[drawerSite.id]) _siteCache[drawerSite.id].bookmarked = newVal;
  document.getElementById('drBm').textContent = newVal ? '🔖 Saved' : '🔖 Bookmark';
  document.getElementById('drBm').className = newVal ? 'btn on' : 'btn';
  updateBookmarkCount();
}

async function toggleDrawerReviewed() {
  if (!drawerSite) return;
  const newVal = drawerSite.reviewed ? 0 : 1;
  await fetch(`/api/reviewed?id=${drawerSite.id}&val=${newVal}`);
  drawerSite.reviewed = newVal;
  if (_siteCache[drawerSite.id]) _siteCache[drawerSite.id].reviewed = newVal;
  document.getElementById('drRv').textContent = newVal ? '✓ Reviewed' : '✓ Mark Reviewed';
  document.getElementById('drRv').className = newVal ? 'btn rev on' : 'btn rev';
}

// ── Inline bookmark/reviewed toggles ──────────────────────────────────────────
async function toggleBm(id, btn) {
  const isOn = btn.classList.contains('on');
  await fetch(`/api/bookmark?id=${id}&val=${isOn?0:1}`);
  btn.classList.toggle('on');
  btn.textContent = isOn ? '🔖 save' : '🔖 saved';
  if(_siteCache[id]) _siteCache[id].bookmarked = isOn?0:1;
  updateBookmarkCount();
}

async function toggleRv(id, btn) {
  const isOn = btn.classList.contains('on');
  await fetch(`/api/reviewed?id=${id}&val=${isOn?0:1}`);
  btn.classList.toggle('on');
  btn.classList.toggle('rev');
  if(_siteCache[id]) _siteCache[id].reviewed = isOn?0:1;
}

// ── Search ─────────────────────────────────────────────────────────────────────
function onSearch() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { currentPage=1; load(); }, 300);
}

// ── Polling ────────────────────────────────────────────────────────────────────
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(poll, 3000);
}

async function poll() {
  const st = await fetch('/api/status').then(r=>r.json()).catch(()=>null);
  if (!st) return;
  updateDot(st.status);
  updateHeader(st);
  if (st.new > 0) {
    addLog(`+${st.new} new sites ingested (total: ${st.total.toLocaleString()})`, 'g');
    if (currentTab === 'top') loadTop();
  }
  if (st.status==='finished'||st.status==='idle') {
    clearInterval(pollTimer);
    document.getElementById('btnStart').disabled = false;
    document.getElementById('btnStop').disabled  = true;
    document.getElementById('liveInd').style.display = 'none';
  }
}

async function updateBookmarkCount() {
  const r = await fetch('/api/sites?view=bookmarked&q=&page=1').then(r=>r.json()).catch(()=>null);
  if (r) document.getElementById('hBookmarks').textContent = r.total.toLocaleString();
}

function updateDot(state) {
  const d = document.getElementById('dot');
  d.className = 'dot ' + state;
  document.getElementById('stText').textContent = state==='running'?'Crawling…':state==='finished'?'Finished':'Idle';
}

function updateHeader(st) {
  document.getElementById('hTotal').textContent = (st.total||0).toLocaleString();
  document.getElementById('hCats').textContent  = (st.cats||0).toLocaleString();
}

async function startCrawl() {
  await fetch('/api/start');
  document.getElementById('btnStart').disabled = true;
  document.getElementById('btnStop').disabled  = false;
  document.getElementById('liveInd').style.display = '';
  addLog('Crawl started…','g');
  startPolling();
}

async function stopCrawl() {
  await fetch('/api/stop');
  document.getElementById('btnStart').disabled = false;
  document.getElementById('btnStop').disabled  = true;
  document.getElementById('liveInd').style.display = 'none';
  addLog('Crawl stopped.','r');
}

function addLog(msg,type='') {
  const el=document.getElementById('log');
  const d=document.createElement('div');
  d.className='ll '+type;
  d.textContent=`[${new Date().toLocaleTimeString()}] ${msg}`;
  el.appendChild(d);
  el.scrollTop=el.scrollHeight;
  while(el.children.length>150) el.removeChild(el.firstChild);
}

function esc(s){ return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ── Override load to cache sites ───────────────────────────────────────────────
const _origLoad = load;
window.load = async function() {
  if (currentTab === 'top') { loadTop(); return; }
  const q    = document.getElementById('q').value;
  const sort = document.getElementById('sortSel').value;
  const view = currentTab==='bookmarks'?'bookmarked':currentTab==='noise'?'noise':'clean';
  const params = new URLSearchParams({q,sort,view,page:currentPage,cat:activeCat==='all'?'':activeCat});
  const res = await fetch('/api/sites?'+params).then(r=>r.json()).catch(()=>null);
  if (!res) return;
  cacheSites(res.sites);
  totalItems = res.total;
  document.getElementById('shown').textContent      = res.sites.length.toLocaleString();
  document.getElementById('totalShown').textContent = res.total.toLocaleString();
  renderTable(res.sites);
  renderPagination(res.total);
};

// Also cache top picks
const _origLoadTop = loadTop;
window.loadTop = async function() {
  const res = await fetch('/api/top').then(r=>r.json()).catch(()=>null);
  if (!res) return;
  cacheSites(res);
  document.getElementById('shown').textContent      = res.length;
  document.getElementById('totalShown').textContent = res.length;
  renderTopGrid(res);
};

// Fix openDrawer to use cache
window.openDrawer = function(id) {
  showDrawerById(id);
};

// ── Init ───────────────────────────────────────────────────────────────────────
(async function init() {
  const st = await fetch('/api/status').then(r=>r.json()).catch(()=>null);
  if (st) { updateDot(st.status); updateHeader(st); }
  await updateBookmarkCount();
  setTab('top');
  startPolling();
  if (st && st.status==='running') {
    document.getElementById('btnStart').disabled = true;
    document.getElementById('btnStop').disabled  = false;
    document.getElementById('liveInd').style.display = '';
    addLog('Crawl already running — reconnected.','g');
  } else {
    addLog(`Database loaded. ${(st&&st.total)||0} clean sites ready.`,'b');
  }
})();
</script>
</body>
</html>"""

if __name__ == "__main__":
    ensure_db()
    print(f"\n  Dark Crawler v2")
    print(f"  ────────────────────────────")
    print(f"  http://localhost:{PORT}")
    print(f"  Ctrl+C to stop.\n")
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.allow_reuse_address = True
        try: httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")
            stop_crawler()
