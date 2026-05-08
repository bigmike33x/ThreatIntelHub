"""
server.py  —  Crawler control + live results server
────────────────────────────────────────────────────
Run:  python server.py
Then open:  http://localhost:8765  in your browser
"""

import http.server
import socketserver
import threading
import subprocess
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs

BASE_DIR     = Path(__file__).parent
RESULTS_FILE = BASE_DIR / "results.jsonl"
PORT         = 8765

CATEGORY_RULES = [
    ("Search Engines & Indexes",  ["search engine","index","ahmia","torch","haystack","not evil","searx"]),
    ("Wikis & Directories",       ["wiki","hidden wiki","link list","onion list","catalog","directory of"]),
    ("Forums & Communities",      ["forum","board","thread","post","reply","community","discussion","chan","bbs"]),
    ("News & Media",              ["news","article","press","journalist","media","report","daily","times","herald"]),
    ("Chat & Messaging",          ["chat","message","jabber","xmpp","irc","instant message","messenger"]),
    ("Email & Communication",     ["email","mail","smtp","webmail"]),
    ("Blogs & Personal Sites",    ["blog","personal","diary","journal","my site","about me","portfolio"]),
    ("Markets & Commerce",        ["market","shop","store","buy","sell","vendor","listing","product","price","checkout"]),
    ("Technology & Security",     ["security","hacking","exploit","vulnerability","ctf","tech","software","code","programming","developer"]),
    ("Privacy & Anonymity",       ["privacy","anonymous","vpn","tor","encryption","pgp","opsec","secure","tails","whonix"]),
    ("Libraries & Archives",      ["library","archive","book","document","paper","collection","ebook","pdf"]),
    ("Leak & Whistleblower",      ["leak","whistle","classified","secret","disclosure","securedrop"]),
    ("Finance & Crypto",          ["bitcoin","crypto","wallet","exchange","monero","ethereum","currency","finance"]),
    ("Hosting & Services",        ["hosting","host","server","vps","domain","service provider"]),
]

def categorize(entry):
    text = f"{entry.get('title','')} {entry.get('body_preview','')}".lower()
    for cat, kws in CATEGORY_RULES:
        if any(kw in text for kw in kws):
            return cat
    return "Uncategorized"

crawler_process = None
crawler_lock    = threading.Lock()

def start_crawler():
    global crawler_process
    with crawler_lock:
        if crawler_process and crawler_process.poll() is None:
            return {"status": "already_running"}
        crawler_process = subprocess.Popen(
            [sys.executable, "-m", "scrapy", "crawl", "onion_spider"],
            cwd=str(BASE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return {"status": "started"}

def stop_crawler():
    global crawler_process
    with crawler_lock:
        if crawler_process and crawler_process.poll() is None:
            crawler_process.terminate()
            return {"status": "stopped"}
        return {"status": "not_running"}

def crawler_status():
    with crawler_lock:
        if crawler_process is None:
            return "idle"
        if crawler_process.poll() is None:
            return "running"
        return "finished"

def load_results(since_line=0):
    """Return new entries since `since_line`, deduped by URL."""
    entries = []
    if not RESULTS_FILE.exists():
        return entries, 0
    with open(RESULTS_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    total = len(lines)
    seen_urls = set()
    # Dedup across ALL lines (not just new ones) so UI never shows dupes
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            seen_urls.add(e.get("url",""))
        except:
            pass
    # Now only return the new lines, but still check url uniqueness
    seen_new = set()
    for line in lines[since_line:]:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            url = e.get("url","")
            if url and url not in seen_new:
                seen_new.add(url)
                e["category"] = categorize(e)
                entries.append(e)
        except:
            pass
    return entries, total

class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path)
        qs   = parse_qs(path.query)

        if path.path == "/":
            self.send_html(DASHBOARD_HTML)
        elif path.path == "/api/start":
            self.send_json(start_crawler())
        elif path.path == "/api/stop":
            self.send_json(stop_crawler())
        elif path.path == "/api/status":
            count = 0
            if RESULTS_FILE.exists():
                with open(RESULTS_FILE) as f:
                    count = sum(1 for l in f if l.strip())
            self.send_json({"status": crawler_status(), "total": count})
        elif path.path == "/api/results":
            since = int(qs.get("since", ["0"])[0])
            entries, total_lines = load_results(since)
            self.send_json({"entries": entries, "total_lines": total_lines})
        else:
            self.send_response(404)
            self.end_headers()


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Onion Crawler</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');
:root {
  --bg:#080b0f; --surface:#0d1117; --border:#1c2333;
  --accent:#00ff9d; --accent2:#00c8ff; --danger:#ff4d6d;
  --warn:#ffaa00; --text:#b8ccd8; --dim:#3a5060;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Exo 2',sans-serif;font-weight:300;min-height:100vh;}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.06) 2px,rgba(0,0,0,0.06) 4px);pointer-events:none;z-index:9999;}

header{display:flex;align-items:center;gap:20px;padding:18px 32px;border-bottom:1px solid var(--border);background:linear-gradient(90deg,rgba(0,255,157,0.05),transparent);}
.logo{font-family:'Share Tech Mono',monospace;font-size:1.3rem;color:var(--accent);letter-spacing:.15em;text-shadow:0 0 18px rgba(0,255,157,.35);}
.logo span{color:var(--dim);}
.hstats{display:flex;gap:28px;margin-left:auto;}
.hstat{text-align:right;}
.hstat-val{font-family:'Share Tech Mono',monospace;font-size:1.3rem;color:var(--accent2);}
.hstat-lbl{font-size:.65rem;color:var(--dim);text-transform:uppercase;letter-spacing:.1em;}

.statusbar{display:flex;align-items:center;gap:12px;padding:10px 32px;border-bottom:1px solid var(--border);background:rgba(0,0,0,.2);font-family:'Share Tech Mono',monospace;font-size:.75rem;flex-wrap:wrap;}
.dot{width:8px;height:8px;border-radius:50%;background:var(--dim);flex-shrink:0;}
.dot.running{background:var(--accent);box-shadow:0 0 8px var(--accent);animation:pulse 1.2s infinite;}
.dot.finished{background:var(--accent2);}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.btn{background:transparent;border:1px solid var(--border);color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:.75rem;padding:6px 18px;cursor:pointer;letter-spacing:.05em;transition:all .15s;}
.btn:hover{border-color:var(--accent);color:var(--accent);}
.btn.danger:hover{border-color:var(--danger);color:var(--danger);}
.btn.primary{border-color:var(--accent);color:var(--accent);}
.new-badge{background:var(--accent);color:#000;font-size:.65rem;padding:2px 8px;font-weight:700;letter-spacing:.05em;animation:pop .25s ease;}
@keyframes pop{from{opacity:0;transform:scale(.7)}to{opacity:1;transform:scale(1)}}

.layout{display:grid;grid-template-columns:230px 1fr;height:calc(100vh - 100px);}

.sidebar{border-right:1px solid var(--border);overflow-y:auto;display:flex;flex-direction:column;}
.sidebar-title{font-size:.62rem;color:var(--dim);letter-spacing:.12em;text-transform:uppercase;padding:12px 16px 8px;flex-shrink:0;}
.cat-item{display:flex;align-items:center;gap:8px;padding:8px 16px;cursor:pointer;transition:background .12s;border-left:2px solid transparent;flex-shrink:0;}
.cat-item:hover{background:rgba(0,255,157,.04);}
.cat-item.active{border-left-color:var(--accent);background:rgba(0,255,157,.06);}
.cat-icon{font-size:.95rem;width:20px;text-align:center;}
.cat-name{font-size:.75rem;flex:1;color:var(--text);}
.cat-count{font-family:'Share Tech Mono',monospace;font-size:.7rem;color:var(--accent2);}
.cat-item.active .cat-name{color:var(--accent);}

.main{display:flex;flex-direction:column;overflow:hidden;min-width:0;}

.toolbar{display:flex;gap:10px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--border);flex-shrink:0;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;max-width:420px;}
.search-wrap input{width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:'Share Tech Mono',monospace;font-size:.8rem;padding:8px 12px 8px 34px;outline:none;transition:border-color .2s;}
.search-wrap input:focus{border-color:var(--accent);box-shadow:0 0 10px rgba(0,255,157,.08);}
.search-wrap::before{content:'⌕';position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--dim);pointer-events:none;font-size:1rem;}
.live-indicator{font-size:.65rem;color:var(--accent);font-family:'Share Tech Mono',monospace;animation:pulse 1.5s infinite;}
.filter-select{background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:'Share Tech Mono',monospace;font-size:.72rem;padding:7px 10px;outline:none;cursor:pointer;}
.shown-count{font-family:'Share Tech Mono',monospace;font-size:.7rem;color:var(--dim);margin-left:auto;white-space:nowrap;}
.shown-count span{color:var(--accent);}

.table-wrap{flex:1;overflow-y:auto;min-height:0;}
table{width:100%;border-collapse:collapse;font-size:.78rem;}
th{text-align:left;padding:8px 14px;font-family:'Share Tech Mono',monospace;font-size:.62rem;color:var(--dim);text-transform:uppercase;letter-spacing:.1em;border-bottom:1px solid var(--border);background:rgba(0,0,0,.3);position:sticky;top:0;z-index:10;}
td{padding:8px 14px;border-bottom:1px solid rgba(28,35,51,.6);vertical-align:top;line-height:1.5;}
tr:hover td{background:rgba(0,255,157,.025);}
tr.new-row td{animation:highlight 1.2s ease-out;}
@keyframes highlight{from{background:rgba(0,255,157,.15)}to{background:transparent}}
.td-url{font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--accent2);word-break:break-all;max-width:220px;}
.td-url a{color:inherit;text-decoration:none;}
.td-url a:hover{color:var(--accent);text-decoration:underline;}
.td-title{max-width:180px;color:var(--text);}
.td-cat{font-size:.65rem;color:var(--dim);white-space:nowrap;}
.td-preview{color:var(--dim);font-size:.7rem;max-width:300px;}
.s200{color:var(--accent);font-family:'Share Tech Mono',monospace;font-size:.68rem;}
.serr{color:var(--danger);font-family:'Share Tech Mono',monospace;font-size:.68rem;}

.pagination{display:flex;align-items:center;justify-content:center;gap:5px;padding:10px;border-top:1px solid var(--border);flex-shrink:0;}
.pg-btn{background:transparent;border:1px solid var(--border);color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:.68rem;padding:4px 10px;cursor:pointer;transition:all .12s;}
.pg-btn:hover{border-color:var(--accent);color:var(--accent);}
.pg-btn.active{border-color:var(--accent);color:var(--accent);background:rgba(0,255,157,.07);}
.pg-btn:disabled{opacity:.3;cursor:default;}
.pg-info{font-family:'Share Tech Mono',monospace;font-size:.68rem;color:var(--dim);}

.log-panel{height:110px;overflow-y:auto;background:rgba(0,0,0,.35);padding:6px 20px;font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--dim);flex-shrink:0;border-top:1px solid var(--border);}
.log-line{padding:1px 0;}
.log-line.found{color:var(--accent);}
.log-line.block{color:var(--danger);}
.log-line.info{color:var(--accent2);}

.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:12px;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:.82rem;}
.empty-icon{font-size:2.5rem;opacity:.3;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.cursor{animation:blink 1s infinite;color:var(--accent);}
</style>
</head>
<body>
<header>
  <div class="logo">ONION<span>/</span>CRAWLER <span class="cursor">█</span></div>
  <div class="hstats">
    <div class="hstat"><div class="hstat-val" id="hTotal">0</div><div class="hstat-lbl">sites found</div></div>
    <div class="hstat"><div class="hstat-val" id="hCats">0</div><div class="hstat-lbl">categories</div></div>
  </div>
</header>

<div class="statusbar">
  <div class="dot idle" id="dot"></div>
  <span id="statusText">Idle</span>
  <span id="newBadge"></span>
  <div style="margin-left:auto;display:flex;gap:8px;">
    <button class="btn primary" id="btnStart" onclick="startCrawl()">▶ Start Crawl</button>
    <button class="btn danger"  id="btnStop"  onclick="stopCrawl()" disabled>■ Stop</button>
  </div>
</div>

<div class="layout">
  <div class="sidebar">
    <div class="sidebar-title">Categories</div>
    <div id="catList"></div>
  </div>

  <div class="main">
    <div class="toolbar">
      <div class="search-wrap">
        <input type="text" id="searchInput" placeholder="search titles, urls, previews…" oninput="onSearch()">
      </div>
      <span class="live-indicator" id="liveInd" style="display:none">● LIVE</span>
      <select class="filter-select" id="sortSelect" onchange="onSearch()">
        <option value="newest">Newest first</option>
        <option value="oldest">Oldest first</option>
        <option value="alpha">A → Z</option>
      </select>
      <div class="shown-count">showing <span id="shownCount">0</span> / <span id="totalCount">0</span></div>
    </div>

    <div class="table-wrap" id="tableWrap">
      <div class="empty"><div class="empty-icon">🧅</div>Press "Start Crawl" to begin</div>
    </div>
    <div id="paginationEl"></div>
    <div class="log-panel" id="logPanel"></div>
  </div>
</div>

<script>
const PAGE_SIZE  = 50;
let allSites     = [];       // all unique sites received
let seenURLs     = new Set(); // client-side dedup
let filteredSites= [];
let activeCat    = null;
let currentPage  = 1;
let totalLines   = 0;
let pollTimer    = null;
let newSinceView = 0;
let lastNewRows  = [];

const ICONS = {
  "Search Engines & Indexes":"🔍","Wikis & Directories":"📖",
  "Forums & Communities":"💬","News & Media":"📰","Chat & Messaging":"💭",
  "Email & Communication":"✉️","Blogs & Personal Sites":"✍️",
  "Markets & Commerce":"🛒","Technology & Security":"⚙️",
  "Privacy & Anonymity":"🔒","Libraries & Archives":"📚",
  "Leak & Whistleblower":"📡","Finance & Crypto":"₿",
  "Hosting & Services":"🖥️","Uncategorized":"❓"
};

// ── API ────────────────────────────────────────────────────────────────────────
async function startCrawl() {
  const res = await fetch('/api/start').then(r=>r.json());
  if (res.status === 'already_running') { addLog('Already running.','info'); return; }
  document.getElementById('btnStart').disabled = true;
  document.getElementById('btnStop').disabled  = false;
  document.getElementById('liveInd').style.display = '';
  addLog('Crawl started — searching multiple sources…','found');
  startPolling();
}

async function stopCrawl() {
  await fetch('/api/stop');
  document.getElementById('btnStart').disabled = false;
  document.getElementById('btnStop').disabled  = true;
  document.getElementById('liveInd').style.display = 'none';
  addLog('Crawl stopped.','block');
}

// ── Poll every 2s ──────────────────────────────────────────────────────────────
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(poll, 2000);
  poll();
}

async function poll() {
  const st = await fetch('/api/status').then(r=>r.json()).catch(()=>null);
  if (!st) return;
  updateDot(st.status);

  const res = await fetch(`/api/results?since=${totalLines}`).then(r=>r.json()).catch(()=>null);
  if (!res) return;

  // Client-side dedup: only add URLs we haven't seen yet
  const fresh = res.entries.filter(e => {
    if (!e.url || seenURLs.has(e.url)) return false;
    seenURLs.add(e.url);
    return true;
  });

  if (fresh.length > 0) {
    newSinceView += fresh.length;
    lastNewRows   = fresh;
    allSites      = allSites.concat(fresh);
    totalLines    = res.total_lines;
    buildCatList();
    applyFilters(true);
    updateHeader();
    addLog(`+${fresh.length} new sites found (total: ${allSites.length.toLocaleString()})`, 'found');
  } else {
    totalLines = res.total_lines;
  }

  if (st.status === 'finished' || st.status === 'idle') {
    clearInterval(pollTimer);
    document.getElementById('btnStart').disabled = false;
    document.getElementById('btnStop').disabled  = true;
    document.getElementById('liveInd').style.display = 'none';
    if (st.status === 'finished') addLog('Crawl complete.','info');
  }
}

// ── UI ─────────────────────────────────────────────────────────────────────────
function updateDot(state) {
  const dot  = document.getElementById('dot');
  const text = document.getElementById('statusText');
  dot.className = 'dot ' + state;
  text.textContent = state==='running' ? 'Crawling…' : state==='finished' ? 'Finished' : 'Idle';
}

function updateHeader() {
  document.getElementById('hTotal').textContent = allSites.length.toLocaleString();
  document.getElementById('hCats').textContent  = new Set(allSites.map(s=>s.category)).size;
  const badge = document.getElementById('newBadge');
  badge.innerHTML = newSinceView > 0
    ? `<span class="new-badge">+${newSinceView} new</span>` : '';
}

function buildCatList() {
  const counts = {};
  for (const s of allSites) counts[s.category] = (counts[s.category]||0)+1;
  const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  const el = document.getElementById('catList');
  el.innerHTML = '';

  const all = document.createElement('div');
  all.className = 'cat-item'+(activeCat===null?' active':'');
  all.innerHTML = `<span class="cat-icon">🌐</span><span class="cat-name">All Sites</span><span class="cat-count">${allSites.length.toLocaleString()}</span>`;
  all.onclick = () => { activeCat=null; currentPage=1; newSinceView=0; updateHeader(); applyFilters(); buildCatList(); };
  el.appendChild(all);

  for (const [cat, count] of sorted) {
    const div = document.createElement('div');
    div.className = 'cat-item'+(activeCat===cat?' active':'');
    div.innerHTML = `<span class="cat-icon">${ICONS[cat]||'🌐'}</span><span class="cat-name">${cat}</span><span class="cat-count">${count.toLocaleString()}</span>`;
    div.onclick = () => { activeCat=cat; currentPage=1; newSinceView=0; updateHeader(); applyFilters(); buildCatList(); };
    el.appendChild(div);
  }
}

// ── Search (works live during crawl) ──────────────────────────────────────────
function onSearch() { currentPage=1; applyFilters(); }

function applyFilters(keepPage=false) {
  if (!keepPage) currentPage=1;
  const q    = document.getElementById('searchInput').value.toLowerCase();
  const sort = document.getElementById('sortSelect').value;

  // When search box has text, search ALL categories.
  // Category sidebar only filters when search is empty.
  let pool = (q || !activeCat) ? allSites : allSites.filter(s=>s.category===activeCat);

  if (q) {
    pool = pool.filter(s =>
      (s.title||'').toLowerCase().includes(q) ||
      (s.url||'').toLowerCase().includes(q)   ||
      (s.body_preview||'').toLowerCase().includes(q) ||
      (s.category||'').toLowerCase().includes(q)
    );
  }

  pool = [...pool];
  if (sort==='newest')      pool.sort((a,b)=>(b.timestamp||0)-(a.timestamp||0));
  else if (sort==='oldest') pool.sort((a,b)=>(a.timestamp||0)-(b.timestamp||0));
  else if (sort==='alpha')  pool.sort((a,b)=>(a.title||'').localeCompare(b.title||''));

  filteredSites = pool;
  const catPool = (q || !activeCat) ? allSites : allSites.filter(s=>s.category===activeCat);
  document.getElementById('shownCount').textContent = pool.length.toLocaleString();
  document.getElementById('totalCount').textContent = catPool.length.toLocaleString();
  renderTable();
}

// ── Table ──────────────────────────────────────────────────────────────────────
function renderTable() {
  const wrap = document.getElementById('tableWrap');
  const pgEl = document.getElementById('paginationEl');

  if (!filteredSites.length) {
    wrap.innerHTML = `<div class="empty"><div class="empty-icon">${allSites.length?'🔍':'🧅'}</div>${allSites.length?'No results match your search':'Press "Start Crawl" to begin'}</div>`;
    pgEl.innerHTML='';
    return;
  }

  const start = (currentPage-1)*PAGE_SIZE;
  const page  = filteredSites.slice(start, start+PAGE_SIZE);
  const pages = Math.ceil(filteredSites.length/PAGE_SIZE);
  const newSet= new Set(lastNewRows.map(r=>r.url));

  const rows = page.map(s => {
    const isNew  = newSet.has(s.url);
    const sc     = s.status===200?'s200':'serr';
    const preview= (s.body_preview||'').substring(0,110).replace(/</g,'&lt;');
    const title  = (s.title||'[no title]').replace(/</g,'&lt;');
    const url    = (s.url||'').replace(/</g,'&lt;');
    return `<tr class="${isNew?'new-row':''}">
      <td class="td-url"><a href="${url}" target="_blank">${url}</a></td>
      <td class="td-title">${title}</td>
      <td class="td-cat">${ICONS[s.category]||''} ${s.category||''}</td>
      <td class="${sc}">${s.status}</td>
      <td class="td-preview">${preview}</td>
    </tr>`;
  }).join('');

  wrap.innerHTML = `<table>
    <thead><tr><th>URL</th><th>Title</th><th>Category</th><th>Status</th><th>Preview</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;

  if (pages>1) {
    let btns = `<button class="pg-btn" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>← prev</button>`;
    let s2=Math.max(1,currentPage-3), e2=Math.min(pages,s2+6);
    if(s2>1) btns+=`<button class="pg-btn" onclick="goPage(1)">1</button><span class="pg-info">…</span>`;
    for(let i=s2;i<=e2;i++) btns+=`<button class="pg-btn ${i===currentPage?'active':''}" onclick="goPage(${i})">${i}</button>`;
    if(e2<pages) btns+=`<span class="pg-info">…</span><button class="pg-btn" onclick="goPage(${pages})">${pages}</button>`;
    btns+=`<button class="pg-btn" onclick="goPage(${currentPage+1})" ${currentPage===pages?'disabled':''}>next →</button>`;
    btns+=`<span class="pg-info">page ${currentPage} of ${pages}</span>`;
    pgEl.innerHTML=`<div class="pagination">${btns}</div>`;
  } else {
    pgEl.innerHTML='';
  }
}

function goPage(p) {
  const pages=Math.ceil(filteredSites.length/PAGE_SIZE);
  if(p<1||p>pages) return;
  currentPage=p;
  renderTable();
  document.getElementById('tableWrap').scrollTo({top:0,behavior:'smooth'});
}

function addLog(msg,type='') {
  const el=document.getElementById('logPanel');
  const d=document.createElement('div');
  d.className='log-line '+type;
  d.textContent=`[${new Date().toLocaleTimeString()}] ${msg}`;
  el.appendChild(d);
  el.scrollTop=el.scrollHeight;
  while(el.children.length>200) el.removeChild(el.firstChild);
}

// ── Init — load any existing results on page open ─────────────────────────────
(async function init() {
  const st = await fetch('/api/status').then(r=>r.json()).catch(()=>null);
  if (!st) return;
  updateDot(st.status);

  if (st.total > 0) {
    addLog(`Loading ${st.total.toLocaleString()} existing results…`, 'info');
    const res = await fetch('/api/results?since=0').then(r=>r.json()).catch(()=>null);
    if (res && res.entries.length) {
      for (const e of res.entries) {
        if (e.url && !seenURLs.has(e.url)) {
          seenURLs.add(e.url);
          allSites.push(e);
        }
      }
      totalLines = res.total_lines;
      buildCatList();
      applyFilters();
      updateHeader();
      addLog(`Loaded ${allSites.length.toLocaleString()} sites from previous crawl.`, 'info');
    }
  }

  if (st.status === 'running') {
    document.getElementById('btnStart').disabled = true;
    document.getElementById('btnStop').disabled  = false;
    document.getElementById('liveInd').style.display = '';
    addLog('Crawl already in progress — reconnecting…','found');
    startPolling();
  }
})();
</script>
</body>
</html>"""

if __name__ == "__main__":
    print(f"\n  Onion Crawler UI")
    print(f"  ─────────────────────────────")
    print(f"  Open your browser:")
    print(f"  http://localhost:{PORT}")
    print(f"\n  Ctrl+C to shut down.\n")
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")
            stop_crawler()
