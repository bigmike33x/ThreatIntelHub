import scrapy
import re
import json
import time
from urllib.parse import urlparse, quote_plus
from darkweb_crawler.items import OnionPageItem, LeakItem
from pathlib import Path

ONION_RE = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)

# ── Load CTI seeds from deepdarkCTI data ──────────────────────────────────────
_CTI_FILE = Path(__file__).parent.parent.parent / "cti_seeds.json"
try:
    _CTI = json.loads(_CTI_FILE.read_text())
except Exception:
    _CTI = {}

RANSOMWARE_SEEDS = _CTI.get('ransomware_onions', [])
FORUM_SEEDS      = _CTI.get('forum_onions', [])
SEARCH_SEEDS     = _CTI.get('search_onions', [])

# ── Blocked content ────────────────────────────────────────────────────────────
# ── HARD BLOCKED — CSAM and sexual violence ───────────────────────────────────
# These are checked FIRST before anything else.
# Sites matching any of these are rejected immediately and never saved.
CSAM_KWS = [
    "pthc","ptsc","jailbait","child porn","cp ","lolita","underage sex",
    "child sex","kiddie","preteen","pedo","pedophil","childlove",
    "toddlercon","babyj","hussyfan","r@ygold","ygold","kdv","tochka",
    "rindexx","boy love","girl love","child model","cp link",
    "cute girls underage","cp video","cp image","cp pic",
]
CSAM_TITLE_KWS = [
    "pthc","ptsc","jailbait","cp -","underage","child","kiddie",
    "preteen","lolita","pedo","rindexx","boy love","girl love",
    "cute girls","yvids","zoo sex",
]
RAPE_KWS = [
    "rape video","rape image","rape pic","rape porn","raped bitch",
    "rape kids","rape children","forced sex video","snuff",
]

# Human trafficking and exploitation
TRAFFICKING_KWS = [
    "buy girl","buy boy","buy child","buy baby","buy newborn",
    "sex slave","sex slaves","young wife for sale","human traffic",
    "illegal trade of people","behappy","buy wife","sell girl",
    "sell boy","sell child","slave market","girl for sale",
    "boy for sale","child for sale","baby for sale",
]

ADULT_KWS = [
    "porn","xxx","nude","naked","escort","erotic","fetish","cam girl",
    "onlyfans","nsfw","18+","hentai","lewd","explicit","stripclub","prostitut",
]
NOISE_KWS = [
    "gift card","clone card","cashgod","buy money","bitcoin generator",
    "stolen wallets","escrow marketplace","darkweb shop","bazaar plastic",
    "this site has been seized","seized by","link disabled",
    "ddos protection by","you will be redirected","please wait",
    "buy cocaine","buy heroin","buy meth","buy fentanyl",
]
NOISE_TITLES = [
    "[no title]","403 forbidden","404 not found","404","access denied",
    "index of /","queue","please wait","link disabled","untitled",
    "welcome to nginx","apache2 ubuntu default page","it works!",
    "under construction","coming soon",
]
MIN_PREVIEW = 80

# ── Leak detection ─────────────────────────────────────────────────────────────
EMAIL_RE  = re.compile(r'[\w\.-]+@[\w\.-]+\.\w{2,}')
HASH_RE   = re.compile(r'\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|\$2[aby]\$\d+\$\S+)\b', re.I)
CVE_RE    = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
RECORD_RE = re.compile(r'(\d+[\.,]?\d*)\s*(million|billion|thousand|k|m)\s*(records?|rows?|accounts?|users?|entries)', re.I)
SSN_RE    = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
MAGNET_RE = re.compile(r'magnet:\?xt=urn:', re.I)

LEAK_SIGNALS = [
    'data breach','database leak','credential dump','password dump','combo list',
    'leaked database','breach notification','data dump','db dump','sql dump',
    '0day','zero day','zero-day','remote code execution','rce',
    'proof of concept','poc exploit','vulnerability disclosure',
    'privilege escalation','sql injection','buffer overflow',
    'plaintext passwords','hashed passwords','password hashes',
    'ssn','social security','credit card numbers','pii exposed',
    'million records','million accounts','million users',
    'victim','ransomware attack','data stolen','files encrypted',
]
LEAK_NOISE = [
    'buy this database','purchase access','for sale','buy now',
    'contact us to buy','btc only','monero only','telegram:','wickr:',
    'mega leak','huge dump','fresh fullz','buy fullz','buy dumps',
    'guaranteed','100% working','legit seller','trusted vendor',
]
NEWS_INDICATORS = [
    'breaking news','world news','sports news','business news',
    'subscribe to our newsletter','read more stories','follow us on',
    'share this article','published by','copyright bbc','all rights reserved',
    'terms of use','privacy policy','cookie policy','editorial guidelines',
]

# ── File extensions to flag ────────────────────────────────────────────────────
FLAG_EXTS = {
    '.sql','.gz','.zip','.tar','.7z','.rar',
    '.txt','.csv','.json','.db','.sqlite',
    '.pdf','.docx','.xlsx','.torrent',
}

# ── Search terms ───────────────────────────────────────────────────────────────
AHMIA_TERMS = [
    "forum","wiki","news","blog","chat","library","directory","community",
    "search","privacy","security","crypto","whistleblower","leak",
    "journalism","technology","archive","pgp","encryption","tails",
    "whonix","anonymous","hosting","research","activist",
]
DARKSEARCH_TERMS = [
    "forum","wiki","news","security","privacy","crypto",
    "library","directory","technology","research",
]
LEAK_TERMS = [
    "database leak","data breach","credential dump","0day exploit",
    "zero day","CVE exploit","proof of concept","vulnerability disclosure",
    "ransomware victims","leaked data","ssn leak",
]
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
    ("Ransomware",         ["ransomware","ransom","victim","encrypted files","pay ransom"]),
]


def categorize(title, preview):
    text = f"{title} {preview}".lower()
    for cat, kws in CATEGORY_RULES:
        if any(kw in text for kw in kws): return cat
    return "Uncategorized"


def is_blocked(title, preview):
    text        = f"{title} {preview}".lower()
    title_lower = title.lower().strip()

    # ── HARD BLOCK: CSAM and sexual violence — checked first, no exceptions ──
    if any(kw in text for kw in CSAM_KWS):
        return True, "CSAM"
    if any(kw in title_lower for kw in CSAM_TITLE_KWS):
        return True, "CSAM title"
    if any(kw in text for kw in RAPE_KWS):
        return True, "sexual violence"
    if any(kw in text for kw in TRAFFICKING_KWS):
        return True, "human trafficking"

    if len(preview.strip()) < MIN_PREVIEW:
        return True, "thin content"
    if title_lower in NOISE_TITLES:
        return True, "noise title"
    if any(kw in text for kw in ADULT_KWS):
        return True, "adult content"
    if any(kw in text for kw in NOISE_KWS):
        return True, "noise/scam"
    return False, ""


def analyze_leak(title, full_text):
    text_lower = full_text.lower()
    confidence = 0
    extracted  = {}

    noise_hits = sum(1 for kw in LEAK_NOISE if kw in text_lower)
    if noise_hits >= 2:
        return False, 0, {}

    # News site check
    news_hits = sum(1 for kw in NEWS_INDICATORS if kw in text_lower)
    if news_hits >= 2:
        strong = len(SSN_RE.findall(full_text)) + len(HASH_RE.findall(full_text)) + len(EMAIL_RE.findall(full_text))
        if strong < 5:
            return False, 0, {}

    emails = EMAIL_RE.findall(full_text)
    if len(emails) >= 3:
        confidence += 25
        extracted['sample_emails'] = list(set(emails[:5]))

    hashes = HASH_RE.findall(full_text)
    if len(hashes) >= 3:
        confidence += 20
        extracted['hash_count'] = len(hashes)

    cves = list(set(CVE_RE.findall(full_text)))
    if cves:
        confidence += 30
        extracted['cves'] = cves[:10]

    ssns = SSN_RE.findall(full_text)
    if ssns:
        confidence += 35
        extracted['ssn_count'] = len(ssns)

    records = RECORD_RE.findall(full_text)
    if records:
        confidence += 20
        extracted['record_counts'] = [f"{m[0]} {m[1]} {m[2]}" for m in records[:3]]

    if MAGNET_RE.search(full_text):
        confidence += 20
        extracted['has_magnet'] = True

    signal_hits = [kw for kw in LEAK_SIGNALS if kw in text_lower]
    confidence += min(len(signal_hits) * 5, 25)
    if signal_hits:
        extracted['signals'] = signal_hits[:5]

    breach_ctx = re.findall(
        r'([A-Z][a-zA-Z0-9\s]{2,30})\s*(breach|leak|dump|hacked|compromised|victim|attack)',
        full_text)
    if breach_ctx:
        confidence += 15
        extracted['breach_targets'] = list(set([b[0].strip() for b in breach_ctx[:5]]))

    has_supporting = (len(emails) >= 3 or len(hashes) >= 3 or
                      len(cves) > 0 or len(records) > 0 or
                      MAGNET_RE.search(full_text))

    exploit_types = [e for e in [
        'RCE','SQLi','XSS','LFI','RFI','SSRF','XXE','IDOR',
        'buffer overflow','use after free','heap spray',
    ] if e.lower() in text_lower]
    if exploit_types and has_supporting:
        confidence += 15
        extracted['exploit_types'] = exploit_types[:5]
    elif exploit_types:
        confidence += 3

    if confidence < 40:
        return False, 0, {}
    return True, min(confidence, 100), extracted


def load_existing_hosts():
    """Load only hosts from DB — much faster and uses less RAM than reading jsonl."""
    db_file = Path(__file__).parent.parent.parent / "crawler.db"
    seen = set()
    if db_file.exists():
        try:
            import sqlite3
            con = sqlite3.connect(str(db_file))
            rows = con.execute("SELECT host FROM sites").fetchall()
            con.close()
            seen = {r[0].lower() for r in rows if r[0]}
            return seen
        except: pass
    # Fallback to jsonl if DB doesn't exist yet
    results_file = Path(__file__).parent.parent.parent / "results.jsonl"
    if results_file.exists():
        with open(results_file, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    e = json.loads(line)
                    url = e.get('url','')
                    if url:
                        host = urlparse(url).hostname or ''
                        seen.add(host.lower())
                except: pass
    return seen


class OnionSpider(scrapy.Spider):
    name = "onion_spider"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.visited_hosts = load_existing_hosts()
        self.blocked_count = 0
        self.saved_count   = 0
        self.leak_count    = 0
        self._new_hosts    = set()  # only new hosts this session
        self.logger.info(f"[DEDUP] Skipping {len(self.visited_hosts)} existing hosts")
        self.logger.info(f"[CTI] Loaded {len(RANSOMWARE_SEEDS)} ransomware + {len(FORUM_SEEDS)} forum + {len(SEARCH_SEEDS)} search seeds")

    custom_settings = {
        "DOWNLOADER_MIDDLEWARES": {
            "darkweb_crawler.middlewares.TorProxyMiddleware": 610,
        },
        "ROBOTSTXT_OBEY":              False,
        "DOWNLOAD_TIMEOUT":            20,
        "RETRY_TIMES":                 0,
        "DOWNLOAD_DELAY":              2,
        "RANDOMIZE_DOWNLOAD_DELAY":    True,
        "CONCURRENT_REQUESTS":         4,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
        "DEPTH_LIMIT":                 1,    # depth 1 only — no following links from discovered pages
        "MEMUSAGE_ENABLED":            True,
        "MEMUSAGE_LIMIT_MB":           512,  # hard stop at 512MB — well before OOM
        "MEMUSAGE_WARNING_MB":         384,
        "DEPTH_PRIORITY":              1,
        "REACTOR_THREADPOOL_MAXSIZE":  4,
        "CLOSESPIDER_PAGECOUNT":       2000, # stop after 2000 pages per run — restart fresh
        "SCHEDULER_PRIORITY_QUEUE":    "scrapy.pqueues.DownloaderAwarePriorityQueue",
        "FEEDS": {
            "results.jsonl": {"format":"jsonlines","overwrite":False},
            "leaks.jsonl":   {"format":"jsonlines","overwrite":False},
        },
        "LOG_LEVEL": "INFO",
    }

    def start_requests(self):
        # ── All seeds are .onion only — no clearnet requests ─────────────────
        # Daniel's Onion Link List — large categorized .onion directory
        yield scrapy.Request(
            "http://donionsixbjtiohce24abfgsffo2l4tk26qx464zylumgejukfq2vead.onion/onions.php",
            callback=self.parse_index, errback=self.handle_error)

        # Ahmia .onion mirror
        yield scrapy.Request(
            "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
            callback=self.parse_index, errback=self.handle_error)

        # DarkSearch .onion mirror
        yield scrapy.Request(
            "http://darkschn4iw2hxvpv2vy2uoxwkvs2padb56t3h4wqztre6upoc5qwgid.onion/",
            callback=self.parse_index, errback=self.handle_error)

        # Haystak search engine
        yield scrapy.Request(
            "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/",
            callback=self.parse_index, errback=self.handle_error)

        # Torch search engine
        yield scrapy.Request(
            "http://torchqsxkllrj2eqaitp5xvcgfeg3g5dr3hr2wnuvnj76bbxkxfiwxqd.onion",
            callback=self.parse_index, errback=self.handle_error)

        # Fresh Onions — newly registered .onion sites
        yield scrapy.Request(
            "http://freshonifyfe4rmuh6qwpsexfhdrww7wnt5qmkoertwxmcuvm4woo4ad.onion",
            callback=self.parse_index, errback=self.handle_error)

        # Onion Land search
        yield scrapy.Request(
            "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion",
            callback=self.parse_index, errback=self.handle_error)

        # ── CTI: Ransomware gang sites ────────────────────────────────────────
        self.logger.info(f"[CTI] Queuing {len(RANSOMWARE_SEEDS)} ransomware seeds")
        for url in RANSOMWARE_SEEDS:
            yield from self._queue_url(url, priority='ransomware')

        # ── CTI: Forums ───────────────────────────────────────────────────────
        self.logger.info(f"[CTI] Queuing {len(FORUM_SEEDS)} forum seeds")
        for url in FORUM_SEEDS:
            yield from self._queue_url(url, priority='forum')

        # ── CTI: Search engines ───────────────────────────────────────────────
        self.logger.info(f"[CTI] Queuing {len(SEARCH_SEEDS)} search engine seeds")
        for url in SEARCH_SEEDS:
            yield from self._queue_url(url, priority='search')

    def parse_index(self, response):
        found = set(h.lower() for h in ONION_RE.findall(response.text))
        self.logger.info(f"[SEED] {len(found)} onions in {response.url}")
        for host in found:
            yield from self._queue_host(host)

    def parse_darksearch(self, response):
        # Kept for compatibility but no longer called from clearnet
        try:
            data = json.loads(response.text)
            for r in (data.get("data") or []):
                link = r.get("link","")
                host = urlparse(link).hostname or ""
                if host.endswith(".onion"):
                    yield from self._queue_host(host.lower())
        except Exception as e:
            self.logger.warning(f"DarkSearch parse error: {e}")

    def parse_onion(self, response):
        if response.status != 200:
            return

        title     = response.css("title::text").get(default="").strip()
        # Only extract what we need — don't hold full page in memory
        texts     = response.css("body *::text").getall()
        full_text = " ".join(t.strip() for t in texts if t.strip())[:2000]
        preview   = full_text[:300]
        del texts  # free immediately

        blocked, reason = is_blocked(title, full_text[:500])
        if blocked:
            self.blocked_count += 1
            self.logger.debug(f"[SKIP] {reason} — {response.url}")
            yield from self._follow_links(response)
            return

        # Detect file links — cap hrefs to limit memory from large link lists
        all_hrefs = response.css("a::attr(href)").getall()[:30]
        file_links = []
        for href in all_hrefs:
            abs_url = response.urljoin(href)
            path    = urlparse(abs_url).path.lower()
            ext     = next((e for e in FLAG_EXTS if path.endswith(e)), None)
            if ext:
                file_links.append([abs_url, ext])

        # Leak detection
        is_leak, confidence, extracted = analyze_leak(title, full_text)
        if is_leak:
            leak = LeakItem()
            leak["url"]            = response.url
            leak["title"]          = title or "[no title]"
            leak["status"]         = response.status
            leak["confidence"]     = confidence
            leak["full_text"]      = full_text[:2000]
            leak["extracted"]      = json.dumps(extracted)
            leak["cves"]           = json.dumps(extracted.get("cves",[]))
            leak["breach_targets"] = json.dumps(extracted.get("breach_targets",[]))
            leak["record_counts"]  = json.dumps(extracted.get("record_counts",[]))
            leak["exploit_types"]  = json.dumps(extracted.get("exploit_types",[]))
            leak["has_emails"]     = 1 if extracted.get("sample_emails") else 0
            leak["has_hashes"]     = 1 if extracted.get("hash_count") else 0
            leak["has_ssn"]        = 1 if extracted.get("ssn_count") else 0
            leak["has_magnet"]     = 1 if extracted.get("has_magnet") else 0
            leak["timestamp"]      = int(time.time())
            self.leak_count += 1
            self.logger.info(f"[LEAK #{self.leak_count}] conf={confidence}% — {title[:50]}")
            yield leak

        item = OnionPageItem()
        item["url"]          = response.url
        item["title"]        = title or "[no title]"
        item["status"]       = response.status
        item["body_preview"] = preview
        item["file_links"]   = json.dumps(file_links)
        item["timestamp"]    = int(time.time())
        self.saved_count += 1
        if self.saved_count % 10 == 0:
            self.logger.info(f"[PROGRESS] saved={self.saved_count} blocked={self.blocked_count} leaks={self.leak_count} queued={len(self.visited_hosts)}")
        self.logger.info(f"[SAVED #{self.saved_count}] {title[:50]} — {response.url}")
        yield item

        yield from self._follow_links(response)

    def _follow_links(self, response):
        # Hard caps to prevent frontier queue memory explosion
        MAX_LINKS_PER_PAGE   = 5   # max same-host page links to follow
        MAX_HOSTS_PER_PAGE   = 5   # max new external hosts to discover per page
        MAX_TEXT_SCAN_CHARS  = 5000  # only scan first 5k chars of text for onions

        current_host = urlparse(response.url).hostname or ""
        seen_page    = set()
        same_host    = 0
        new_hosts    = 0

        for href in response.css("a::attr(href)").getall():
            if same_host >= MAX_LINKS_PER_PAGE and new_hosts >= MAX_HOSTS_PER_PAGE:
                break
            absolute = response.urljoin(href)
            host     = urlparse(absolute).hostname or ""
            if not host.endswith(".onion"): continue
            if host == current_host:
                if same_host < MAX_LINKS_PER_PAGE and absolute not in seen_page:
                    seen_page.add(absolute)
                    same_host += 1
                    yield scrapy.Request(absolute, callback=self.parse_onion,
                                         errback=self.handle_error,
                                         meta={"handle_httpstatus_all": True})
            elif new_hosts < MAX_HOSTS_PER_PAGE and host not in self.visited_hosts:
                new_hosts += 1
                yield from self._queue_host(host)

        # Scan page text for .onion addresses — capped
        for host in ONION_RE.findall(response.text[:MAX_TEXT_SCAN_CHARS]):
            if new_hosts >= MAX_HOSTS_PER_PAGE: break
            host = host.lower()
            if host not in self.visited_hosts:
                new_hosts += 1
                yield from self._queue_host(host)

        # Free memory
        del seen_page

    def _queue_url(self, url, priority='normal'):
        host = urlparse(url).hostname or ""
        if not host: return
        if host in self.visited_hosts or host in self._new_hosts: return
        self._new_hosts.add(host)
        self.logger.info(f"[QUEUE:{priority}] {host}")
        yield scrapy.Request(url, callback=self.parse_onion,
                             errback=self.handle_error,
                             meta={"handle_httpstatus_all": True})

    def _queue_host(self, host):
        # Cap new hosts per session to prevent unbounded frontier growth
        if len(self._new_hosts) >= 5000:
            return
        if host in self.visited_hosts or host in self._new_hosts: return
        self._new_hosts.add(host)
        self.logger.info(f"[QUEUE] {host}")
        yield scrapy.Request(f"http://{host}/", callback=self.parse_onion,
                             errback=self.handle_error,
                             meta={"handle_httpstatus_all": True})

    def handle_error(self, failure):
        self.logger.info(f"[FAIL] {failure.request.url} — {repr(failure.value)[:80]}")