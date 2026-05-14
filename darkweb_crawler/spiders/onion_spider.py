import scrapy
import re
import json
import time
from urllib.parse import urlparse, quote_plus
from darkweb_crawler.items import OnionPageItem
from pathlib import Path

ONION_RE = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)

# ── Blocked content — never saved ─────────────────────────────────────────────
# Adult content
ADULT_KWS = [
    "porn", "xxx", "sex", "nude", "naked", "escort", "adult", "erotic",
    "fetish", "cam girl", "onlyfans", "nsfw", "18+", "hentai",
    "lewd", "explicit", "lingerie", "stripclub", "prostitut",
]

# Noise/scam/junk sites — from analysis of real crawl data
NOISE_KWS = [
    # Scam shops & markets
    "gift card", "clone card", "cashgod", "buy money securely",
    "bitcoin generator", "bitcoin exploit", "generate bitcoins",
    "stolen cryptocurrency", "stolen wallets", "buy cheap",
    "escrow marketplace", "multisig escrow",
    # Cloned/spam sites
    "bazaar plastic", "giftcardxpress", "z33-apple",
    # Dead/useless pages
    "this site has been seized", "seized by", "operation alice",
    "link disabled", "ddos protection by", "you will be redirected shortly",
    "please wait", "waiting time:",
    # Generic junk titles
    "403 forbidden", "404 not found", "access denied",
    # Carding / fraud
    "cvv", "fullz", "dumps", "carding", "hacked accounts",
    "buy accounts", "cheap accounts",
    # Fake tools
    "whatsapp hack", "facebook hack", "instagram hack",
    "phone hack", "email hack", "spy on",
    # Drug markets (specific spam patterns)
    "buy cocaine", "buy heroin", "buy meth", "buy fentanyl",
    "order drugs", "drug market",
]

# Titles that are pure noise regardless of body
NOISE_TITLES = [
    "[no title]", "403 forbidden", "404 not found", "404",
    "access denied", "index of /", "queue", "please wait",
    "link disabled", "error", "untitled", "untitled document",
    "welcome to nginx", "apache2 ubuntu default page",
    "it works!", "under construction", "coming soon",
]

# Minimum content length — skip thin/empty pages
MIN_PREVIEW_LEN = 80

AHMIA_TERMS = [
    "forum", "wiki", "news", "blog", "chat", "library", "directory",
    "services", "community", "search", "privacy", "security", "crypto",
    "whistleblower", "leak", "journalism", "technology", "archive",
    "pgp", "encryption", "tails", "whonix", "anonymous", "hosting",
    "research", "documentation", "open source", "activist", "human rights",
]

DARKSEARCH_TERMS = [
    "forum", "wiki", "news", "security", "privacy", "crypto",
    "library", "chat", "directory", "technology", "research",
]


def is_blocked(title, preview):
    """Return (blocked, reason) — True if site should be skipped."""
    text  = f"{title} {preview}".lower()
    title_lower = title.lower().strip()

    # Skip dead/empty pages
    if len(preview.strip()) < MIN_PREVIEW_LEN:
        return True, "thin content"

    # Skip noise titles exactly
    if title_lower in NOISE_TITLES:
        return True, f"noise title: {title_lower}"

    # Skip adult content
    if any(kw in text for kw in ADULT_KWS):
        return True, "adult content"

    # Skip noise/scam content
    if any(kw in text for kw in NOISE_KWS):
        return True, f"noise/scam content"

    return False, ""


def load_existing_hosts():
    """Load already-crawled hosts from results.jsonl to skip on restart."""
    results_file = Path(__file__).parent.parent.parent / "results.jsonl"
    seen = set()
    if results_file.exists():
        with open(results_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    url = entry.get("url", "")
                    if url:
                        host = urlparse(url).hostname or ""
                        seen.add(host.lower())
                except:
                    pass
    return seen


class OnionSpider(scrapy.Spider):
    name = "onion_spider"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.visited_hosts = load_existing_hosts()
        self.blocked_count = 0
        self.saved_count   = 0
        self.logger.info(f"[DEDUP] Skipping {len(self.visited_hosts)} already-crawled hosts")

    custom_settings = {
        "DOWNLOADER_MIDDLEWARES": {
            "darkweb_crawler.middlewares.TorProxyMiddleware": 610,
        },
        "ROBOTSTXT_OBEY": False,
        "DOWNLOAD_TIMEOUT": 45,
        "RETRY_TIMES": 1,
        "DOWNLOAD_DELAY": 1.5,
        "RANDOMIZE_DOWNLOAD_DELAY": True,
        "CONCURRENT_REQUESTS": 6,
        "DEPTH_LIMIT": 3,
        "FEEDS": {
            "results.jsonl": {"format": "jsonlines", "overwrite": False}
        },
        "LOG_LEVEL": "INFO",
    }

    def start_requests(self):
        yield scrapy.Request(
            "https://ahmia.fi/onions/",
            callback=self.parse_index,
            errback=self.handle_error
        )
        for term in AHMIA_TERMS:
            url = f"https://ahmia.fi/search/?q={quote_plus(term)}"
            yield scrapy.Request(url, callback=self.parse_index, errback=self.handle_error)
        for term in DARKSEARCH_TERMS:
            for page in range(1, 4):
                url = f"https://darksearch.io/api/search?query={quote_plus(term)}&page={page}"
                yield scrapy.Request(url, callback=self.parse_darksearch, errback=self.handle_error)

    def parse_index(self, response):
        found = set(h.lower() for h in ONION_RE.findall(response.text))
        self.logger.info(f"[SEED] {len(found)} onions in {response.url}")
        for host in found:
            yield from self._queue_host(host)

    def parse_darksearch(self, response):
        try:
            data    = json.loads(response.text)
            results = data.get("data", [])
            for r in results:
                link = r.get("link", "")
                host = urlparse(link).hostname or ""
                if host.endswith(".onion"):
                    yield from self._queue_host(host.lower())
        except Exception as e:
            self.logger.warning(f"DarkSearch parse error: {e}")

    def parse_onion(self, response):
        # Only process successful responses
        if response.status != 200:
            return

        title   = response.css("title::text").get(default="").strip()
        preview = " ".join(
            t.strip() for t in response.css("body *::text").getall() if t.strip()
        )[:500]

        blocked, reason = is_blocked(title, preview)
        if blocked:
            self.blocked_count += 1
            self.logger.debug(f"[SKIP] {reason} — {response.url}")
            # Still follow links from the page even if we don't save it
            # (it might link to useful sites)
            self._follow_links(response)
            return

        # Save the item
        item = OnionPageItem()
        item["url"]          = response.url
        item["title"]        = title or "[no title]"
        item["status"]       = response.status
        item["body_preview"] = preview[:300]
        item["timestamp"]    = int(time.time())
        self.saved_count += 1
        self.logger.info(f"[SAVED #{self.saved_count}] {title[:50]} — {response.url}")
        yield item

        self._follow_links(response)

    def _follow_links(self, response):
        """Follow .onion links found on a page."""
        current_host = urlparse(response.url).hostname or ""

        # Follow href links
        for href in response.css("a::attr(href)").getall():
            absolute = response.urljoin(href)
            host     = urlparse(absolute).hostname or ""
            if not host.endswith(".onion"):
                continue
            if host == current_host:
                # Internal link — follow deeper into same site
                yield scrapy.Request(
                    absolute,
                    callback=self.parse_onion,
                    errback=self.handle_error,
                    meta={"handle_httpstatus_all": True},
                )
            elif host not in self.visited_hosts:
                yield from self._queue_host(host)

        # Scan raw text for .onion addresses not in links
        for host in ONION_RE.findall(response.text):
            host = host.lower()
            if host not in self.visited_hosts:
                yield from self._queue_host(host)

    def _queue_host(self, host):
        if host in self.visited_hosts:
            return
        self.visited_hosts.add(host)
        yield scrapy.Request(
            f"http://{host}/",
            callback=self.parse_onion,
            errback=self.handle_error,
            meta={"handle_httpstatus_all": True},
        )

    def handle_error(self, failure):
        self.logger.debug(f"[FAIL] {failure.request.url} — {failure.value}")
