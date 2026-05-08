import scrapy
import re
import json
import time
from urllib.parse import urlparse, quote_plus
from darkweb_crawler.items import OnionPageItem
from pathlib import Path

ONION_RE = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)

BLOCKED_KEYWORDS = [
    "porn", "xxx", "sex", "nude", "naked", "escort", "adult", "erotic",
    "fetish", "cam girl", "onlyfans", "nsfw", "18+", "hentai",
    "lewd", "explicit", "lingerie", "stripclub", "prostitut",
]

AHMIA_TERMS = [
    "forum", "wiki", "news", "blog", "chat", "library", "directory",
    "services", "community", "search", "privacy", "security", "crypto",
    "whistleblower", "leak", "journalism", "technology", "archive",
    "pgp", "encryption", "tails", "whonix", "anonymous", "hosting",
]

DARKSEARCH_TERMS = [
    "forum", "wiki", "news", "security", "privacy", "crypto",
    "library", "chat", "directory", "technology",
]


def is_blocked(text):
    lower = text.lower()
    return any(kw in lower for kw in BLOCKED_KEYWORDS)


def load_existing_urls():
    """Load already-crawled URLs from results.jsonl to avoid duplicates."""
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
        # Pre-load already seen hosts from existing results — prevents duplicates
        self.visited_hosts = load_existing_urls()
        self.logger.info(f"[DEDUP] Loaded {len(self.visited_hosts)} existing hosts — these will be skipped")

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
        # APPEND not overwrite — so old results are kept
        "FEEDS": {
            "results.jsonl": {"format": "jsonlines", "overwrite": False}
        },
        "LOG_LEVEL": "INFO",
    }

    def start_requests(self):
        yield scrapy.Request("https://ahmia.fi/onions/", callback=self.parse_index, errback=self.handle_error)
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
            data = json.loads(response.text)
            results = data.get("data", [])
            for r in results:
                link = r.get("link", "")
                host = urlparse(link).hostname or ""
                if host.endswith(".onion"):
                    yield from self._queue_host(host.lower())
        except Exception as e:
            self.logger.warning(f"DarkSearch parse error: {e}")

    def parse_onion(self, response):
        title   = response.css("title::text").get(default="").strip()
        preview = " ".join(
            t.strip() for t in response.css("body *::text").getall() if t.strip()
        )[:500]

        if response.status != 200:
            return
        if len(preview.strip()) < 20:
            return
        if is_blocked(title) or is_blocked(preview):
            self.logger.info(f"[BLOCKED] {response.url}")
            return

        item = OnionPageItem()
        item["url"]          = response.url
        item["title"]        = title or "[no title]"
        item["status"]       = response.status
        item["body_preview"] = preview[:300]
        item["timestamp"]    = int(time.time())
        yield item

        current_host = urlparse(response.url).hostname or ""
        for href in response.css("a::attr(href)").getall():
            absolute = response.urljoin(href)
            host     = urlparse(absolute).hostname or ""
            if not host.endswith(".onion"):
                continue
            if host == current_host:
                yield scrapy.Request(absolute, callback=self.parse_onion,
                                     errback=self.handle_error,
                                     meta={"handle_httpstatus_all": True})
            elif host not in self.visited_hosts:
                yield from self._queue_host(host)

        for host in ONION_RE.findall(response.text):
            host = host.lower()
            if host not in self.visited_hosts:
                yield from self._queue_host(host)

    def _queue_host(self, host):
        if host in self.visited_hosts:
            return
        self.visited_hosts.add(host)
        self.logger.info(f"[QUEUE] {host}")
        yield scrapy.Request(
            f"http://{host}/",
            callback=self.parse_onion,
            errback=self.handle_error,
            meta={"handle_httpstatus_all": True},
        )

    def handle_error(self, failure):
        self.logger.debug(f"[FAIL] {failure.request.url} — {failure.value}")
