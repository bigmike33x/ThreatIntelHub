BOT_NAME = "darkweb_crawler"

SPIDER_MODULES = ["darkweb_crawler.spiders"]
NEWSPIDER_MODULE = "darkweb_crawler.spiders"

# Respect robots.txt where present
ROBOTSTXT_OBEY = False  # robots.txt fetches fail through Tor proxy

# Default request headers
DEFAULT_REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en",
    "User-Agent": "Mozilla/5.0 (compatible; research-bot/1.0)",
}

# Dedup filter — don't revisit the same URL
DUPEFILTER_CLASS = "scrapy.dupefilters.RFPDupeFilter"

# Depth limit — adjust as needed (None = unlimited)
DEPTH_LIMIT = 3