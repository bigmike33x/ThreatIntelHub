"""
TorProxyMiddleware
──────────────────
Routes all Scrapy requests through the local Tor SOCKS5 proxy.

Prerequisites
─────────────
  pip install scrapy requests[socks] PySocks

Tor must be running before you start the crawl:
  - Tor Browser (Windows):       keep it open, uses port 9150
  - Tor Expert Bundle (Windows): run tor.exe, uses port 9050
"""

import logging
from scrapy import signals
from scrapy.http import HtmlResponse
import requests

logger = logging.getLogger(__name__)

TOR_PROXY = "socks5h://127.0.0.1:9150"   # 9150 for Tor Browser, 9050 for Expert Bundle


class TorProxyMiddleware:
    """Replace Scrapy's default downloader with a requests session via Tor."""

    def __init__(self, crawler):
        self.crawler = crawler

    @classmethod
    def from_crawler(cls, crawler):
        mw = cls(crawler)
        crawler.signals.connect(mw.spider_opened, signal=signals.spider_opened)
        return mw

    def spider_opened(self, spider):
        logger.info("TorProxyMiddleware active — routing via %s", TOR_PROXY)

    # ------------------------------------------------------------------

    def process_request(self, request):
        proxies = {"http": TOR_PROXY, "https": TOR_PROXY}

        # Scrapy headers are {bytes: [bytes]} — requests needs {str: str}
        clean_headers = {
            k.decode(): v[0].decode()
            for k, v in request.headers.items()
            if v
        }

        # Remove Accept-Encoding so requests returns a plain uncompressed body.
        # Without this, requests decompresses gzip internally but still sends
        # back Content-Encoding: gzip, causing Scrapy to try (and fail) to
        # decompress the already-decoded body a second time.
        clean_headers.pop("Accept-Encoding", None)

        try:
            resp = requests.get(
                request.url,
                proxies=proxies,
                timeout=self.crawler.settings.getint("DOWNLOAD_TIMEOUT", 60),
                headers=clean_headers,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.warning("Tor request failed for %s: %s", request.url, exc)
            raise

        # Strip Content-Encoding from the response so Scrapy's compression
        # middleware doesn't attempt a second decompression pass.
        headers = dict(resp.headers)
        headers.pop("Content-Encoding", None)
        headers.pop("content-encoding", None)

        return HtmlResponse(
            url=resp.url,
            status=resp.status_code,
            headers=headers,
            body=resp.content,
            encoding="utf-8",
            request=request,
        )