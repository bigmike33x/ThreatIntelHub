"""
TorProxyMiddleware
──────────────────
Routes ALL requests through Tor SOCKS5 proxy.
Only .onion addresses are crawled — no clearnet.

Tor must be running on port 9050 (Raspberry Pi / Linux service).
"""

import logging
import socket
import socks
from scrapy import signals
from scrapy.http import HtmlResponse

logger  = logging.getLogger(__name__)
TOR_HOST = "127.0.0.1"
TOR_PORT = 9050


class TorProxyMiddleware:

    def __init__(self, crawler):
        self.crawler = crawler

    @classmethod
    def from_crawler(cls, crawler):
        mw = cls(crawler)
        crawler.signals.connect(mw.spider_opened, signal=signals.spider_opened)
        return mw

    def spider_opened(self, spider):
        logger.info("TorProxyMiddleware — all traffic via socks5h://%s:%d",
                    TOR_HOST, TOR_PORT)

    def process_request(self, request):
        timeout = self.crawler.settings.getint("DOWNLOAD_TIMEOUT", 20)
        url     = request.url

        # Safety check — should only ever receive .onion URLs now
        if '.onion' not in url:
            logger.warning("Non-onion URL blocked: %s", url)
            raise Exception(f"Non-onion URL not allowed: {url}")

        from urllib.parse import urlparse
        parsed = urlparse(url)
        host   = parsed.hostname
        port   = parsed.port or 80
        path   = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, TOR_HOST, TOR_PORT, rdns=True)
        s.settimeout(timeout)

        try:
            s.connect((host, port))

            req_bytes = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Accept: text/html,*/*\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode('utf-8')
            s.sendall(req_bytes)

            # Read response with size cap to prevent memory exhaustion
            MAX_RESPONSE = 2 * 1024 * 1024  # 2MB max per page
            chunks = []
            total  = 0
            while total < MAX_RESPONSE:
                try:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                except socket.timeout:
                    break

            raw = b''.join(chunks)
            chunks = []  # free immediately
            del chunks

            if not raw:
                raise Exception("Empty response")

            # Split headers and body
            sep     = b'\r\n\r\n'
            sep_idx = raw.find(sep)
            if sep_idx == -1:
                sep     = b'\n\n'
                sep_idx = raw.find(sep)

            if sep_idx == -1:
                body         = raw
                header_bytes = b''
            else:
                header_bytes = raw[:sep_idx]
                body         = raw[sep_idx + len(sep):]

            # Parse status line
            status = 200
            lines  = header_bytes.decode('utf-8', errors='replace').splitlines()
            if lines:
                parts = lines[0].split(' ', 2)
                if len(parts) >= 2:
                    try:
                        status = int(parts[1])
                    except ValueError:
                        pass

            # Parse response headers
            resp_headers = {}
            for line in lines[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    resp_headers[k.strip()] = v.strip()

            # Strip encoding so Scrapy doesn't double-decompress
            resp_headers.pop('Content-Encoding', None)
            resp_headers.pop('content-encoding', None)

            return HtmlResponse(
                url=url, status=status,
                headers=resp_headers, body=body,
                encoding='utf-8', request=request,
            )

        except Exception as exc:
            logger.debug("Tor request failed %s: %s", url, exc)
            raise
        finally:
            try:
                s.close()
            except Exception:
                pass
