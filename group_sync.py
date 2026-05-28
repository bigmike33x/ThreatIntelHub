#!/usr/bin/env python3
"""
group_sync.py — RansomLook API sync for Dark Crawler
Polls ransomlook.io every 2-4 hours and stores groups + victim posts locally.

Cron (every 3 hours):
  0 */3 * * * cd ~/dark-crawler && ~/dark-crawler/venv/bin/python group_sync.py >> ~/dark-crawler/group_sync.log 2>&1

Attribution: "Data sourced from ransomlook.io" — CC BY 4.0
"""

import sqlite3
import json
import time
import logging
import sys
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from datetime import datetime

# ── Config ─────────────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).parent
DB_PATH   = BASE_DIR / "crawler.db"
LOG_PATH  = BASE_DIR / "group_sync.log"

API_BASE        = "https://www.ransomlook.io/api"
GROUPS_LIST     = f"{API_BASE}/groups"
POSTS_ENDPOINT  = f"{API_BASE}/posts"   # ?days=N
POSTS_DAYS      = 30                     # fetch last N days of posts per run
REQUEST_TIMEOUT = 30  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [GROUP_SYNC] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)


# ── Database ───────────────────────────────────────────────────────────────────
def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def ensure_tables():
    """Create ransomware group tables if they don't exist yet."""
    con = db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS groups (
            id           INTEGER PRIMARY KEY,
            name         TEXT UNIQUE,
            slug         TEXT UNIQUE,
            status       TEXT DEFAULT 'active',
            description  TEXT,
            added_at     INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS group_urls (
            id          INTEGER PRIMARY KEY,
            group_id    INTEGER REFERENCES groups(id),
            url         TEXT UNIQUE,
            is_primary  INTEGER DEFAULT 0,
            last_seen   INTEGER,
            uptime_pct  REAL DEFAULT 0.0
        );

        CREATE TABLE IF NOT EXISTS group_posts (
            id            INTEGER PRIMARY KEY,
            group_name    TEXT,
            title         TEXT,
            published_at  TEXT,
            discovered_at INTEGER DEFAULT (strftime('%s','now')),
            country       TEXT,
            sector        TEXT,
            description   TEXT,
            source_url    TEXT,
            source        TEXT DEFAULT 'ransomlook'
        );

        CREATE INDEX IF NOT EXISTS idx_group_posts_group  ON group_posts(group_name);
        CREATE INDEX IF NOT EXISTS idx_group_posts_date   ON group_posts(published_at);
        CREATE INDEX IF NOT EXISTS idx_group_posts_country ON group_posts(country);
        CREATE INDEX IF NOT EXISTS idx_group_posts_sector  ON group_posts(sector);
        CREATE INDEX IF NOT EXISTS idx_groups_slug         ON groups(slug);
        CREATE INDEX IF NOT EXISTS idx_group_urls_group    ON group_urls(group_id);
    """)
    con.commit()
    con.close()
    log.info("Tables verified / created.")


# ── HTTP helpers ───────────────────────────────────────────────────────────────
def _get_json(url: str) -> list | dict | None:
    """Simple HTTP GET with User-Agent, returns parsed JSON or None."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "dark-crawler/1.0 (self-hosted CTI; ransomlook attribution)",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        log.error("HTTP %s fetching %s", e.code, url)
    except urllib.error.URLError as e:
        log.error("URL error fetching %s: %s", url, e.reason)
    except json.JSONDecodeError as e:
        log.error("JSON parse error from %s: %s", url, e)
    except Exception as e:
        log.error("Unexpected error fetching %s: %s", url, e)
    return None


# ── Sync: groups ───────────────────────────────────────────────────────────────
def sync_groups() -> int:
    """Pull /api/groups (list of names), upsert into groups table.

    /api/groups returns a plain list of group name strings: ["lockbit", "alphv", ...]
    We store names + slugs. Status is updated separately when posts are fetched.
    To avoid 575 sequential HTTP calls, we only fetch per-group detail for groups
    that have no URLs yet (first run) — limited to avoid rate limiting.
    """
    log.info("Fetching groups list from RansomLook…")
    data = _get_json(GROUPS_LIST)
    if not data:
        log.warning("No group data returned.")
        return 0

    if isinstance(data, list):
        group_names = [str(n) for n in data if n]
    elif isinstance(data, dict):
        group_names = list(data.keys())
    else:
        log.warning("Unexpected groups API format: %s", type(data))
        return 0

    new_groups = 0
    con = db()

    for name in group_names:
        slug = name.lower().replace(" ", "-")
        cur = con.execute(
            """INSERT INTO groups (name, slug, status)
               VALUES (?, ?, 'unknown')
               ON CONFLICT(name) DO NOTHING""",
            (name, slug),
        )
        if cur.rowcount == 1:
            new_groups += 1

    con.commit()
    con.close()
    log.info("Groups sync complete: %d total, %d newly inserted.", len(group_names), new_groups)
    return new_groups


# ── Sync: recent posts ─────────────────────────────────────────────────────────
def sync_group_detail(name: str) -> None:
    """Fetch /api/group/<name> and upsert locations into group_urls.
    Call this for individual groups when you want .onion URLs populated.
    Not called in bulk during normal sync to avoid rate limits.
    """
    data = _get_json(f"{API_BASE}/group/{urllib.parse.quote(name)}")
    if not data or not isinstance(data, list):
        return
    entry = data[0] if data else {}
    locations = entry.get("locations", [])
    if not locations:
        return

    any_up = any(loc.get("available", False) for loc in locations if isinstance(loc, dict))
    status = "active" if any_up else "offline"

    con = db()
    con.execute("UPDATE groups SET status=? WHERE name=?", (status, name))

    row = con.execute("SELECT id FROM groups WHERE name=?", (name,)).fetchone()
    if row:
        group_id = row["id"]
        for i, loc in enumerate(locations):
            if not isinstance(loc, dict):
                continue
            url = loc.get("slug") or loc.get("url") or ""
            if not url:
                continue
            if not url.startswith("http"):
                url = f"http://{url}"
            uptime = 1.0 if loc.get("available") else 0.0
            con.execute(
                """INSERT INTO group_urls (group_id, url, is_primary, last_seen, uptime_pct)
                   VALUES (?, ?, ?, strftime('%s','now'), ?)
                   ON CONFLICT(url) DO UPDATE SET
                       last_seen  = excluded.last_seen,
                       uptime_pct = excluded.uptime_pct""",
                (group_id, url, 1 if i == 0 else 0, uptime),
            )
    con.commit()
    con.close()


def sync_recent_posts() -> int:
    """Pull /api/posts?days=N, insert new victim posts into group_posts.

    API response is a list of post objects:
    [
      {
        "post_title":  "Acme Corp",
        "group_name":  "lockbit",
        "discovered":  "2024-12-01T10:00:00",
        "published":   "2024-11-30T08:00:00",   # may be absent
        "country":     "US",
        "sector":      "manufacturing",
        "description": "...",
        "url":         "http://..."
      },
      ...
    ]
    """
    url = f"{POSTS_ENDPOINT}?days={POSTS_DAYS}"
    log.info("Fetching posts from RansomLook (%d days)…", POSTS_DAYS)
    data = _get_json(url)
    if not data:
        log.warning("No posts returned.")
        return 0
    # API returns {"posts": [...]} — unwrap if needed
    if isinstance(data, dict):
        data = data.get("posts", [])
    if not isinstance(data, list) or not data:
        log.warning("Unexpected posts format: %s", type(data))
        return 0

    new_posts = 0
    con = db()

    # Track which groups appear in posts so we can mark them active
    active_groups: set[str] = set()

    for post in data:
        if not isinstance(post, dict):
            continue

        title      = (post.get("post_title") or post.get("title") or post.get("victim") or "").strip()
        group_name = (post.get("group_name") or post.get("group") or "").strip()
        # discovered = when ransomlook first saw it; published = group's own date
        published  = (post.get("published") or post.get("discovered") or "").strip()
        country    = (post.get("country") or "").strip()
        sector     = (post.get("sector") or post.get("industry") or "").strip()
        description= (post.get("description") or "").strip()
        source_url = (post.get("url") or post.get("link") or "").strip()

        # Use discovered timestamp as title fallback so no posts are dropped
        if not group_name:
            continue
        if not title:
            title = f"[unknown] {published[:10] if published else 'no date'}"

        active_groups.add(group_name)

        # Dedup: same title + group + published_at
        exists = con.execute(
            "SELECT 1 FROM group_posts WHERE group_name=? AND title=? AND published_at=?",
            (group_name, title, published),
        ).fetchone()
        if exists:
            continue

        con.execute(
            """INSERT INTO group_posts
               (group_name, title, published_at, country, sector, description, source_url, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'ransomlook')""",
            (group_name, title, published, country, sector, description, source_url),
        )
        new_posts += 1

    # Mark groups that posted recently as active
    for gname in active_groups:
        con.execute(
            "UPDATE groups SET status='active' WHERE name=?", (gname,)
        )

    con.commit()
    con.close()
    log.info("Posts sync complete: %d new victim posts inserted (%d active groups updated).",
             new_posts, len(active_groups))
    return new_posts


# ── Stats helpers (for dashboard API) ─────────────────────────────────────────
def get_stats() -> dict:
    """Return summary stats — called by server.py /api/ransom/stats."""
    con = db()
    total_groups  = con.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
    active_groups = con.execute("SELECT COUNT(*) FROM groups WHERE status='active'").fetchone()[0]
    total_victims = con.execute("SELECT COUNT(*) FROM group_posts").fetchone()[0]
    recent_7d     = con.execute(
        "SELECT COUNT(*) FROM group_posts WHERE discovered_at >= strftime('%s','now','-7 days')"
    ).fetchone()[0]

    top_groups = con.execute(
        """SELECT group_name, COUNT(*) as cnt
           FROM group_posts GROUP BY group_name ORDER BY cnt DESC LIMIT 10"""
    ).fetchall()

    top_sectors = con.execute(
        """SELECT sector, COUNT(*) as cnt FROM group_posts
           WHERE sector != '' GROUP BY sector ORDER BY cnt DESC LIMIT 10"""
    ).fetchall()

    top_countries = con.execute(
        """SELECT country, COUNT(*) as cnt FROM group_posts
           WHERE country != '' GROUP BY country ORDER BY cnt DESC LIMIT 10"""
    ).fetchall()

    con.close()
    return {
        "total_groups":  total_groups,
        "active_groups": active_groups,
        "total_victims": total_victims,
        "recent_7d":     recent_7d,
        "top_groups":    [dict(r) for r in top_groups],
        "top_sectors":   [dict(r) for r in top_sectors],
        "top_countries": [dict(r) for r in top_countries],
    }


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 60)
    log.info("Dark Crawler — group_sync.py starting")
    log.info("DB: %s", DB_PATH)

    ensure_tables()

    t0 = time.time()
    g_new = sync_groups()
    p_new = sync_recent_posts()
    elapsed = time.time() - t0

    stats = get_stats()
    log.info(
        "Sync done in %.1fs | groups: %d total (%d active) | victims: %d total | +%d posts this run",
        elapsed,
        stats["total_groups"],
        stats["active_groups"],
        stats["total_victims"],
        p_new,
    )
    log.info("=" * 60)

    # Exit 2 only if DB is completely empty (genuine failure), not just no new data this run
    if stats["total_groups"] == 0 and stats["total_victims"] == 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
