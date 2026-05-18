"""
telegram_monitor.py — Dark Crawler Telegram Monitor
─────────────────────────────────────────────────────
Monitors Telegram channels for leak/threat intel with aggressive
rate limit protection. Joins channels slowly, uses stored IDs
to avoid repeated API calls, and backs off at any hint of rate limiting.

Usage:
    export TG_API_ID=your_id
    export TG_API_HASH=your_hash
    python telegram_monitor.py

Rate limit strategy:
    - 15s between each new channel join
    - 5 minute pause every 10 joins
    - Uses stored channel_id to skip get_entity() on already-known channels
    - On any FloodWaitError: sleep the full wait + 30s buffer, then continue
    - Never retries a failed join — moves on
"""

import asyncio
import json
import re
import os
import sqlite3
import time
import logging
from pathlib import Path
from datetime import timezone

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [TG] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('tg_monitor')

try:
    from telethon import TelegramClient, events
    from telethon.tl.types import Channel, PeerChannel
    from telethon.errors import (
        FloodWaitError, ChannelPrivateError,
        InviteHashExpiredError, UserAlreadyParticipantError,
        UsernameInvalidError, UsernameNotOccupiedError,
    )
    HAS_TELETHON = True
except ImportError:
    HAS_TELETHON = False
    log.error("Telethon not installed. Run: pip install telethon")

BASE_DIR   = Path(__file__).parent
DB_PATH    = BASE_DIR / "crawler.db"
SEEDS_FILE = BASE_DIR / "cti_seeds.json"
SESSION    = str(BASE_DIR / "tg_monitor_session")

# ── Rate limit settings ────────────────────────────────────────────────────────
JOIN_DELAY       = 15    # seconds between each join attempt
JOIN_BATCH_PAUSE = 300   # 5 min pause every N joins
JOIN_BATCH_SIZE  = 10    # joins per batch
FLOOD_BUFFER     = 30    # extra seconds added to any flood wait
HISTORY_LIMIT    = 50    # messages to fetch per channel on startup
HISTORY_DELAY    = 2     # seconds between channels during history

# ── Leak detection ─────────────────────────────────────────────────────────────
EMAIL_RE  = re.compile(r'[\w\.-]+@[\w\.-]+\.\w{2,}')
HASH_RE   = re.compile(r'\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b', re.I)
CVE_RE    = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
SSN_RE    = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
RECORD_RE = re.compile(r'(\d+[\.,]?\d*)\s*(million|k|thousand)\s*(records?|accounts?|emails?)', re.I)
MAGNET_RE = re.compile(r'magnet:\?xt=urn:', re.I)
TG_LINK_RE = re.compile(r'(?:https?://)?t\.me/([\w+@\-/]+)', re.I)

LEAK_SIGNALS = [
    'data breach','database leak','credential dump','password dump',
    'combo list','leaked database','data dump','db dump','sql dump',
    '0day','zero day','rce exploit','proof of concept','vulnerability',
    'plaintext passwords','hashed passwords','ssn','social security',
    'million records','million accounts','ransomware','victim','encrypted',
    'stealer logs','infostealer','redline','raccoon','vidar',
]
NOISE_SIGNALS = [
    'buy this database','for sale','purchase access','contact to buy',
    'guaranteed','100% working','legit seller','trusted vendor',
]

def analyze_message(text):
    if not text or len(text) < 20:
        return False, 0, {}
    tl    = text.lower()
    score = 0
    ext   = {}

    if sum(1 for k in NOISE_SIGNALS if k in tl) >= 2:
        return False, 0, {}

    emails = EMAIL_RE.findall(text)
    if len(emails) >= 3:
        score += 30
        ext['sample_emails'] = list(set(emails[:5]))

    hashes = HASH_RE.findall(text)
    if len(hashes) >= 3:
        score += 20
        ext['hash_count'] = len(hashes)

    cves = list(set(CVE_RE.findall(text)))
    if cves:
        score += 35
        ext['cves'] = cves[:10]

    if SSN_RE.search(text):
        score += 40
        ext['has_ssn'] = True

    records = RECORD_RE.findall(text)
    if records:
        score += 20
        ext['record_counts'] = [f"{m[0]} {m[1]} {m[2]}" for m in records[:3]]

    if MAGNET_RE.search(text):
        score += 15
        ext['has_magnet'] = True

    signal_hits = [kw for kw in LEAK_SIGNALS if kw in tl]
    score += min(len(signal_hits) * 5, 25)
    if signal_hits:
        ext['signals'] = signal_hits[:5]

    new_channels = TG_LINK_RE.findall(text)
    if new_channels:
        ext['discovered_channels'] = [f"https://t.me/{c}" for c in new_channels[:5]]

    return score >= 35, min(score, 100), ext

# ── Database ───────────────────────────────────────────────────────────────────
def db():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con

def ensure_tables():
    con = db()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS telegram_messages (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id   TEXT,
        channel_name TEXT,
        message_id   INTEGER,
        text         TEXT,
        timestamp    INTEGER,
        has_leak     INTEGER DEFAULT 0,
        confidence   INTEGER DEFAULT 0,
        processed    INTEGER DEFAULT 0,
        UNIQUE(channel_id, message_id)
    );
    CREATE TABLE IF NOT EXISTS telegram_channels (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        url           TEXT UNIQUE,
        name          TEXT,
        channel_type  TEXT,
        channel_id    TEXT,
        access_hash   TEXT,
        joined        INTEGER DEFAULT 0,
        active        INTEGER DEFAULT 1,
        message_count INTEGER DEFAULT 0,
        last_message  INTEGER,
        discovered_from TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_tg_has_leak ON telegram_messages(has_leak);
    CREATE INDEX IF NOT EXISTS idx_tg_channel  ON telegram_messages(channel_id);
    ''')
    # Add channel_id column if missing (migration)
    cols = [r[1] for r in con.execute("PRAGMA table_info(telegram_channels)").fetchall()]
    if 'channel_id' not in cols:
        con.execute("ALTER TABLE telegram_channels ADD COLUMN channel_id TEXT")
        log.info("Migrated: added channel_id column")
    if 'access_hash' not in cols:
        con.execute("ALTER TABLE telegram_channels ADD COLUMN access_hash TEXT")
        log.info("Migrated: added access_hash column")
    con.commit()
    con.close()

def save_message(channel_id, channel_name, msg_id, text, timestamp, is_leak, confidence, extracted):
    con = db()
    try:
        con.execute('''INSERT OR IGNORE INTO telegram_messages
            (channel_id,channel_name,message_id,text,timestamp,has_leak,confidence,processed)
            VALUES (?,?,?,?,?,?,?,1)''',
            (str(channel_id), channel_name, msg_id,
             text[:2000], timestamp, 1 if is_leak else 0, confidence))
        if is_leak and confidence >= 45:
            url = f"https://t.me/{channel_name}/{msg_id}"
            con.execute('''INSERT OR IGNORE INTO leaks
                (url,title,confidence,full_text,cves,breach_targets,
                 record_counts,has_emails,has_hashes,has_ssn,has_magnet,timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                (url,
                 f"[Telegram] {channel_name}: {text[:60]}...",
                 confidence, text[:2000],
                 json.dumps(extracted.get('cves',[])),
                 json.dumps(extracted.get('breach_targets',[])),
                 json.dumps(extracted.get('record_counts',[])),
                 1 if extracted.get('sample_emails') else 0,
                 1 if extracted.get('hash_count') else 0,
                 1 if extracted.get('has_ssn') else 0,
                 1 if extracted.get('has_magnet') else 0,
                 timestamp))
        con.commit()
    except Exception as e:
        log.debug(f"DB save error: {e}")
    finally:
        con.close()

def save_channel(url, name, channel_type, discovered_from=None):
    con = db()
    try:
        con.execute('''INSERT OR IGNORE INTO telegram_channels
            (url,name,channel_type,joined,active,discovered_from)
            VALUES (?,?,?,0,1,?)''',
            (url, name, channel_type, discovered_from or 'seed'))
        con.commit()
    except: pass
    con.close()

def mark_joined(url, channel_id, access_hash=None):
    con = db()
    con.execute(
        "UPDATE telegram_channels SET joined=1, channel_id=?, access_hash=? WHERE url=?",
        (str(channel_id), str(access_hash) if access_hash else None, url))
    con.commit()
    con.close()

def mark_inactive(url):
    con = db()
    con.execute("UPDATE telegram_channels SET active=0 WHERE url=?", (url,))
    con.commit()
    con.close()

def get_pending_channels():
    """Get channels not yet joined, with any stored channel_id and access_hash."""
    con = db()
    rows = con.execute(
        "SELECT url, name, channel_id, access_hash FROM telegram_channels "
        "WHERE active=1 AND joined=0 ORDER BY id"
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]

def get_joined_channels():
    """Get all joined channels with stored IDs and access hashes."""
    con = db()
    rows = con.execute(
        "SELECT url, name, channel_id, access_hash FROM telegram_channels "
        "WHERE joined=1 AND active=1 ORDER BY id"
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]

def discover_new_channels(extracted, source):
    for ch_url in extracted.get('discovered_channels', []):
        name = ch_url.split('/')[-1]
        save_channel(ch_url, name, 'discovered', source)

# ── Safe entity loading ────────────────────────────────────────────────────────
async def safe_get_entity(client, ch, delay=True):
    """
    Load a Telegram entity with flood protection.

    Priority order (least API calls first):
    1. InputPeerChannel(id, access_hash) — zero API calls, instant
    2. PeerChannel(id) — minimal API call
    3. URL lookup — full API call, most likely to rate limit

    Returns entity or None.
    """
    from telethon.tl.types import InputPeerChannel
    cid  = ch.get('channel_id')
    ahash = ch.get('access_hash')
    url  = ch.get('url', '')

    # Option 1: Both ID and access_hash stored — zero API call needed
    if cid and ahash and str(cid).lstrip('-').isdigit() and str(ahash).lstrip('-').isdigit():
        try:
            entity = await client.get_entity(
                InputPeerChannel(abs(int(cid)), int(ahash)))
            return entity
        except Exception:
            pass  # Fall through

    # Option 2: ID only — one lightweight API call
    if cid and str(cid).lstrip('-').isdigit():
        try:
            entity = await client.get_entity(PeerChannel(abs(int(cid))))
            return entity
        except FloodWaitError as e:
            log.warning(f"Flood wait {e.seconds}s loading {ch.get('name','?')} by ID")
            await asyncio.sleep(e.seconds + FLOOD_BUFFER)
            return None
        except Exception:
            pass  # Fall through to URL lookup

    # URL lookup — slower, more API calls
    if not url:
        return None
    try:
        if delay:
            await asyncio.sleep(JOIN_DELAY)
        entity = await client.get_entity(url)
        return entity
    except FloodWaitError as e:
        log.warning(f"Flood wait {e.seconds}s joining {url}")
        await asyncio.sleep(e.seconds + FLOOD_BUFFER)
        return None
    except (ChannelPrivateError, InviteHashExpiredError,
            UsernameInvalidError, UsernameNotOccupiedError):
        log.info(f"Cannot join (private/expired/invalid): {url}")
        mark_inactive(url)
        return None
    except UserAlreadyParticipantError:
        # Already a member — just get the entity
        try:
            entity = await client.get_entity(url)
            return entity
        except: return None
    except Exception as e:
        log.debug(f"Join error {url}: {e}")
        return None

# ── Main monitor ───────────────────────────────────────────────────────────────
async def run_monitor():
    if not HAS_TELETHON:
        log.error("Cannot run: telethon not installed")
        return

    api_id   = os.environ.get('TG_API_ID')
    api_hash = os.environ.get('TG_API_HASH')
    if not api_id or not api_hash:
        log.error(
            "Missing TG_API_ID and TG_API_HASH.\n"
            "Run: export TG_API_ID=xxx && export TG_API_HASH=yyy"
        )
        return

    ensure_tables()

    # Seed channels from cti_seeds.json
    try:
        seeds = json.loads(SEEDS_FILE.read_text())
        for url in seeds.get('telegram_infostealer', []):
            save_channel(url, url.split('/')[-1], 'infostealer')
        for url in seeds.get('telegram_threat_actors', []):
            save_channel(url, url.split('/')[-1], 'threat_actor')
        log.info(f"Seeds loaded from cti_seeds.json")
    except Exception as e:
        log.warning(f"Could not load cti_seeds.json: {e}")

    client = TelegramClient(SESSION, int(api_id), api_hash)
    await client.start()
    log.info("Telegram client connected")

    # ── Step 1: Load joined channels via get_dialogs() ──────────────────────────
    # This is ONE API call that returns ALL channels you're a member of.
    # Zero per-channel API calls. Zero flood risk.
    log.info("Loading joined channels via get_dialogs() (one API call)...")
    monitoring = []
    dialog_map = {}  # channel_id -> entity

    try:
        async for dialog in client.iter_dialogs():
            entity = dialog.entity
            if not hasattr(entity, 'id'): continue
            cid   = entity.id
            ahash = getattr(entity, 'access_hash', None)
            title = getattr(entity, 'title', str(cid))
            dialog_map[cid] = entity
            monitoring.append(entity)
            # Store/update channel_id and access_hash in DB
            con = db()
            con.execute(
                "UPDATE telegram_channels SET channel_id=?, access_hash=?, joined=1 "
                "WHERE channel_id=? OR name=?",
                (str(cid), str(ahash) if ahash else None, str(cid), title))
            con.commit()
            con.close()
    except FloodWaitError as e:
        log.warning(f"Flood wait {e.seconds}s on get_dialogs — sleeping")
        await asyncio.sleep(e.seconds + FLOOD_BUFFER)
    except Exception as e:
        log.warning(f"get_dialogs error: {e}")

    log.info(f"Loaded {len(monitoring)} channels from dialogs")

    # ── Step 2: Process recent history for loaded channels ─────────────────────
    if monitoring:
        log.info(f"Processing last {HISTORY_LIMIT} messages from {len(monitoring)} channels...")
        import gc
        total_msgs  = 0
        total_leaks = 0

        for i, entity in enumerate(monitoring):
            name = getattr(entity, 'title', str(entity.id))
            try:
                async for msg in client.iter_messages(entity, limit=HISTORY_LIMIT):
                    if not msg.text: continue
                    is_leak, conf, extracted = analyze_message(msg.text)
                    ts = int(msg.date.replace(tzinfo=timezone.utc).timestamp())
                    save_message(entity.id, name, msg.id,
                                 msg.text, ts, is_leak, conf, extracted)
                    total_msgs += 1
                    if is_leak:
                        total_leaks += 1
                        log.info(f"[LEAK {conf}%] {name}: {msg.text[:80]}")
                        discover_new_channels(extracted, name)

                con = db()
                con.execute("UPDATE telegram_channels SET last_message=? WHERE channel_id=?",
                            (int(time.time()), str(entity.id)))
                con.commit()
                con.close()

                if (i + 1) % 20 == 0:
                    log.info(f"History: {i+1}/{len(monitoring)} channels, "
                             f"{total_msgs} messages, {total_leaks} leaks")
                    gc.collect()
                    await asyncio.sleep(10)
                else:
                    await asyncio.sleep(HISTORY_DELAY)

            except FloodWaitError as e:
                log.warning(f"Flood wait {e.seconds}s during history — sleeping")
                await asyncio.sleep(e.seconds + FLOOD_BUFFER)
            except Exception as e:
                log.debug(f"History error {name}: {e}")
                await asyncio.sleep(1)

        monitoring.clear()
        gc.collect()
        log.info(f"History done: {total_msgs} messages, {total_leaks} leaks")

    # ── Step 3: Join pending channels slowly ───────────────────────────────────
    pending = get_pending_channels()
    log.info(f"{len(pending)} channels pending to join")
    log.info(f"Join rate: {JOIN_DELAY}s per channel, "
             f"{JOIN_BATCH_PAUSE}s pause every {JOIN_BATCH_SIZE}")

    joined_count = 0
    for i, ch in enumerate(pending):
        entity = await safe_get_entity(client, ch, delay=True)
        if entity:
            # Store both channel_id AND access_hash for future zero-API-call lookups
            ahash = getattr(entity, 'access_hash', None)
            mark_joined(ch['url'], entity.id, ahash)
            joined_count += 1
            log.info(f"[{i+1}/{len(pending)}] Joined: {getattr(entity,'title',ch['url'])}")

        # Batch pause
        if (i + 1) % JOIN_BATCH_SIZE == 0:
            log.info(f"Joined {joined_count} so far — pausing {JOIN_BATCH_PAUSE}s...")
            await asyncio.sleep(JOIN_BATCH_PAUSE)

    log.info(f"Joining complete: {joined_count} new channels joined")

    # ── Step 4: Live monitoring ────────────────────────────────────────────────
    log.info("Listening for new messages...")

    @client.on(events.NewMessage)
    async def handler(event):
        if not event.text: return
        try:
            chat = await event.get_chat()
            name = getattr(chat, 'title', str(chat.id))
            is_leak, conf, extracted = analyze_message(event.text)
            ts = int(time.time())
            save_message(chat.id, name, event.id,
                         event.text, ts, is_leak, conf, extracted)
            # Discover new channels from any message (not just leaks)
            discover_new_channels(extracted, name)
            if is_leak:
                log.info(f"[LIVE LEAK {conf}%] {name}: {event.text[:80]}")
            con = db()
            con.execute('''UPDATE telegram_channels SET
                message_count=message_count+1, last_message=?
                WHERE channel_id=?''', (ts, str(chat.id)))
            con.commit()
            con.close()
        except Exception as e:
            log.debug(f"Handler error: {e}")

    await client.run_until_disconnected()


if __name__ == '__main__':
    log.info("Dark Crawler — Telegram Monitor")
    log.info("--------------------------------")
    log.info(f"DB:    {DB_PATH}")
    log.info(f"Seeds: {SEEDS_FILE}")
    log.info(f"Join delay: {JOIN_DELAY}s per channel")
    log.info(f"Batch pause: {JOIN_BATCH_PAUSE}s every {JOIN_BATCH_SIZE} joins")
    asyncio.run(run_monitor())
