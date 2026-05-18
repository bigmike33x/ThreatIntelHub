"""
telegram_history.py
────────────────────
Reads message history from already-joined Telegram channels.
Run this separately from telegram_monitor.py to process history
without triggering flood bans from joining new channels.

Usage:
    python telegram_history.py

Requires TG_API_ID and TG_API_HASH environment variables.
"""

import asyncio
import sqlite3
import json
import time
import logging
import os
import re
from pathlib import Path
from datetime import timezone

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [TG-HISTORY] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger()

from telethon import TelegramClient, events
from telethon.errors import FloodWaitError

DB_PATH = Path(__file__).parent / 'crawler.db'
SESSION = str(Path(__file__).parent / 'tg_session')

# ── Leak detection ─────────────────────────────────────────────────────────────
EMAIL_RE  = re.compile(r'[\w\.-]+@[\w\.-]+\.\w{2,}')
HASH_RE   = re.compile(r'\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b', re.I)
CVE_RE    = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
SSN_RE    = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
RECORD_RE = re.compile(r'(\d+[\.,]?\d*)\s*(million|k|thousand)\s*(records?|accounts?|emails?)', re.I)
MAGNET_RE = re.compile(r'magnet:\?xt=urn:', re.I)
LEAK_KWS  = [
    'credential','dump','leak','breach','combo','stealer','log',
    'password','hash','database','ssn','social security','fullz',
    'infostealer','redline','raccoon','vidar','0day','exploit','cve',
]

# Telegram channel link discovery
TG_LINK_RE = re.compile(r'(?:https?://)?t\.me/([\w+@\-/]+)', re.I)

def save_new_channel(url, source):
    """Save a newly discovered channel to DB for future joining."""
    name = url.rstrip("/").split("/")[-1]
    con = db()
    try:
        con.execute(
            "INSERT OR IGNORE INTO telegram_channels "
            "(url,name,channel_type,joined,active,discovered_from) "
            "VALUES (?,?,'discovered',0,1,?)",
            (url, name, source))
        con.commit()
    except: pass
    con.close()

def discover_channels(text, source):
    """Find t.me links in message text and save for future joining."""
    handles = TG_LINK_RE.findall(text)
    for handle in handles[:10]:  # cap at 10 per message
        if "/" not in handle and len(handle) > 3:  # skip paths, keep channel names
            url = f"https://t.me/{handle}"
            save_new_channel(url, source)

def analyze(text):
    if not text or len(text) < 20:
        return False, 0
    tl   = text.lower()
    score = 0
    if len(EMAIL_RE.findall(text)) >= 3:  score += 30
    if len(HASH_RE.findall(text))  >= 3:  score += 20
    if CVE_RE.search(text):               score += 35
    if SSN_RE.search(text):               score += 40
    if RECORD_RE.search(text):            score += 20
    if MAGNET_RE.search(text):            score += 15
    score += min(sum(5 for k in LEAK_KWS if k in tl), 25)
    return score >= 35, score

def db():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con

def save_message(channel_id, channel_name, msg_id, text, ts, is_leak, conf):
    con = db()
    try:
        con.execute('''INSERT OR IGNORE INTO telegram_messages
            (channel_id,channel_name,message_id,text,timestamp,has_leak,confidence,processed)
            VALUES (?,?,?,?,?,?,?,1)''',
            (str(channel_id), channel_name, msg_id,
             text[:2000], ts, 1 if is_leak else 0, conf))
        # Save high confidence hits to main leaks table
        if is_leak and conf >= 45:
            url = f"https://t.me/{channel_name}/{msg_id}"
            con.execute('''INSERT OR IGNORE INTO leaks
                (url,title,confidence,full_text,cves,breach_targets,
                 record_counts,has_emails,has_hashes,has_ssn,has_magnet,timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                (url,
                 f"[Telegram] {channel_name}: {text[:80]}",
                 conf, text[:2000],
                 json.dumps(list(set(CVE_RE.findall(text)))),
                 '[]', '[]',
                 1 if len(EMAIL_RE.findall(text)) >= 3 else 0,
                 1 if len(HASH_RE.findall(text))  >= 3 else 0,
                 1 if SSN_RE.search(text) else 0,
                 1 if MAGNET_RE.search(text) else 0,
                 ts))
        con.commit()
    except Exception as e:
        log.debug(f"DB error: {e}")
    finally:
        con.close()

async def main():
    api_id   = os.environ.get('TG_API_ID')
    api_hash = os.environ.get('TG_API_HASH')

    if not api_id or not api_hash:
        log.error("Set TG_API_ID and TG_API_HASH environment variables")
        return

    client = TelegramClient(SESSION, int(api_id), api_hash)
    await client.start()
    log.info("Connected to Telegram")

    # Load joined channels from database
    con = db()
    rows = con.execute(
        "SELECT url, name, channel_id FROM telegram_channels WHERE joined=1 ORDER BY name"
    ).fetchall()
    con.close()

    if not rows:
        log.error("No joined channels found in database. Run telegram_monitor.py first.")
        return

    log.info(f"Found {len(rows)} joined channels — loading entities...")

    # Use stored channel_id to avoid get_entity() API calls
    # get_entity() triggers rate limits — using InputChannel with stored ID is free
    from telethon.tl.types import InputChannel, PeerChannel
    entities = []
    for i, row in enumerate(rows):
        try:
            # If we have a stored numeric channel_id, use it directly
            cid = row['channel_id']
            if cid and str(cid).lstrip('-').isdigit():
                cid_int = int(cid)
                # Try direct peer access — no API call needed
                try:
                    entity = await client.get_entity(PeerChannel(abs(cid_int)))
                    entities.append((entity, row['name']))
                    # Store channel_id for future use
                    con2 = db()
                    con2.execute("UPDATE telegram_channels SET channel_id=? WHERE url=?",
                                (str(entity.id), row['url']))
                    con2.commit(); con2.close()
                    continue
                except: pass
            # Fall back to URL lookup with longer delay
            entity = await client.get_entity(row['url'])
            entities.append((entity, row['name']))
            # Store the ID so next run doesn't need API call
            con2 = db()
            con2.execute("UPDATE telegram_channels SET channel_id=? WHERE url=?",
                        (str(entity.id), row['url']))
            con2.commit(); con2.close()
            if (i + 1) % 20 == 0:
                log.info(f"  Loaded {i+1}/{len(rows)} channels")
            await asyncio.sleep(3)  # longer delay between lookups
        except FloodWaitError as e:
            log.warning(f"Flood wait {e.seconds}s — sleeping")
            await asyncio.sleep(e.seconds + 5)
        except Exception as e:
            log.debug(f"Could not load {row['name']}: {e}")
            await asyncio.sleep(1)

    log.info(f"Loaded {len(entities)} entities — processing history one at a time")

    # Process one channel at a time to keep memory flat
    MSGS_PER_CH  = 200  # balance between coverage and memory
    total_saved  = 0
    total_leaks  = 0
    import gc

    for i, (entity, name) in enumerate(entities):
        try:
            channel_id = entity.id
            msg_count  = 0
            async for msg in client.iter_messages(entity, limit=MSGS_PER_CH):
                if not msg.text: continue
                is_leak, conf = analyze(msg.text)
                ts = int(msg.date.replace(tzinfo=timezone.utc).timestamp())
                save_message(channel_id, name, msg.id,
                             msg.text, ts, is_leak, conf)
                discover_channels(msg.text, name)
                msg_count  += 1
                total_saved += 1
                if is_leak:
                    total_leaks += 1
                    log.info(f"  [LEAK {conf}%] {name}: {msg.text[:80]}")

            con = db()
            con.execute(
                "UPDATE telegram_channels SET last_message=? WHERE name=?",
                (int(time.time()), name))
            con.commit()
            con.close()

            if msg_count > 0:
                log.info(f"[{i+1}/{len(entities)}] {name}: {msg_count} msgs "
                         f"({total_saved} total, {total_leaks} leaks)")

            # Free entity from memory after processing
            del entity
            gc.collect()
            await asyncio.sleep(2)

        except FloodWaitError as e:
            log.warning(f"Flood wait {e.seconds}s — sleeping")
            await asyncio.sleep(e.seconds + 5)
        except Exception as e:
            log.debug(f"Error reading {name}: {e}")
            await asyncio.sleep(1)

        # Pause every 20 channels
        if (i + 1) % 20 == 0:
            log.info(f"Processed {i+1}/{len(entities)} channels — pausing 30s")
            gc.collect()
            await asyncio.sleep(30)

    # Free all entities
    entities.clear()
    gc.collect()

    log.info(f"History complete — {total_saved} messages saved, {total_leaks} leak hits")
    log.info("Switching to live monitoring...")

    # Now listen for new messages in real time
    @client.on(events.NewMessage)
    async def handler(event):
        if not event.text: return
        try:
            chat = await event.get_chat()
            name = getattr(chat, 'title', str(chat.id))
            is_leak, conf = analyze(event.text)
            ts = int(time.time())
            save_message(chat.id, name, event.id,
                         event.text, ts, is_leak, conf)
            discover_channels(event.text, name)
            if is_leak:
                log.info(f"[LIVE LEAK {conf}%] {name}: {event.text[:80]}")
        except Exception as e:
            log.debug(f"Handler error: {e}")

    log.info("Listening for live messages...")
    await client.run_until_disconnected()


if __name__ == '__main__':
    asyncio.run(main())
