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

# ── Stealer detection (shared module) ─────────────────────────────────────────
try:
    from stealer_detection import detect_stealers
    HAS_STEALER_DETECTION = True
except ImportError:
    HAS_STEALER_DETECTION = False
    log.warning("stealer_detection.py not found — stealer intel disabled. "
                "Place stealer_detection.py in the same directory.")

# ── Message intel extraction (creds, C2, tools, actor handles) ────────────────
try:
    from message_intel import extract_message_intel
    HAS_MESSAGE_INTEL = True
except ImportError:
    HAS_MESSAGE_INTEL = False
    log.warning("message_intel.py not found — cred/C2/tool/actor extraction disabled.")

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
    """
    Score a message for leak/threat content.
    Returns (is_leak, score, ext_dict) where ext_dict contains all extracted intel
    including stealer family detection if stealer_detection.py is available.
    """
    if not text or len(text) < 20:
        return False, 0, {}

    tl    = text.lower()
    score = 0
    ext   = {}

    # ── Base leak signals ──────────────────────────────────────────────────────
    emails = EMAIL_RE.findall(text)
    if len(emails) >= 3:
        score += 30
        ext['sample_emails'] = list(set(emails[:5]))
    elif len(emails) >= 1:
        score += 10

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

    kw_hits = [k for k in LEAK_KWS if k in tl]
    score += min(len(kw_hits) * 5, 25)
    if kw_hits:
        ext['signals'] = kw_hits[:5]

    # ── Stealer family detection ───────────────────────────────────────────────
    if HAS_STEALER_DETECTION:
        stealer = detect_stealers(text)
        if stealer['families'] or stealer['log_count'] or stealer['target_domains']:
            boost = min(stealer['confidence_boost'], 35)
            score += boost
            ext['stealer_intel'] = stealer
            if stealer['families']:
                log.debug(f"  Stealer families: {stealer['families']} "
                          f"(+{boost}pts, targets: {stealer['target_domains'][:3]})")

    # ── Deep message intel (creds, C2, tools, actor handles) ──────────────────
    if HAS_MESSAGE_INTEL:
        intel = extract_message_intel(text)
        if intel:
            ext['message_intel'] = intel
            # Boost score for high-value findings
            if intel.get('cred_samples'):
                score += 15
            if intel.get('c2_ips') or intel.get('c2_domains'):
                score += 20
            if intel.get('tool_files') or intel.get('github_links'):
                score += 10
            if intel.get('cred_count', 0) >= 10:
                score += 10  # large cred dump bonus

    return score >= 35, min(score, 100), ext

def db():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con

def ensure_stealer_column():
    """Add stealer_intel column to telegram_messages if it doesn't exist."""
    con = db()
    cols = [r[1] for r in con.execute(
        "PRAGMA table_info(telegram_messages)").fetchall()]
    if 'stealer_intel' not in cols:
        con.execute(
            "ALTER TABLE telegram_messages ADD COLUMN stealer_intel TEXT DEFAULT NULL")
        con.commit()
        log.info("Migrated: added stealer_intel column to telegram_messages")
    con.close()

def save_message(channel_id, channel_name, msg_id, text, ts, is_leak, conf, ext=None):
    """
    Save a Telegram message to the DB.
    ext dict may contain stealer_intel, message_intel, cves, sample_emails, etc.
    """
    ext = ext or {}

    # Serialize stealer intel — only store if something was actually detected
    stealer_json = None
    si = ext.get('stealer_intel')
    if si and (si.get('families') or si.get('log_count') or si.get('target_domains')):
        stealer_json = json.dumps(si)

    # Merge message_intel into stealer_json blob for storage efficiency
    # Both go into the same stealer_intel column as a unified JSON object
    mi = ext.get('message_intel')
    if mi:
        combined = json.loads(stealer_json) if stealer_json else {}
        combined.update(mi)
        stealer_json = json.dumps(combined)

    con = db()
    try:
        con.execute('''INSERT OR IGNORE INTO telegram_messages
            (channel_id,channel_name,message_id,text,timestamp,
             has_leak,confidence,processed,stealer_intel)
            VALUES (?,?,?,?,?,?,?,1,?)''',
            (str(channel_id), channel_name, msg_id,
             text[:2000], ts, 1 if is_leak else 0, conf, stealer_json))

        # Save high-confidence hits to main leaks table
        if is_leak and conf >= 45:
            url = f"https://t.me/{channel_name}/{msg_id}"

            # Build descriptive title
            parts = []
            if si and si.get('families'):
                parts.append('/'.join(si['families'][:2]))
            if mi and mi.get('tool_categories'):
                parts.append('+'.join(mi['tool_categories'][:2]))
            if mi and mi.get('c2_ips'):
                parts.append('C2')
            prefix = f"[{', '.join(parts)}]" if parts else "[Telegram]"
            title  = f"{prefix} {channel_name}: {text[:80]}"

            con.execute('''INSERT OR IGNORE INTO leaks
                (url,title,confidence,full_text,cves,breach_targets,
                 record_counts,has_emails,has_hashes,has_ssn,has_magnet,timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                (url, title, conf, text[:2000],
                 json.dumps(ext.get('cves', [])),
                 '[]',
                 json.dumps(ext.get('record_counts', [])),
                 1 if ext.get('sample_emails') or (mi and mi.get('cred_samples')) else 0,
                 1 if ext.get('hash_count')    else 0,
                 1 if ext.get('has_ssn')       else 0,
                 1 if ext.get('has_magnet')    else 0,
                 ts))
        con.commit()
    except Exception as e:
        import traceback
        log.warning(f"DB error: {e}\n{traceback.format_exc()}")
    finally:
        con.close()

async def main():
    api_id   = os.environ.get('TG_API_ID')
    api_hash = os.environ.get('TG_API_HASH')

    if not api_id or not api_hash:
        log.error("Set TG_API_ID and TG_API_HASH environment variables")
        return

    # Run DB migration before anything else
    ensure_stealer_column()

    client = TelegramClient(SESSION, int(api_id), api_hash)
    await client.start()
    log.info("Connected to Telegram")

    if HAS_STEALER_DETECTION:
        log.info("Stealer family detection: ENABLED")
    else:
        log.info("Stealer family detection: DISABLED (missing stealer_detection.py)")

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
    from telethon.tl.types import InputChannel, PeerChannel
    entities = []
    for i, row in enumerate(rows):
        try:
            cid = row['channel_id']
            if cid and str(cid).lstrip('-').isdigit():
                cid_int = int(cid)
                try:
                    entity = await client.get_entity(PeerChannel(abs(cid_int)))
                    entities.append((entity, row['name']))
                    con2 = db()
                    con2.execute("UPDATE telegram_channels SET channel_id=? WHERE url=?",
                                (str(entity.id), row['url']))
                    con2.commit(); con2.close()
                    continue
                except: pass
            # Fall back to URL lookup
            entity = await client.get_entity(row['url'])
            entities.append((entity, row['name']))
            con2 = db()
            con2.execute("UPDATE telegram_channels SET channel_id=? WHERE url=?",
                        (str(entity.id), row['url']))
            con2.commit(); con2.close()
            if (i + 1) % 20 == 0:
                log.info(f"  Loaded {i+1}/{len(rows)} channels")
            await asyncio.sleep(3)
        except FloodWaitError as e:
            log.warning(f"Flood wait {e.seconds}s — sleeping")
            await asyncio.sleep(e.seconds + 5)
        except Exception as e:
            log.debug(f"Could not load {row['name']}: {e}")
            await asyncio.sleep(1)

    log.info(f"Loaded {len(entities)} entities — processing history one at a time")

    MSGS_PER_CH  = 200
    total_saved  = 0
    total_leaks  = 0
    stealer_hits = 0
    import gc

    for i, (entity, name) in enumerate(entities):
        try:
            channel_id = entity.id
            msg_count  = 0
            async for msg in client.iter_messages(entity, limit=MSGS_PER_CH):
                if not msg.text: continue
                is_leak, conf, ext = analyze(msg.text)
                ts = int(msg.date.replace(tzinfo=timezone.utc).timestamp())
                save_message(channel_id, name, msg.id,
                             msg.text, ts, is_leak, conf, ext)
                discover_channels(msg.text, name)
                msg_count  += 1
                total_saved += 1
                if is_leak:
                    total_leaks += 1
                    si = ext.get('stealer_intel', {})
                    families = si.get('families', [])
                    if families:
                        stealer_hits += 1
                        log.info(f"  [LEAK {conf}% | {', '.join(families)}] "
                                 f"{name}: {msg.text[:70]}")
                    else:
                        log.info(f"  [LEAK {conf}%] {name}: {msg.text[:80]}")

            con = db()
            con.execute(
                "UPDATE telegram_channels SET last_message=? WHERE name=?",
                (int(time.time()), name))
            con.commit()
            con.close()

            if msg_count > 0:
                log.info(f"[{i+1}/{len(entities)}] {name}: {msg_count} msgs "
                         f"({total_saved} total, {total_leaks} leaks, "
                         f"{stealer_hits} stealer hits)")

            del entity
            gc.collect()
            await asyncio.sleep(2)

        except FloodWaitError as e:
            log.warning(f"Flood wait {e.seconds}s — sleeping")
            await asyncio.sleep(e.seconds + 5)
        except Exception as e:
            log.debug(f"Error reading {name}: {e}")
            await asyncio.sleep(1)

        if (i + 1) % 20 == 0:
            log.info(f"Processed {i+1}/{len(entities)} channels — pausing 30s")
            gc.collect()
            await asyncio.sleep(30)

    entities.clear()
    gc.collect()

    log.info(f"History complete — {total_saved} messages, "
             f"{total_leaks} leak hits, {stealer_hits} stealer family detections")
    log.info("Switching to live monitoring...")

    # Live monitoring
    @client.on(events.NewMessage)
    async def handler(event):
        if not event.text: return
        try:
            chat = await event.get_chat()
            name = getattr(chat, 'title', str(chat.id))
            is_leak, conf, ext = analyze(event.text)
            ts = int(time.time())
            save_message(chat.id, name, event.id,
                         event.text, ts, is_leak, conf, ext)
            discover_channels(event.text, name)
            if is_leak:
                si = ext.get('stealer_intel', {})
                mi = ext.get('message_intel', {})
                families = si.get('families', [])
                c2s      = mi.get('c2_ips', []) or mi.get('c2_domains', [])
                tools    = mi.get('tool_files', []) or mi.get('github_links', [])
                actors   = mi.get('attributed_to', []) or mi.get('tg_handles', [])
                parts    = []
                if families: parts.append(f"families:{','.join(families)}")
                if c2s:      parts.append(f"C2:{c2s[0]}")
                if tools:    parts.append(f"tool:{tools[0]}")
                if actors:   parts.append(f"actor:{actors[0]}")
                detail = ' | '.join(parts) if parts else event.text[:60]
                log.info(f"[LIVE LEAK {conf}%] {name} | {detail}")
        except Exception as e:
            import traceback
            log.warning(f"Handler error: {e}\n{traceback.format_exc()}")

    log.info("Listening for live messages...")
    await client.run_until_disconnected()


if __name__ == '__main__':
    asyncio.run(main())
