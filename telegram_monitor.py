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
import hashlib
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

BASE_DIR   = Path(__file__).parent
DB_PATH    = BASE_DIR / "crawler.db"
SEEDS_FILE = BASE_DIR / "cti_seeds.json"
SESSION    = str(BASE_DIR / "tg_monitor_session")
ARTIFACT_DIR = Path(os.getenv("TG_ARTIFACT_DIR", str(BASE_DIR / "telegram_artifacts")))

# ── Rate limit settings ────────────────────────────────────────────────────────
JOIN_DELAY       = 15    # seconds between each join attempt
JOIN_BATCH_PAUSE = 300   # 5 min pause every N joins
JOIN_BATCH_SIZE  = 10    # joins per batch
FLOOD_BUFFER     = 30    # extra seconds added to any flood wait
HISTORY_LIMIT    = 50    # messages to fetch per channel on startup
HISTORY_DELAY    = 2     # seconds between channels during history
MAX_ARTIFACT_MB  = int(os.getenv("TG_MAX_ARTIFACT_MB", "100"))  # skip files bigger than this

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
    """
    Score a message for leak/threat content.
    Returns (is_leak, score, ext_dict) where ext_dict contains all extracted
    intel including stealer family detection if stealer_detection.py is available.
    """
    if not text or len(text) < 20:
        return False, 0, {}

    tl    = text.lower()
    score = 0
    ext   = {}

    # Hard noise filter — bail early on pure vendor spam
    if sum(1 for k in NOISE_SIGNALS if k in tl) >= 2:
        return False, 0, {}

    # ── Base leak signals ──────────────────────────────────────────────────────
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

    # ── Stealer family detection ───────────────────────────────────────────────
    if HAS_STEALER_DETECTION:
        stealer = detect_stealers(text)
        if stealer['families'] or stealer['log_count'] or stealer['target_domains']:
            boost = min(stealer['confidence_boost'], 35)
            score += boost
            ext['stealer_intel'] = stealer
            log.debug(f"  Stealer: {stealer['families']} +{boost}pts "
                      f"geo:{stealer['geo_tags']} targets:{stealer['target_domains'][:3]}")

    # ── Deep message intel (creds, C2, tools, actor handles) ──────────────────
    if HAS_MESSAGE_INTEL:
        intel = extract_message_intel(text)
        if intel:
            ext['message_intel'] = intel
            if intel.get('cred_samples'):
                score += 15
            if intel.get('c2_ips') or intel.get('c2_domains'):
                score += 20
            if intel.get('tool_files') or intel.get('github_links'):
                score += 10
            if intel.get('cred_count', 0) >= 10:
                score += 10

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
        stealer_intel TEXT DEFAULT NULL,
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
    CREATE TABLE IF NOT EXISTS telegram_artifacts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id      TEXT,
        channel_name    TEXT,
        message_id      INTEGER,
        filename        TEXT,
        mime_type       TEXT,
        size_bytes      INTEGER,
        sha256          TEXT,
        local_path      TEXT,
        downloaded_at   INTEGER,
        download_status TEXT DEFAULT 'downloaded',
        error           TEXT,
        UNIQUE(channel_id, message_id, filename)
    );
    CREATE INDEX IF NOT EXISTS idx_tg_has_leak ON telegram_messages(has_leak);
    CREATE INDEX IF NOT EXISTS idx_tg_channel  ON telegram_messages(channel_id);
    CREATE INDEX IF NOT EXISTS idx_tg_artifacts_msg ON telegram_artifacts(channel_id, message_id);
    CREATE INDEX IF NOT EXISTS idx_tg_artifacts_sha ON telegram_artifacts(sha256);
    ''')

    # ── Migrations for existing databases ─────────────────────────────────────
    cols = [r[1] for r in con.execute(
        "PRAGMA table_info(telegram_messages)").fetchall()]
    if 'stealer_intel' not in cols:
        con.execute(
            "ALTER TABLE telegram_messages ADD COLUMN stealer_intel TEXT DEFAULT NULL")
        log.info("Migrated: added stealer_intel column to telegram_messages")

    chan_cols = [r[1] for r in con.execute(
        "PRAGMA table_info(telegram_channels)").fetchall()]
    if 'channel_id' not in chan_cols:
        con.execute("ALTER TABLE telegram_channels ADD COLUMN channel_id TEXT")
        log.info("Migrated: added channel_id column")
    if 'access_hash' not in chan_cols:
        con.execute("ALTER TABLE telegram_channels ADD COLUMN access_hash TEXT")
        log.info("Migrated: added access_hash column")

    con.commit()
    con.close()

def save_message(channel_id, channel_name, msg_id, text, timestamp, is_leak, confidence, extracted):
    """
    Save a Telegram message to the DB.
    extracted dict may contain stealer_intel, cves, sample_emails, etc.
    """
    # Serialize stealer intel — only store if something detected
    stealer_json = None
    si = extracted.get('stealer_intel')
    if si and (si.get('families') or si.get('log_count') or si.get('target_domains')):
        stealer_json = json.dumps(si)

    # Merge message_intel into the same column (unified intel blob)
    mi = extracted.get('message_intel')
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
             text[:2000], timestamp, 1 if is_leak else 0,
             confidence, stealer_json))

        if is_leak and confidence >= 45:
            url = f"https://t.me/{channel_name}/{msg_id}"

            # Build descriptive title with all detected intel types
            parts = []
            if si and si.get('families'):
                parts.append('/'.join(si['families'][:2]))
            if mi and mi.get('tool_categories'):
                parts.append('+'.join(mi['tool_categories'][:2]))
            if mi and mi.get('c2_ips'):
                parts.append('C2')
            if mi and mi.get('attributed_to'):
                parts.append(f"actor:{mi['attributed_to'][0]}")
            prefix = f"[{', '.join(parts)}]" if parts else "[Telegram]"
            title  = f"{prefix} {channel_name}: {text[:60]}..."

            con.execute('''INSERT OR IGNORE INTO leaks
                (url,title,confidence,full_text,cves,breach_targets,
                 record_counts,has_emails,has_hashes,has_ssn,has_magnet,timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                (url, title, confidence, text[:2000],
                 json.dumps(extracted.get('cves', [])),
                 json.dumps(extracted.get('breach_targets', [])),
                 json.dumps(extracted.get('record_counts', [])),
                 1 if extracted.get('sample_emails') or (mi and mi.get('cred_samples')) else 0,
                 1 if extracted.get('hash_count')    else 0,
                 1 if extracted.get('has_ssn')       else 0,
                 1 if extracted.get('has_magnet')    else 0,
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
    con = db()
    rows = con.execute(
        "SELECT url, name, channel_id, access_hash FROM telegram_channels "
        "WHERE active=1 AND joined=0 ORDER BY id"
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]

def get_joined_channels():
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

# ── Telegram artifact filtering ────────────────────────────────────────────────
ALLOWED_TG_ARTIFACT_EXTS = {
    ".txt", ".csv", ".json", ".sql", ".log",
    ".conf", ".xml", ".yaml", ".yml",
    ".zip", ".7z", ".rar", ".tar", ".gz",
    ".py", ".php", ".js", ".ps1", ".sh", ".bat",
    ".exe", ".dll", ".apk"
}

SKIP_TG_MIME_PREFIXES = (
    "image/",
    "video/",
    "audio/",
)

SKIP_TG_MIME_TYPES = {
    "application/x-tgsticker",
    "application/x-bad-tgsticker",
}

def should_download_telegram_artifact(filename, mime_type="", size_bytes=0):
    filename = str(filename or "").strip()
    mime_type = str(mime_type or "").lower().strip()

    if not filename:
        return False

    low = filename.lower()
    ext = Path(low).suffix

    # Skip generic Telegram mystery blobs like telegram_386239.bin.
    if re.match(r"^telegram_\d+\.bin$", low):
        return False

    # Skip all .bin files. These are usually unnamed Telegram media/blob noise.
    if ext == ".bin":
        return False

    # Skip visible media/stickers that Telegram exposes as files.
    if any(mime_type.startswith(prefix) for prefix in SKIP_TG_MIME_PREFIXES):
        return False

    if mime_type in SKIP_TG_MIME_TYPES:
        return False

    # Only keep useful intel/archive/script file types.
    return ext in ALLOWED_TG_ARTIFACT_EXTS

def safe_filename(name):
    name = name or "telegram_file.bin"
    name = Path(str(name)).name
    name = re.sub(r'[^A-Za-z0-9._ -]+', '_', name).strip()
    return name or "telegram_file.bin"

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def artifact_already_saved(channel_id, message_id, filename):
    con = db()
    row = con.execute("""SELECT local_path FROM telegram_artifacts
        WHERE channel_id=? AND message_id=? AND filename=?""",
        (str(channel_id), int(message_id), filename)).fetchone()
    con.close()
    if not row:
        return False
    local_path = row['local_path']
    return bool(local_path and Path(local_path).exists())

def save_artifact_record(channel_id, channel_name, message_id, filename,
                         mime_type, size_bytes, sha256, local_path,
                         status='downloaded', error=None):
    con = db()
    try:
        con.execute("""INSERT OR REPLACE INTO telegram_artifacts
            (channel_id, channel_name, message_id, filename, mime_type,
             size_bytes, sha256, local_path, downloaded_at, download_status, error)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (str(channel_id), channel_name, int(message_id), filename, mime_type,
             size_bytes, sha256, str(local_path) if local_path else None,
             int(time.time()), status, error))
        con.commit()
    except Exception as e:
        log.debug(f"Artifact DB save error: {e}")
    finally:
        con.close()

async def download_telegram_artifact(client, msg, channel_id, channel_name):
    """
    Download Telegram document/file attachments and save metadata.
    Returns artifact metadata dict or None.
    """
    if not getattr(msg, 'file', None):
        return None

    filename = safe_filename(getattr(msg.file, 'name', None) or f"telegram_{msg.id}.bin")
    mime_type = getattr(msg.file, 'mime_type', None)
    size_bytes = getattr(msg.file, 'size', None) or 0
    # Skip useless Telegram media, stickers, thumbnails, and mystery blobs.
    if not should_download_telegram_artifact(filename, mime_type, size_bytes):
        log.info(
            f"[ARTIFACT SKIPPED] {channel_name}/{msg.id} "
            f"{filename} mime={mime_type} size={size_bytes}"
        )
        return None


    if size_bytes and size_bytes > MAX_ARTIFACT_MB * 1024 * 1024:
        save_artifact_record(channel_id, channel_name, msg.id, filename,
                             mime_type, size_bytes, None, None,
                             status='skipped_too_large',
                             error=f"File exceeds TG_MAX_ARTIFACT_MB={MAX_ARTIFACT_MB}")
        log.info(f"[ARTIFACT SKIPPED] {channel_name}/{msg.id} {filename} ({size_bytes} bytes)")
        return None

    if artifact_already_saved(channel_id, msg.id, filename):
        return None

    channel_dir = ARTIFACT_DIR / safe_filename(str(channel_name)) / str(msg.id)
    channel_dir.mkdir(parents=True, exist_ok=True)
    dest = channel_dir / filename

    if dest.exists():
        stem, suffix = dest.stem, dest.suffix
        n = 2
        while True:
            candidate = channel_dir / f"{stem}_{n}{suffix}"
            if not candidate.exists():
                dest = candidate
                filename = dest.name
                break
            n += 1

    try:
        downloaded = await client.download_media(msg, file=str(dest))
        final_path = Path(downloaded) if downloaded else dest
        digest = sha256_file(final_path) if final_path.exists() else None
        final_size = final_path.stat().st_size if final_path.exists() else size_bytes

        save_artifact_record(channel_id, channel_name, msg.id, filename,
                             mime_type, final_size, digest, final_path)
        log.info(f"[ARTIFACT DOWNLOADED] {channel_name}/{msg.id} {filename} sha256={digest}")
        return {
            'filename': filename,
            'mime_type': mime_type,
            'size_bytes': final_size,
            'sha256': digest,
            'local_path': str(final_path),
        }
    except FloodWaitError as e:
        log.warning(f"Flood wait {e.seconds}s during artifact download — sleeping")
        await asyncio.sleep(e.seconds + FLOOD_BUFFER)
        return None
    except Exception as e:
        save_artifact_record(channel_id, channel_name, msg.id, filename,
                             mime_type, size_bytes, None, dest,
                             status='error', error=str(e))
        log.warning(f"Artifact download failed {channel_name}/{msg.id} {filename}: {e}")
        return None

async def process_telegram_message(client, msg, channel_id, channel_name, source='history'):
    text = getattr(msg, 'text', None) or getattr(msg, 'message', None) or ''
    artifact = await download_telegram_artifact(client, msg, channel_id, channel_name)

    if not text and artifact:
        text = f"[Telegram attachment] {artifact['filename']}"

    if not text:
        return False, 0, {}

    is_leak, conf, extracted = analyze_message(text)
    if artifact:
        extracted['telegram_artifact'] = artifact
        fn = artifact['filename'].lower()
        if any(x in fn for x in ('cve-', 'exploit', 'poc', 'shell', 'webshell')):
            is_leak = True
            conf = max(conf, 45)

    if getattr(msg, 'date', None):
        ts = int(msg.date.replace(tzinfo=timezone.utc).timestamp())
    else:
        ts = int(time.time())

    save_message(channel_id, channel_name, msg.id, text, ts, is_leak, conf, extracted)
    discover_new_channels(extracted, channel_name)

    con = db()
    con.execute("""UPDATE telegram_channels SET
        message_count=message_count+1, last_message=?
        WHERE channel_id=?""", (ts, str(channel_id)))
    con.commit()
    con.close()

    return is_leak, conf, extracted

# ── Safe entity loading ────────────────────────────────────────────────────────
async def safe_get_entity(client, ch, delay=True):
    """
    Load a Telegram entity with flood protection.

    Priority order (least API calls first):
    1. InputPeerChannel(id, access_hash) — zero API calls, instant
    2. PeerChannel(id) — minimal API call
    3a. Invite hash URLs (t.me/+HASH or t.me/joinchat/HASH) — ImportChatInviteRequest
    3b. Public username URL — get_entity()

    Returns entity or None.
    """
    from telethon.tl.types import InputPeerChannel
    from telethon.tl.functions.messages import ImportChatInviteRequest

    cid   = ch.get('channel_id')
    ahash = ch.get('access_hash')
    url   = ch.get('url', '')

    # Option 1: Both ID and access_hash stored — zero API call needed
    if cid and ahash and str(cid).lstrip('-').isdigit() and str(ahash).lstrip('-').isdigit():
        try:
            entity = await client.get_entity(
                InputPeerChannel(abs(int(cid)), int(ahash)))
            return entity
        except Exception:
            pass

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
            pass

    if not url:
        return None

    if delay:
        await asyncio.sleep(JOIN_DELAY)

    # Option 3a: Invite hash URLs
    invite_match = re.search(r't\.me/(?:joinchat/|\+)([A-Za-z0-9_\-]+)', url)
    if invite_match:
        invite_hash = invite_match.group(1)
        try:
            updates = await client(ImportChatInviteRequest(invite_hash))
            if updates.chats:
                entity = updates.chats[0]
                log.info(f"Joined via invite link: {getattr(entity, 'title', url)}")
                return entity
            return None
        except UserAlreadyParticipantError:
            try:
                entity = await client.get_entity(url)
                return entity
            except Exception:
                return None
        except FloodWaitError as e:
            log.warning(f"Flood wait {e.seconds}s on invite join {url}")
            await asyncio.sleep(e.seconds + FLOOD_BUFFER)
            return None
        except InviteHashExpiredError:
            log.info(f"Invite link expired/invalid: {url}")
            mark_inactive(url)
            return None
        except Exception as e:
            log.warning(f"Invite join failed {url}: {e}")
            mark_inactive(url)
            return None

    # Option 3b: Public username URL
    try:
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
        try:
            entity = await client.get_entity(url)
            return entity
        except Exception:
            return None
    except Exception as e:
        log.warning(f"Join error {url}: {e}")
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

    if HAS_STEALER_DETECTION:
        log.info("Stealer family detection: ENABLED")
    else:
        log.info("Stealer family detection: DISABLED (missing stealer_detection.py)")

    # Seed channels from cti_seeds.json
    try:
        seeds = json.loads(SEEDS_FILE.read_text())
        for url in seeds.get('telegram_infostealer', []):
            save_channel(url, url.split('/')[-1], 'infostealer')
        for url in seeds.get('telegram_threat_actors', []):
            save_channel(url, url.split('/')[-1], 'threat_actor')
        log.info("Seeds loaded from cti_seeds.json")
    except Exception as e:
        log.warning(f"Could not load cti_seeds.json: {e}")

    client = TelegramClient(SESSION, int(api_id), api_hash)
    await client.start()
    log.info("Telegram client connected")

    # ── Live handler — registered FIRST so no messages are missed during
    #    history/join phases which can take hours with 200+ pending channels ──────
    @client.on(events.NewMessage)
    async def handler(event):
        try:
            chat = await event.get_chat()
            name = getattr(chat, 'title', str(chat.id))
            is_leak, conf, extracted = await process_telegram_message(
                client, event.message, chat.id, name, source='live')

            if is_leak:
                si    = extracted.get('stealer_intel', {})
                mi    = extracted.get('message_intel', {})
                art   = extracted.get('telegram_artifact', {})
                parts = []
                if si.get('families'):      parts.append(f"families:{','.join(si['families'])}")
                if mi.get('c2_ips'):        parts.append(f"C2:{mi['c2_ips'][0]}")
                if mi.get('c2_domains'):    parts.append(f"C2:{mi['c2_domains'][0]}")
                if mi.get('tool_files'):    parts.append(f"tool:{mi['tool_files'][0]}")
                if mi.get('github_links'):  parts.append(f"gh:{mi['github_links'][0]}")
                if mi.get('attributed_to'): parts.append(f"actor:{mi['attributed_to'][0]}")
                if mi.get('cred_count'):    parts.append(f"creds:{mi['cred_count']}")
                if art.get('filename'):     parts.append(f"file:{art['filename']}")
                detail = ' | '.join(parts) if parts else (event.text or '')[:60]
                log.info(f"[LIVE LEAK {conf}%] {name} | {detail}")
        except Exception as e:
            import traceback
            log.warning(f"Handler error: {e}\n{traceback.format_exc()}")

    log.info("Live handler registered — capturing messages through all startup phases")

    # ── Step 1: Load joined channels via get_dialogs() ─────────────────────────
    log.info("Loading joined channels via get_dialogs() (one API call)...")
    monitoring  = []
    dialog_map  = {}
    stealer_hits = 0

    try:
        async for dialog in client.iter_dialogs():
            entity = dialog.entity
            if not hasattr(entity, 'id'): continue
            cid   = entity.id
            ahash = getattr(entity, 'access_hash', None)
            title = getattr(entity, 'title', str(cid))
            dialog_map[cid] = entity
            monitoring.append(entity)
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

    # ── Step 2: Process recent history ────────────────────────────────────────
    if monitoring:
        log.info(f"Processing last {HISTORY_LIMIT} messages from "
                 f"{len(monitoring)} channels...")
        import gc
        total_msgs  = 0
        total_leaks = 0

        for i, entity in enumerate(monitoring):
            name = getattr(entity, 'title', str(entity.id))
            try:
                async for msg in client.iter_messages(entity, limit=HISTORY_LIMIT):
                    is_leak, conf, extracted = await process_telegram_message(
                        client, msg, entity.id, name, source='history')
                    if not (getattr(msg, 'text', None) or getattr(msg, 'message', None) or extracted.get('telegram_artifact')):
                        continue
                    total_msgs += 1
                    if is_leak:
                        total_leaks += 1
                        si = extracted.get('stealer_intel', {})
                        art = extracted.get('telegram_artifact', {})
                        families = si.get('families', [])
                        if families:
                            stealer_hits += 1
                            log.info(f"[LEAK {conf}% | {', '.join(families)}] "
                                     f"{name}: {(getattr(msg, 'text', None) or art.get('filename',''))[:70]}")
                        elif art.get('filename'):
                            log.info(f"[LEAK {conf}% | FILE] {name}: {art['filename']}")
                        else:
                            log.info(f"[LEAK {conf}%] {name}: {(getattr(msg, 'text', None) or '')[:80]}")

                con = db()
                con.execute(
                    "UPDATE telegram_channels SET last_message=? WHERE channel_id=?",
                    (int(time.time()), str(entity.id)))
                con.commit()
                con.close()

                if (i + 1) % 20 == 0:
                    log.info(f"History: {i+1}/{len(monitoring)} channels, "
                             f"{total_msgs} msgs, {total_leaks} leaks, "
                             f"{stealer_hits} stealer hits")
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
        log.info(f"History done: {total_msgs} msgs, {total_leaks} leaks, "
                 f"{stealer_hits} stealer family detections")

    # ── Step 3: Join pending channels slowly ──────────────────────────────────
    pending = get_pending_channels()
    log.info(f"{len(pending)} channels pending to join")
    log.info(f"Join rate: {JOIN_DELAY}s per channel, "
             f"{JOIN_BATCH_PAUSE}s pause every {JOIN_BATCH_SIZE}")

    joined_count = 0
    for i, ch in enumerate(pending):
        entity = await safe_get_entity(client, ch, delay=True)
        if entity:
            ahash = getattr(entity, 'access_hash', None)
            mark_joined(ch['url'], entity.id, ahash)
            joined_count += 1
            log.info(f"[{i+1}/{len(pending)}] Joined: "
                     f"{getattr(entity,'title',ch['url'])}")

        if (i + 1) % JOIN_BATCH_SIZE == 0:
            log.info(f"Joined {joined_count} so far — pausing {JOIN_BATCH_PAUSE}s...")
            await asyncio.sleep(JOIN_BATCH_PAUSE)

    log.info(f"Joining complete: {joined_count} new channels joined")

    # ── All startup phases complete — handler already active since startup ─────
    log.info("Startup complete — live monitoring active")
    await client.run_until_disconnected()


if __name__ == '__main__':
    log.info("Dark Crawler — Telegram Monitor")
    log.info("--------------------------------")
    log.info(f"DB:    {DB_PATH}")
    log.info(f"Seeds: {SEEDS_FILE}")
    log.info(f"Join delay: {JOIN_DELAY}s per channel")
    log.info(f"Batch pause: {JOIN_BATCH_PAUSE}s every {JOIN_BATCH_SIZE} joins")
    asyncio.run(run_monitor())
