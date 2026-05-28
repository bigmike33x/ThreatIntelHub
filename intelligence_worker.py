"""
intelligence_worker.py — Dark Crawler Intelligence Enrichment Worker v2
────────────────────────────────────────────────────────────────────────
Fixes in v2:
  1. Word-boundary regex matching — no more substring false positives
  2. Confidence scoring — actor/TTP/threat tags scored 1-100
  3. SHA-256 message deduplication — reposts/mirrors skipped
  4. Separated IOC types — IPs, domains, URLs, onions stored distinctly
  5. spaCy EntityRuler — custom CTI patterns bolted onto en_core_web_sm
  6. Structured tables only — ai_intel JSON column removed, summary only

Enrichment pipeline per message:
  Pass 1 — IOC extraction    (iocextract + fallback regex)
  Pass 2 — NER + EntityRuler (spaCy with custom CTI patterns)
  Pass 3 — Actor matching    (word-boundary, multi-hit confidence)
  Pass 4 — TTP matching      (word-boundary, scored)
  Pass 5 — Threat type       (scored classification)
  Pass 6 — Dedup check       (SHA-256 hash, skip repost)

Install:
    pip install iocextract spacy
    python -m spacy download en_core_web_sm

Run:
    python intelligence_worker.py
    nohup python intelligence_worker.py >> intel.log 2>&1 &
"""

import sqlite3
import time
import json
import logging
import re
import hashlib
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [INTEL] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('intel_worker')

BASE_DIR = Path(__file__).parent
DB_PATH  = BASE_DIR / 'crawler.db'

# ── Config ─────────────────────────────────────────────────────────────────────
BATCH_SIZE       = 20     # messages per cycle
SLEEP_IDLE       = 8      # seconds when queue empty
MIN_TEXT_LEN     = 20     # skip very short messages
ACTOR_CONF_BASE  = 40     # base confidence for single actor keyword hit
ACTOR_CONF_BONUS = 15     # bonus per additional corroborating keyword
TTP_CONF_BASE    = 35     # base confidence for single TTP keyword hit
TTP_CONF_BONUS   = 10     # bonus per additional keyword in same TTP

# ── Lazy-loaded deps ───────────────────────────────────────────────────────────
_iocextract = None
_nlp        = None

def get_iocextract():
    global _iocextract
    if _iocextract is None:
        try:
            import iocextract as _ie
            _iocextract = _ie
            log.info("iocextract loaded OK")
        except ImportError:
            log.warning("iocextract missing — pip install iocextract (using fallback regex)")
            _iocextract = False
    return _iocextract if _iocextract else None

def get_nlp():
    global _nlp
    if _nlp is None:
        try:
            import spacy
            from spacy.language import Language
            nlp = spacy.load('en_core_web_sm', disable=['parser'])
            _add_cti_ruler(nlp)
            _nlp = nlp
            log.info("spaCy + CTI EntityRuler loaded OK")
        except OSError:
            log.warning("spaCy model missing — python -m spacy download en_core_web_sm")
            _nlp = False
        except ImportError:
            log.warning("spaCy missing — pip install spacy")
            _nlp = False
    return _nlp if _nlp else None

# ── spaCy Custom EntityRuler — CTI patterns ────────────────────────────────────
# These patterns run BEFORE the statistical model, so they always win.
# Label convention:  MALWARE / THREAT_ACTOR / EXPLOIT / RANSOM_GROUP
CTI_PATTERNS = [
    # Ransomware groups
    {"label": "RANSOM_GROUP", "pattern": "LockBit"},
    {"label": "RANSOM_GROUP", "pattern": "ALPHV"},
    {"label": "RANSOM_GROUP", "pattern": "BlackCat"},
    {"label": "RANSOM_GROUP", "pattern": "Black Basta"},
    {"label": "RANSOM_GROUP", "pattern": "Cl0p"},
    {"label": "RANSOM_GROUP", "pattern": "Clop"},
    {"label": "RANSOM_GROUP", "pattern": "RansomHub"},
    {"label": "RANSOM_GROUP", "pattern": "Rhysida"},
    {"label": "RANSOM_GROUP", "pattern": "Qilin"},
    {"label": "RANSOM_GROUP", "pattern": "Akira"},
    {"label": "RANSOM_GROUP", "pattern": "8Base"},
    {"label": "RANSOM_GROUP", "pattern": "BianLian"},
    {"label": "RANSOM_GROUP", "pattern": "Medusa Locker"},
    {"label": "RANSOM_GROUP", "pattern": "Play ransomware"},
    {"label": "RANSOM_GROUP", "pattern": "Royal ransomware"},
    {"label": "RANSOM_GROUP", "pattern": "Hunters International"},
    {"label": "RANSOM_GROUP", "pattern": "NoEscape"},
    {"label": "RANSOM_GROUP", "pattern": "DarkVault"},
    {"label": "RANSOM_GROUP", "pattern": "Mogilevich"},
    # Stealer malware
    {"label": "MALWARE", "pattern": "RedLine Stealer"},
    {"label": "MALWARE", "pattern": "RedLine"},
    {"label": "MALWARE", "pattern": "Raccoon Stealer"},
    {"label": "MALWARE", "pattern": "Vidar Stealer"},
    {"label": "MALWARE", "pattern": "Lumma Stealer"},
    {"label": "MALWARE", "pattern": "LummaC2"},
    {"label": "MALWARE", "pattern": "StealC"},
    {"label": "MALWARE", "pattern": "Rhadamanthys"},
    {"label": "MALWARE", "pattern": "Meduza Stealer"},
    {"label": "MALWARE", "pattern": "WhiteSnake"},
    {"label": "MALWARE", "pattern": "Aurora Stealer"},
    {"label": "MALWARE", "pattern": "Atomic Stealer"},
    {"label": "MALWARE", "pattern": "AMOS"},
    {"label": "MALWARE", "pattern": "AsyncRAT"},
    {"label": "MALWARE", "pattern": "NjRAT"},
    {"label": "MALWARE", "pattern": "QuasarRAT"},
    {"label": "MALWARE", "pattern": "Cobalt Strike"},
    {"label": "MALWARE", "pattern": "Sliver"},
    {"label": "MALWARE", "pattern": "Brute Ratel"},
    # Threat actors / APT
    {"label": "THREAT_ACTOR", "pattern": "Lazarus Group"},
    {"label": "THREAT_ACTOR", "pattern": "APT28"},
    {"label": "THREAT_ACTOR", "pattern": "Fancy Bear"},
    {"label": "THREAT_ACTOR", "pattern": "APT29"},
    {"label": "THREAT_ACTOR", "pattern": "Cozy Bear"},
    {"label": "THREAT_ACTOR", "pattern": "APT41"},
    {"label": "THREAT_ACTOR", "pattern": "Sandworm"},
    {"label": "THREAT_ACTOR", "pattern": "Volt Typhoon"},
    {"label": "THREAT_ACTOR", "pattern": "Salt Typhoon"},
    {"label": "THREAT_ACTOR", "pattern": "Scattered Spider"},
    {"label": "THREAT_ACTOR", "pattern": "UNC3944"},
    {"label": "THREAT_ACTOR", "pattern": "Lapsus$"},
    {"label": "THREAT_ACTOR", "pattern": "LAPSUS$"},
    {"label": "THREAT_ACTOR", "pattern": "KillNet"},
    {"label": "THREAT_ACTOR", "pattern": "Anonymous Sudan"},
    {"label": "THREAT_ACTOR", "pattern": "REvil"},
    {"label": "THREAT_ACTOR", "pattern": "Conti"},
    {"label": "THREAT_ACTOR", "pattern": "DarkSide"},
    # Exploit types / techniques
    {"label": "EXPLOIT", "pattern": [{"TEXT": {"REGEX": "CVE-\\d{4}-\\d{4,7}"}}]},
    {"label": "EXPLOIT", "pattern": "zero-day"},
    {"label": "EXPLOIT", "pattern": "zero day"},
    {"label": "EXPLOIT", "pattern": "0-day"},
    {"label": "EXPLOIT", "pattern": "proof of concept"},
    {"label": "EXPLOIT", "pattern": "PoC exploit"},
]

def _add_cti_ruler(nlp):
    """Add CTI EntityRuler before NER so custom labels always win."""
    try:
        from spacy.pipeline import EntityRuler
        # Add before ner so it takes priority
        if "entity_ruler" not in nlp.pipe_names:
            ruler = nlp.add_pipe("entity_ruler", before="ner")
            ruler.add_patterns(CTI_PATTERNS)
            log.info(f"CTI EntityRuler: {len(CTI_PATTERNS)} patterns added")
    except Exception as e:
        log.warning(f"EntityRuler setup failed: {e}")


# ── Actor Map — word-boundary aware ───────────────────────────────────────────
# Structure: keyword → (canonical_name, is_specific)
# is_specific=True  → high-value match (full name, unique alias)
# is_specific=False → requires corroboration (short/ambiguous term)
ACTOR_MAP = {
    # ── Ransomware ──────────────────────────────────────────────────────────
    'lockbit':              ('LockBit',                 True),
    'lock bit':             ('LockBit',                 True),
    'alphv':                ('ALPHV/BlackCat',           True),
    'blackcat':             ('ALPHV/BlackCat',           True),
    'black cat ransomware': ('ALPHV/BlackCat',           True),
    'cl0p':                 ('Cl0p',                    True),
    'clop ransomware':      ('Cl0p',                    True),
    'black basta':          ('Black Basta',              True),
    'blackbasta':           ('Black Basta',              True),
    'royal ransomware':     ('Royal',                   True),
    'play ransomware':      ('Play',                    True),   # "play" alone too generic
    'noescaperansom':       ('NoEscape',                True),
    'noescape':             ('NoEscape',                True),
    'rhysida':              ('Rhysida',                 True),
    'akira ransomware':     ('Akira',                   True),
    'medusa locker':        ('Medusa Locker',            True),  # NOT bare "medusa"
    'medusalocker':         ('Medusa Locker',            True),
    'bianlian':             ('BianLian',                True),
    'bian lian':            ('BianLian',                True),
    'ransomhub':            ('RansomHub',               True),
    'ransom hub':           ('RansomHub',               True),
    '8base':                ('8Base',                   True),
    'hunters international':('Hunters International',   True),
    'qilin ransomware':     ('Qilin',                   True),
    'qilin group':          ('Qilin',                   True),
    'darkvault':            ('DarkVault',               True),
    'mogilevich':           ('Mogilevich',              True),
    # ── Nation-state / APT ──────────────────────────────────────────────────
    'lazarus group':        ('Lazarus Group (NK)',       True),
    'lazarus':              ('Lazarus Group (NK)',       False),  # needs corroboration
    'apt28':                ('APT28/Fancy Bear (RU)',    True),
    'fancy bear':           ('APT28/Fancy Bear (RU)',    True),
    'apt29':                ('APT29/Cozy Bear (RU)',     True),
    'cozy bear':            ('APT29/Cozy Bear (RU)',     True),
    'apt41':                ('APT41 (CN)',               True),
    'sandworm':             ('Sandworm (RU)',            True),
    'volt typhoon':         ('Volt Typhoon (CN)',        True),
    'salt typhoon':         ('Salt Typhoon (CN)',        True),
    'scattered spider':     ('Scattered Spider',        True),
    'unc3944':              ('Scattered Spider',        True),
    'lapsus$':              ('Lapsus$',                 True),
    'lapsus group':         ('Lapsus$',                 True),
    'killnet':              ('KillNet',                 True),
    'kill net':             ('KillNet',                 True),
    'anonymous sudan':      ('Anonymous Sudan',         True),
    'revil':                ('REvil',                   True),
    'sodinokibi':           ('REvil',                   True),
    'darkside ransomware':  ('DarkSide',                True),
    'conti ransomware':     ('Conti',                   True),
    'conti group':          ('Conti',                   True),
    # ── Stealers ────────────────────────────────────────────────────────────
    'redline stealer':      ('RedLine Stealer',         True),
    'redline':              ('RedLine Stealer',         False),
    'raccoon stealer':      ('Raccoon Stealer',         True),
    'raccoon':              ('Raccoon Stealer',         False),
    'vidar stealer':        ('Vidar Stealer',           True),
    'vidar':                ('Vidar Stealer',           False),
    'aurora stealer':       ('Aurora Stealer',          True),
    'lumma stealer':        ('Lumma Stealer',           True),
    'lummac2':              ('Lumma Stealer',           True),
    'lumma':                ('Lumma Stealer',           False),
    'stealc':               ('StealC',                  True),
    'rhadamanthys':         ('Rhadamanthys',            True),
    'meduza stealer':       ('Meduza Stealer',          True),
    'whitesnake stealer':   ('WhiteSnake Stealer',      True),
    'atomic stealer':       ('Atomic Stealer (AMOS)',   True),
    # ── Forums / markets ────────────────────────────────────────────────────
    'breachforums':         ('BreachForums',            True),
    'breach forums':        ('BreachForums',            True),
    'exploit.in':           ('Exploit.in',              True),
    'xss.is':               ('XSS.is',                  True),
    'raidforums':           ('RaidForums',              True),
}

# Pre-compile word-boundary patterns for each keyword
_ACTOR_PATTERNS = {
    kw: re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
    for kw in ACTOR_MAP
}


# ── TTP Map — word-boundary aware, scored ─────────────────────────────────────
# Structure: category → [(keyword, weight)]
# weight 2 = strong indicator, weight 1 = supporting
TTP_MAP = {
    'initial_access': [
        ('spearphish',           2), ('credential harvest',    2),
        ('phishing kit',         2), ('brute force',           2),
        ('password spray',       2), ('vpn exploit',           2),
        ('initial access broker',2), ('access sale',           2),
        ('phish',                1), ('0day',                  1),
        ('zero-day',             1), ('rce exploit',           2),
    ],
    'ransomware': [
        ('encrypted files',      2), ('ransom note',           2),
        ('decryptor',            2), ('victim portal',         2),
        ('double extortion',     2), ('data leak site',        2),
        ('payment portal',       2), ('recovery key',          2),
        ('tor payment',          2), ('ransomware',            1),
    ],
    'data_exfiltration': [
        ('leaked database',      2), ('data breach',           2),
        ('credential dump',      2), ('combo list',            2),
        ('db dump',              2), ('sql dump',              2),
        ('stolen data',          2), ('exfil',                 2),
        ('dump',                 1), ('fullz',                 2),
    ],
    'malware_delivery': [
        ('malware loader',       2), ('dropper',               2),
        ('crypter',              2), ('fully undetected',      2),
        ('fud',                  2), ('stealer log',           2),
        ('infostealer',          2), ('remote access trojan',  2),
        ('command and control',  2), ('botnet',                2),
        ('loader',               1), ('rat',                   1),
        ('c2',                   1), ('keylogger',             1),
    ],
    'vulnerability_exploit': [
        ('proof of concept',     2), ('poc exploit',           2),
        ('sql injection',        2), ('remote code execution', 2),
        ('privilege escalation', 2), ('buffer overflow',       2),
        ('use after free',       2), ('zero-day exploit',      2),
        ('cve-',                 1), ('lfi',                   1),
        ('rfi',                  1), ('sqli',                  1),
        ('rce',                  1), ('xss',                   1),
    ],
    'credential_theft': [
        ('combo list',           2), ('email:pass',            2),
        ('user:pass',            2), ('login:pass',            2),
        ('password list',        2), ('hash dump',             2),
        ('pass the hash',        2), ('kerberoast',            2),
        ('ntlm hash',            2), ('/etc/shadow',           2),
        ('credential',           1), ('ntlm',                  1),
    ],
    'financial_fraud': [
        ('carding',              2), ('cc dump',               2),
        ('cvv dump',             2), ('bank logs',             2),
        ('cashout method',       2), ('money mule',            2),
        ('phishing kit',         2), ('scam page',             2),
        ('cvv',                  1), ('fullz',                 1),
        ('fraud',                1), ('paypal logs',           2),
    ],
    'infrastructure': [
        ('bulletproof host',     2), ('bulletproof vps',       2),
        ('residential proxy',    2), ('dedicated server',      2),
        ('rdp access',           2), ('ssh access',            2),
        ('webshell',             2), ('c2 panel',              2),
        ('socks5 proxy',         2), ('shell access',          2),
    ],
}

# Pre-compile TTP patterns
_TTP_PATTERNS = {
    cat: [(re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE), w)
          for kw, w in keywords]
    for cat, keywords in TTP_MAP.items()
}

# ── Threat type classifier ─────────────────────────────────────────────────────
THREAT_TYPES = {
    'ransomware_attack':  [('ransom note',2),('encrypted files',2),('decryptor',2),('victim portal',2),('ransomware',1)],
    'data_breach':        [('data breach',2),('leaked database',2),('credential dump',2),('million records',2),('dump',1)],
    'malware_sale':       [('stealer for sale',2),('rat for sale',2),('loader for sale',2),('stealer',1),('rat',1)],
    'exploit_sale':       [('0day for sale',2),('zero day exploit',2),('cve-',1),('exploit',1),('rce',1)],
    'credential_sale':    [('combo list',2),('email:pass',2),('user:pass',2),('credential',1),('logs',1)],
    'access_sale':        [('rdp access',2),('ssh access',2),('vpn access',2),('shell access',2),('access',1)],
    'fraud_service':      [('carding',2),('cvv dump',2),('cashout',2),('fullz',2),('fraud',1)],
    'threat_intel':       [('ioc',2),('threat actor',2),('ttp',2),('attribution',2),('apt',1)],
}

_THREAT_PATTERNS = {
    tt: [(re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE), w)
         for kw, w in kws]
    for tt, kws in THREAT_TYPES.items()
}


# ── IOC extraction ─────────────────────────────────────────────────────────────
# Strict regexes that minimise false positives
_IP_RE     = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_ONION_RE  = re.compile(r'\b[a-z2-7]{16,56}\.onion\b', re.I)
_DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|fr|to|cc|me)\b',
    re.I
)
_URL_RE    = re.compile(r'https?://[^\s\])\'"<>]{8,}', re.I)
_HASH_RE   = re.compile(r'\b([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b', re.I)
_CVE_RE    = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)
_BTC_RE    = re.compile(r'\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
_XMR_RE    = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
_EMAIL_RE  = re.compile(r'\b[\w.\-+]+@[\w.\-]+\.[a-z]{2,}\b', re.I)

# Private/reserved IPs to filter out of IOC results
_PRIVATE_IP_RE = re.compile(
    r'^(?:10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|255\.)'
)


def _ioc_quality(ioc_type, value):
    """
    Return a quality score 0-100 for a single IOC value.
    Higher = more likely to be a real, useful indicator.
    """
    if ioc_type == 'ip':
        if _PRIVATE_IP_RE.match(value):
            return 0   # private/reserved — not an IOC
        return 80

    if ioc_type == 'hash':
        if len(value) == 64: return 95   # SHA-256 — most specific
        if len(value) == 40: return 85   # SHA-1
        if len(value) == 32: return 70   # MD5 — collision risk
        return 50

    if ioc_type == 'cve':
        return 95   # CVEs are always high quality if regex matched

    if ioc_type == 'onion':
        return 90   # onion addresses are specific

    if ioc_type == 'url':
        return 75 if len(value) > 30 else 60

    if ioc_type == 'domain':
        # Short common words that aren't real domains
        if len(value) < 8: return 20
        return 65

    if ioc_type == 'btc':
        return 85

    if ioc_type == 'xmr':
        return 90   # Monero addresses are very specific, common in ransomware

    if ioc_type == 'email':
        return 70

    return 50


def extract_iocs_fallback(text):
    """Pure-regex fallback when iocextract not installed."""
    raw_ips = _IP_RE.findall(text)
    ips = [ip for ip in raw_ips if not _PRIVATE_IP_RE.match(ip)]
    return {
        'ip':     list(set(ips))[:20],
        'domain': list(set(_DOMAIN_RE.findall(text)))[:20],
        'url':    list(set(_URL_RE.findall(text)))[:20],
        'onion':  list(set(_ONION_RE.findall(text)))[:10],
        'hash':   list(set(_HASH_RE.findall(text)))[:20],
        'cve':    list(set(m.upper() for m in _CVE_RE.findall(text)))[:10],
        'btc':    list(set(_BTC_RE.findall(text)))[:5],
        'xmr':    list(set(_XMR_RE.findall(text)))[:5],
        'email':  list(set(_EMAIL_RE.findall(text)))[:10],
    }


def extract_iocs(text):
    """
    Extract IOCs with iocextract if available.
    Returns dict: ioc_type → [value, ...] — types kept SEPARATE.
    """
    ie = get_iocextract()
    if not ie:
        return extract_iocs_fallback(text)

    result = {k: [] for k in ['ip','domain','url','onion','hash','cve','btc','xmr','email']}

    try:
        for ip in ie.extract_ips(text, refang=True):
            ip = str(ip)
            if not _PRIVATE_IP_RE.match(ip):
                result['ip'].append(ip)

        for url in ie.extract_urls(text, refang=True):
            url = str(url)
            if '.onion' in url:
                result['onion'].append(url)
            elif url.startswith('http'):
                result['url'].append(url)
            else:
                result['domain'].append(url)

        # Standalone onion addresses not in URLs
        for onion in _ONION_RE.findall(text):
            if onion not in ' '.join(result['onion']):
                result['onion'].append(onion)

        for h in ie.extract_hashes(text):
            result['hash'].append(str(h))

        for cve in _CVE_RE.findall(text):
            result['cve'].append(cve.upper())

        for btc in ie.extract_bitcoin_addresses(text):
            result['btc'].append(str(btc))

        for xmr in _XMR_RE.findall(text):
            result['xmr'].append(xmr)

        for email in ie.extract_emails(text):
            result['email'].append(str(email))

        return {k: list(set(v))[:20] for k, v in result.items()}

    except Exception as e:
        log.debug(f"iocextract error ({e}), using fallback")
        return extract_iocs_fallback(text)


# ── NER ────────────────────────────────────────────────────────────────────────
def extract_entities(text):
    """
    Run spaCy NER + CTI EntityRuler.
    Returns dict: label → [entity text, ...]
    CTI labels: MALWARE, THREAT_ACTOR, RANSOM_GROUP, EXPLOIT
    Standard:   ORG, GPE, PRODUCT, PERSON
    """
    nlp = get_nlp()
    if not nlp:
        return {}
    try:
        doc = nlp(text[:1200])
        out = {}
        keep = {'MALWARE','THREAT_ACTOR','RANSOM_GROUP','EXPLOIT',
                'ORG','GPE','PRODUCT','PERSON','NORP'}
        for ent in doc.ents:
            if ent.label_ not in keep:
                continue
            val = ent.text.strip()
            if 2 < len(val) < 80:
                out.setdefault(ent.label_, [])
                if val not in out[ent.label_]:
                    out[ent.label_].append(val)
        return {k: v[:10] for k, v in out.items()}
    except Exception as e:
        log.debug(f"NER error: {e}")
        return {}


# ── Actor matching — word-boundary, confidence scored ─────────────────────────
def match_actors(text):
    """
    Returns list of (canonical_name, confidence) tuples.
    Confidence:
      - specific keyword alone     → ACTOR_CONF_BASE (40)
      - non-specific keyword alone → ACTOR_CONF_BASE - 15 (25), needs corroboration
      - each extra keyword for same actor → +ACTOR_CONF_BONUS (15), capped at 95
    """
    tl = text.lower()
    hits = {}   # canonical_name → {specific: bool, count: int}

    for kw, (canonical, is_specific) in ACTOR_MAP.items():
        if _ACTOR_PATTERNS[kw].search(tl):
            if canonical not in hits:
                hits[canonical] = {'specific': is_specific, 'count': 1}
            else:
                hits[canonical]['count'] += 1
                if is_specific:
                    hits[canonical]['specific'] = True

    results = []
    for canonical, info in hits.items():
        if not info['specific'] and info['count'] == 1:
            # Single ambiguous keyword — skip (would be a false positive)
            continue
        base = ACTOR_CONF_BASE if info['specific'] else (ACTOR_CONF_BASE - 15)
        conf = min(95, base + (info['count'] - 1) * ACTOR_CONF_BONUS)
        results.append((canonical, conf))

    return sorted(results, key=lambda x: -x[1])


# ── TTP matching — word-boundary, confidence scored ───────────────────────────
def match_ttps(text):
    """
    Returns list of (ttp_category, confidence) tuples.
    Confidence based on weighted keyword hits, capped at 95.
    """
    tl = text.lower()
    results = []

    for cat, patterns in _TTP_PATTERNS.items():
        weight_sum = 0
        hit_count  = 0
        for pattern, weight in patterns:
            if pattern.search(tl):
                weight_sum += weight
                hit_count  += 1

        if hit_count == 0:
            continue

        conf = min(95, TTP_CONF_BASE + weight_sum * TTP_CONF_BONUS)
        results.append((cat, conf))

    return sorted(results, key=lambda x: -x[1])


# ── Threat type classifier ─────────────────────────────────────────────────────
def classify_threat_type(text):
    """
    Returns (threat_type, confidence) or (None, 0).
    Uses same word-boundary pattern matching as TTP.
    """
    tl = text.lower()
    scores = {}

    for tt, patterns in _THREAT_PATTERNS.items():
        total = 0
        for pattern, weight in patterns:
            if pattern.search(tl):
                total += weight
        if total > 0:
            scores[tt] = total

    if not scores:
        return None, 0

    best = max(scores, key=scores.get)
    conf = min(95, 35 + scores[best] * 10)
    return best, conf


# ── Message deduplication ──────────────────────────────────────────────────────
def message_hash(text):
    """SHA-256 of normalised text — strips whitespace for repost detection."""
    normalised = ' '.join(text.lower().split())
    return hashlib.sha256(normalised.encode('utf-8')).hexdigest()


# ── Database ───────────────────────────────────────────────────────────────────
def db():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


def ensure_tables():
    con = db()

    # Tables only — NO indexes here. Indexes that reference new columns (quality,
    # confidence) would crash on old DBs where those columns don't exist yet.
    # Indexes are created AFTER column migrations below, once columns are guaranteed present.
    con.executescript('''
    CREATE TABLE IF NOT EXISTS iocs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        type        TEXT NOT NULL,
        value       TEXT NOT NULL,
        first_seen  INTEGER,
        last_seen   INTEGER,
        times_seen  INTEGER DEFAULT 1,
        UNIQUE(type, value)
    );
    CREATE TABLE IF NOT EXISTS ioc_links (
        ioc_id     INTEGER,
        msg_id     INTEGER,
        channel_id TEXT,
        timestamp  INTEGER,
        PRIMARY KEY (ioc_id, msg_id)
    );
    CREATE TABLE IF NOT EXISTS msg_tags (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        msg_id      INTEGER NOT NULL,
        tag_type    TEXT    NOT NULL,
        tag_value   TEXT    NOT NULL,
        UNIQUE(msg_id, tag_type, tag_value)
    );
    CREATE TABLE IF NOT EXISTS msg_hashes (
        hash         TEXT PRIMARY KEY,
        first_msg_id INTEGER,
        first_seen   INTEGER,
        dupe_count   INTEGER DEFAULT 0
    );
    ''')

    # ── Column migrations (safe to run every startup) ─────────────────────────
    # Each block checks PRAGMA first — ALTER TABLE only fires if column missing.

    ioc_cols = {r[1] for r in con.execute("PRAGMA table_info(iocs)").fetchall()}
    ioc_col_migrations = {
        'quality':     'INTEGER DEFAULT 50',
        'source_type': "TEXT DEFAULT 'telegram'",
    }
    v1_iocs_migrated = False
    for col, typedef in ioc_col_migrations.items():
        if col not in ioc_cols:
            con.execute(f"ALTER TABLE iocs ADD COLUMN {col} {typedef}")
            log.info(f"Migrated: iocs.{col} added")
            v1_iocs_migrated = True

    tag_cols = {r[1] for r in con.execute("PRAGMA table_info(msg_tags)").fetchall()}
    v1_tags_migrated = False
    if 'confidence' not in tag_cols:
        con.execute("ALTER TABLE msg_tags ADD COLUMN confidence INTEGER DEFAULT 50")
        log.info("Migrated: msg_tags.confidence added")
        v1_tags_migrated = True

    tg_cols = {r[1] for r in con.execute("PRAGMA table_info(telegram_messages)").fetchall()}
    tg_col_migrations = {
        'intel_processed': 'INTEGER DEFAULT 0',
        'is_duplicate':    'INTEGER DEFAULT 0',
        'msg_hash':        'TEXT',
    }
    for col, typedef in tg_col_migrations.items():
        if col not in tg_cols:
            con.execute(f"ALTER TABLE telegram_messages ADD COLUMN {col} {typedef}")
            log.info(f"Migrated: telegram_messages.{col} added")

    con.commit()

    # ── Stale v1 data cleanup ──────────────────────────────────────────────────
    # If we just added quality/confidence columns, v1 rows in iocs/msg_tags are
    # incomplete (all quality=50 default, no real scores). Clear them and reset
    # intel_processed so the worker re-processes everything with the v2 pipeline.
    # This only fires once — next startup columns exist so the ALTER blocks above
    # don't run and v1_*_migrated stays False.

    if v1_iocs_migrated or v1_tags_migrated:
        ioc_count = con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        tag_count = con.execute("SELECT COUNT(*) FROM msg_tags").fetchone()[0]
        hash_count = con.execute("SELECT COUNT(*) FROM msg_hashes").fetchone()[0]

        log.info(f"v1 data detected — clearing stale intel for full v2 reprocess")
        log.info(f"  Dropping: {ioc_count:,} ioc rows, {tag_count:,} tag rows, "
                 f"{hash_count:,} hash rows")

        con.execute("DELETE FROM iocs")
        con.execute("DELETE FROM ioc_links")
        con.execute("DELETE FROM msg_tags")
        con.execute("DELETE FROM msg_hashes")

        # Reset intel_processed so every message gets re-enriched by v2
        reset = con.execute(
            "UPDATE telegram_messages SET intel_processed=0, is_duplicate=0, msg_hash=NULL"
        ).rowcount
        log.info(f"  Reset {reset:,} messages to intel_processed=0 — full reprocess queued")

        con.commit()
        log.info("v1 cleanup done — worker will now reprocess all messages with v2 pipeline")

    # ── Indexes — created AFTER migrations so columns are guaranteed present ───
    for stmt in [
        "CREATE INDEX IF NOT EXISTS idx_ioc_type       ON iocs(type)",
        "CREATE INDEX IF NOT EXISTS idx_ioc_quality    ON iocs(quality DESC)",
        "CREATE INDEX IF NOT EXISTS idx_ioc_seen       ON iocs(times_seen DESC)",
        "CREATE INDEX IF NOT EXISTS idx_ioclink_msg    ON ioc_links(msg_id)",
        "CREATE INDEX IF NOT EXISTS idx_ioclink_ioc    ON ioc_links(ioc_id)",
        "CREATE INDEX IF NOT EXISTS idx_tag_msg        ON msg_tags(msg_id)",
        "CREATE INDEX IF NOT EXISTS idx_tag_type_val   ON msg_tags(tag_type, tag_value)",
        "CREATE INDEX IF NOT EXISTS idx_tag_confidence ON msg_tags(confidence DESC)",
    ]:
        con.execute(stmt)
    con.commit()
    con.close()


def save_ioc(con, ioc_type, value, quality, msg_id, channel_id, timestamp):
    now = int(time.time())
    try:
        con.execute('''
            INSERT INTO iocs (type, value, quality, first_seen, last_seen, times_seen)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(type, value) DO UPDATE SET
                last_seen  = excluded.last_seen,
                times_seen = times_seen + 1,
                quality    = MAX(quality, excluded.quality)
        ''', (ioc_type, value, quality, timestamp or now, timestamp or now))

        row = con.execute(
            "SELECT id FROM iocs WHERE type=? AND value=?", (ioc_type, value)
        ).fetchone()
        if row:
            con.execute(
                "INSERT OR IGNORE INTO ioc_links (ioc_id,msg_id,channel_id,timestamp) VALUES(?,?,?,?)",
                (row['id'], msg_id, channel_id, timestamp or now)
            )
    except Exception as e:
        log.debug(f"save_ioc error: {e}")


def save_tag(con, msg_id, tag_type, tag_value, confidence=50):
    try:
        con.execute(
            '''INSERT INTO msg_tags (msg_id, tag_type, tag_value, confidence) VALUES (?,?,?,?)
               ON CONFLICT(msg_id, tag_type, tag_value) DO UPDATE SET
               confidence = MAX(confidence, excluded.confidence)''',
            (msg_id, tag_type, str(tag_value)[:200], confidence)
        )
    except Exception as e:
        log.debug(f"save_tag error: {e}")


# ── Core processing ────────────────────────────────────────────────────────────
def process_message(con, row):
    """Enrich one message. Returns tag summary string for logging."""
    msg_id     = row['id']
    text       = row['text'] or ''
    channel_id = row['channel_id'] or ''
    timestamp  = row['timestamp']

    if len(text) < MIN_TEXT_LEN:
        return "skipped:too_short"

    # ── Deduplication ──────────────────────────────────────────────────────────
    mhash = message_hash(text)
    existing = con.execute(
        "SELECT first_msg_id FROM msg_hashes WHERE hash=?", (mhash,)
    ).fetchone()

    if existing:
        # Mark as duplicate — still save the hash link but skip heavy processing
        con.execute(
            "UPDATE telegram_messages SET intel_processed=1, is_duplicate=1, msg_hash=? WHERE id=?",
            (mhash, msg_id)
        )
        con.execute(
            "UPDATE msg_hashes SET dupe_count=dupe_count+1 WHERE hash=?", (mhash,)
        )
        return "duplicate"

    # Register hash
    con.execute(
        "INSERT OR IGNORE INTO msg_hashes (hash, first_msg_id, first_seen) VALUES (?,?,?)",
        (mhash, msg_id, timestamp or int(time.time()))
    )

    summary_parts = []

    # ── Pass 1: IOC Extraction ─────────────────────────────────────────────────
    iocs = extract_iocs(text)
    ioc_count = 0
    for ioc_type, values in iocs.items():
        for value in values:
            if value and len(value) > 3:
                quality = _ioc_quality(ioc_type, value)
                if quality > 0:   # skip zero-quality (private IPs, etc.)
                    save_ioc(con, ioc_type, value, quality, msg_id, channel_id, timestamp)
                    ioc_count += 1

    if ioc_count:
        summary_parts.append(f"iocs:{ioc_count}")

    # ── Pass 2: NER + EntityRuler ──────────────────────────────────────────────
    entities = extract_entities(text)
    ner_count = 0
    for ent_type, values in entities.items():
        # CTI-specific labels get higher confidence
        conf = 85 if ent_type in ('MALWARE','THREAT_ACTOR','RANSOM_GROUP','EXPLOIT') else 55
        for val in values:
            save_tag(con, msg_id, f'ner_{ent_type.lower()}', val, conf)
            ner_count += 1

    if ner_count:
        summary_parts.append(f"ner:{ner_count}")

    # ── Pass 3: Actor matching ─────────────────────────────────────────────────
    actors = match_actors(text)
    for actor, conf in actors:
        save_tag(con, msg_id, 'actor', actor, conf)

    if actors:
        summary_parts.append(f"actors:{len(actors)}")

    # ── Pass 4: TTP matching ───────────────────────────────────────────────────
    ttps = match_ttps(text)
    for ttp, conf in ttps:
        save_tag(con, msg_id, 'ttp', ttp, conf)

    if ttps:
        summary_parts.append(f"ttps:{len(ttps)}")

    # ── Pass 5: Threat type ────────────────────────────────────────────────────
    threat_type, tt_conf = classify_threat_type(text)
    if threat_type:
        save_tag(con, msg_id, 'threat_type', threat_type, tt_conf)
        summary_parts.append(f"type:{threat_type}({tt_conf})")

    return ', '.join(summary_parts) if summary_parts else "no_intel"


def process_batch():
    con = db()
    try:
        rows = con.execute('''
            SELECT id, text, channel_id, channel_name, timestamp
            FROM telegram_messages
            WHERE intel_processed = 0
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (BATCH_SIZE,)).fetchall()

        if not rows:
            return 0

        count = 0
        for row in rows:
            try:
                summary = process_message(con, row)
                con.execute(
                    "UPDATE telegram_messages SET intel_processed=1, msg_hash=? WHERE id=?",
                    (message_hash(row['text'] or ''), row['id'])
                )
                if summary not in ('duplicate', 'skipped:too_short', 'no_intel'):
                    log.debug(f"msg {row['id']} [{row['channel_name']}]: {summary}")
                count += 1
            except Exception as e:
                log.warning(f"Error on msg {row['id']}: {e}")
                con.execute(
                    "UPDATE telegram_messages SET intel_processed=1 WHERE id=?",
                    (row['id'],)
                )

        con.commit()
        return count

    except Exception as e:
        log.error(f"Batch error: {e}")
        return 0
    finally:
        con.close()


def print_stats():
    con = db()
    try:
        ioc_c   = con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        tag_c   = con.execute("SELECT COUNT(*) FROM msg_tags").fetchone()[0]
        done    = con.execute("SELECT COUNT(*) FROM telegram_messages WHERE intel_processed=1").fetchone()[0]
        queue   = con.execute("SELECT COUNT(*) FROM telegram_messages WHERE intel_processed=0").fetchone()[0]
        dupes   = con.execute("SELECT COUNT(*) FROM telegram_messages WHERE is_duplicate=1").fetchone()[0]

        log.info(f"Stats — IOCs:{ioc_c:,}  Tags:{tag_c:,}  Done:{done:,}  Queue:{queue:,}  Dupes:{dupes:,}")

        top_actors = con.execute('''
            SELECT tag_value, COUNT(*) n, ROUND(AVG(confidence)) avg_conf
            FROM msg_tags WHERE tag_type='actor'
            GROUP BY tag_value ORDER BY n DESC LIMIT 5
        ''').fetchall()
        if top_actors:
            s = '  '.join(f"{r['tag_value']} ({r['n']}, {r['avg_conf']}%)" for r in top_actors)
            log.info(f"Top actors: {s}")

        top_iocs = con.execute('''
            SELECT type, COUNT(*) n, MAX(times_seen) max_seen
            FROM iocs GROUP BY type ORDER BY n DESC
        ''').fetchall()
        if top_iocs:
            s = '  '.join(f"{r['type']}:{r['n']} (max_seen:{r['max_seen']})" for r in top_iocs)
            log.info(f"IOC types: {s}")

        hot_iocs = con.execute('''
            SELECT type, value, times_seen FROM iocs
            WHERE times_seen >= 3
            ORDER BY times_seen DESC LIMIT 5
        ''').fetchall()
        if hot_iocs:
            s = '  '.join(f"{r['type']}={r['value']}({r['times_seen']}x)" for r in hot_iocs)
            log.info(f"Hot IOCs (3+ channels): {s}")

    except Exception as e:
        log.debug(f"Stats error: {e}")
    finally:
        con.close()


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    log.info("Dark Crawler Intelligence Worker v2 starting...")
    log.info(f"DB: {DB_PATH}")

    if not DB_PATH.exists():
        log.error(f"Database not found at {DB_PATH} — start server.py first")
        return

    ensure_tables()
    get_iocextract()
    get_nlp()

    con = db()
    queue = con.execute(
        "SELECT COUNT(*) FROM telegram_messages WHERE intel_processed=0"
    ).fetchone()[0]
    con.close()

    log.info(f"Queue: {queue:,} messages")
    if queue > 0:
        est = (queue / BATCH_SIZE * 2) / 60
        log.info(f"Estimated backlog time: ~{est:.0f} min")

    cycle      = 0
    total_proc = 0

    while True:
        try:
            n = process_batch()
            total_proc += n
            cycle += 1

            if n > 0:
                log.info(f"Batch done: {n} msgs (total {total_proc:,})")

            if cycle % 100 == 0:
                print_stats()

            # Adaptive sleep
            if n == BATCH_SIZE:  time.sleep(1)
            elif n > 0:          time.sleep(3)
            else:                time.sleep(SLEEP_IDLE)

        except KeyboardInterrupt:
            log.info("Shutting down...")
            print_stats()
            break
        except Exception as e:
            log.error(f"Main loop error: {e}")
            time.sleep(10)


if __name__ == '__main__':
    main()