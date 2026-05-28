"""
ransomlook_additions.py
========================
Additions sourced from RansomLook.io (May 2026) for gangs missing from the
original add_gang_attribution.py.

HOW TO APPLY:
  python ransomlook_additions.py --apply --db ~/dark-crawler/crawler.db
  python ransomlook_additions.py --dry-run --db ~/dark-crawler/crawler.db

What it does:
  1. Backfills new seed-map entries (Qilin, DragonForce, Stormous, etc.)
  2. Runs fingerprint matching for new gangs on existing unattributed sites
  3. Appends new live onion URLs to cti_seeds.json
"""

# ── SEED MAP ADDITIONS ────────────────────────────────────────────────────────

RANSOMLOOK_SEED_MAP: dict[str, str] = {

    # Qilin (aka Agenda) — #1 active gang May 2026, 146 posts/30d
    "ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion":  "Qilin",
    "pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd.onion":  "Qilin",
    "kbsqoivihgdmwczmxkbovk7ss2dcynitwhhfu5yw725dboqo5kthfaad.onion":  "Qilin",
    "24kckepr3tdbcomkimbov5nqv2alos6vmrmlxdr76lfmkgegukubctyd.onion":  "Qilin",
    "kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad.onion":  "Qilin",

    # DragonForce — cartel-model RaaS, UK retail attacks (M&S, Harrods, Co-op)
    "z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion":  "DragonForce",
    "dragonforxxbp3awc7mzs5dkswrua3znqyx5roefmi4smjrsdi22xwqd.onion":  "DragonForce",
    "fsguestuctexqqaoxuahuydfa6ovxuhtng66pgyr5gqcrsi7qgchpkad.onion":  "DragonForce",
    "3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd.onion":  "DragonForce",

    # Stormous — politically motivated + financial, active May 2026
    "stmxylixiz4atpmkspvhkym4xccjvpcv3v67uh3dze7xwwhtnz4faxid.onion":  "Stormous",

    # Brain Cipher — hit Indonesia national data center 2024, LockBit 3.0-based
    "nspirep7orjq73k2x2fwh2mxgh74vm2now6cdbnnxjk2f5wn34bmdxad.onion":  "Brain Cipher",

    # Daixin Team — healthcare-focused, joint FBI/CISA advisory
    "ijbw7iiyodqzpg6ooewbgn6mv2pinoer3k5pzdecoejsw5nyoe73zvad.onion":  "Daixin",

    # Abyss-Data (Abyss Locker) — ESXi-focused, Babuk-derived
    "6oeuvb4fq65xlrft2ezxjmkeqnu7oafbsevrr3ocer27wft6ivvhstqd.onion":  "Abyss-Data",

    # BlackByte — RaaS, FBI advisory, critical infrastructure targeting
    "vqifktlreqpudvulhbzmc5gocbeawl67uvs2pttswemdorbnhaddohyd.onion":  "BlackByte",
}


# ── FINGERPRINT ADDITIONS ─────────────────────────────────────────────────────

RANSOMLOOK_FINGERPRINTS: dict[str, list[str]] = {

    # Active groups from RansomLook recent posts (May 2026)
    "Qilin":            ["qilin ransomware", "agenda ransomware", "qilin blog",
                         "qilin group", "readme-recover"],
    "DragonForce":      ["dragonforce", "dragon force ransomware", "dragonforce cartel",
                         "dragonforce blog", "dragongo"],
    "LockBit5":         ["lockbit5", "lockbit 5", "lb5 ransomware"],
    "Stormous":         ["stormous", "stormous ransomware", "stormous team"],
    "Nightspire":       ["nightspire", "night spire ransomware", "nightspire group"],
    "The Gentlemen":    ["the gentlemen ransomware", "gentlemen ransomware group"],
    "Lamashtu":         ["lamashtu", "lamashtu ransomware", "lamashtu group"],
    "Bavacai":          ["bavacai", "bavacai ransomware"],
    "Exitium":          ["exitium", "exitium ransomware", "exitium group"],
    "Chaos":            ["chaos ransomware group", "chaos raas 2025"],
    "Ailock":           ["ailock", "ai lock ransomware", "ailock raas", ".ailock"],
    "M3rx":             ["m3rx", "m3rx ransomware", "m3rx group"],
    "Coinbase Cartel":  ["coinbase cartel", "coinbasecartel"],
    "Cmd Organization": ["cmd organization", "cmd ransomware", "cmd org"],
    "Audit Team":       ["audit team ransomware", "audit entity"],
    "Brain Cipher":     ["brain cipher", "braincipher", "brain cipher ransomware"],
    "Daixin":           ["daixin", "daixin team", "daixin ransomware"],
    "Abyss-Data":       ["abyss locker", "abyss-data", "abyssdata", "abyss ransomware"],
    "BlackByte":        ["blackbyte", "black byte ransomware", "blackbyte2"],
    "BlackSuit":        ["blacksuit", "black suit ransomware"],
    "Dispossessor":     ["dispossessor", "brain dispossessor"],
    "Dark Angels":      ["dark angels ransomware", "darkangels", "dunghill leak"],
    "8Base":            ["8base", "8 base ransomware", ".8base extension"],
    "Blackbasta":       ["black basta", "blackbasta", ".basta extension"],
    "Dark Power":       ["dark power ransomware", ".dark_power extension"],
    "Vice Society":     ["vice society", "vicesociety"],
    "Blackout":         ["blackout ransomware", "blackout group"],
    "Brotherhood":      ["brotherhood ransomware"],
    "Stormous":         ["stormous", "stormous ransomware"],
    "Clop Torrents":    ["clop torrents", "cl0p torrents"],
}


# ── NEW LIVE ONION SEEDS (confirmed Up, high uptime from RansomLook) ──────────

RANSOMLOOK_ONIONS: list[str] = [
    # Qilin primary leak site — 97% uptime
    "http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/",
    # Qilin secondary (Pandora mirror) — 90% uptime
    "http://pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd.onion/",
    # Qilin file server — 100% uptime
    "http://kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad.onion/",
    # DragonForce main blog — 100% uptime
    "http://z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion/blog",
    # DragonForce affiliate portal / file server — 100% uptime
    "http://dragonforxxbp3awc7mzs5dkswrua3znqyx5roefmi4smjrsdi22xwqd.onion/",
    # DragonForce guest access — 90% uptime
    "http://fsguestuctexqqaoxuahuydfa6ovxuhtng66pgyr5gqcrsi7qgchpkad.onion/",
    # DragonForce chat/negotiation portal — 97% uptime
    "http://3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd.onion/login",
]


# ── APPLICATION LOGIC ─────────────────────────────────────────────────────────

import sqlite3, argparse, json
from pathlib import Path


def apply_additions(db_path: Path, dry_run: bool = False) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    existing_cols = {row[1] for row in cur.execute("PRAGMA table_info(sites)")}
    for col, typedef in [("gang_name", "TEXT"), ("gang_confidence", "TEXT")]:
        if col not in existing_cols:
            if not dry_run:
                cur.execute(f"ALTER TABLE sites ADD COLUMN {col} {typedef}")

    # Seed map pass
    hits = 0
    for hostname, gang in RANSOMLOOK_SEED_MAP.items():
        row = cur.execute("SELECT id FROM sites WHERE host=?", (hostname,)).fetchone()
        if row:
            if not dry_run:
                cur.execute(
                    "UPDATE sites SET gang_name=?, gang_confidence='seed', category='Ransomware' WHERE host=?",
                    (gang, hostname)
                )
            hits += 1
    conn.commit()
    print(f"  Seed map: {hits} attributions from {len(RANSOMLOOK_SEED_MAP)} RansomLook entries")

    # Fingerprint pass
    unattributed = cur.execute(
        "SELECT id, host, title, preview FROM sites WHERE category='Ransomware' AND gang_name IS NULL"
    ).fetchall()
    fp_hits = 0
    for row in unattributed:
        text = f"{row['title'] or ''} {row['preview'] or ''}".lower()
        for gang, keywords in RANSOMLOOK_FINGERPRINTS.items():
            if any(kw in text for kw in keywords):
                if not dry_run:
                    cur.execute(
                        "UPDATE sites SET gang_name=?, gang_confidence='fingerprint' WHERE id=?",
                        (gang, row['id'])
                    )
                fp_hits += 1
                break
    conn.commit()
    print(f"  Fingerprints: {fp_hits} additional attributions from {len(unattributed)} unattributed sites")

    # Current gang breakdown
    print("\n  Current gang breakdown (top 25):")
    rows = cur.execute(
        "SELECT gang_name, gang_confidence, COUNT(*) as n FROM sites "
        "WHERE gang_name IS NOT NULL GROUP BY gang_name ORDER BY n DESC LIMIT 25"
    ).fetchall()
    for r in rows:
        print(f"    {r[0]:<30} {r[2]:>3} site(s)  [{r[1]}]")

    # Patch cti_seeds.json
    seeds_path = db_path.parent / "cti_seeds.json"
    if seeds_path.exists():
        seeds = json.loads(seeds_path.read_text())
        existing_onions = set(seeds.get("ransomware_onions", []))
        added = []
        for url in RANSOMLOOK_ONIONS:
            if url not in existing_onions:
                seeds.setdefault("ransomware_onions", []).append(url)
                added.append(url)
        if not dry_run and added:
            seeds_path.write_text(json.dumps(seeds, indent=2))
        print(f"\n  cti_seeds.json: {len(added)} new URLs added")
        for u in added:
            print(f"    + {u}")
    else:
        print(f"\n  WARNING: cti_seeds.json not found at {seeds_path} — copy RANSOMLOOK_ONIONS manually")

    conn.close()
    print(f"\n{'[DRY RUN — no changes written] ' if dry_run else ''}Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="~/dark-crawler/crawler.db")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    parser.add_argument("--apply", action="store_true", help="Required to actually write changes")
    args = parser.parse_args()

    if not args.apply and not args.dry_run:
        print("Usage: python ransomlook_additions.py --dry-run | --apply [--db PATH]")
        exit(0)

    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        print(f"ERROR: DB not found at {db_path}")
        exit(1)

    print(f"{'[DRY RUN] ' if args.dry_run else ''}Applying RansomLook additions to {db_path}...\n")
    apply_additions(db_path, dry_run=args.dry_run)
