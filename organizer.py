"""
organizer.py
────────────
Reads results.jsonl from the crawler, categorizes each entry using
keyword matching against title and body preview, then writes
organized_results.json grouped by category.

Usage:
    python organizer.py
    python organizer.py --input results.jsonl --output organized_results.json

No API key required.
"""

import json
import argparse
import re
from pathlib import Path
from collections import defaultdict

# ── Category rules ─────────────────────────────────────────────────────────────
# Each entry is (category_name, [keywords...])
# Keywords are matched against lowercased title + body preview.
# Order matters — first match wins.
CATEGORY_RULES = [
    ("Dead / Unreachable",      ["[no title]", "connection refused", "timed out", "not found"]),
    ("Search Engines & Indexes",["search engine", "search hidden", "index", "directory", "ahmia", "torch", "haystack", "not evil"]),
    ("Wikis & Directories",     ["wiki", "hidden wiki", "link list", "onion list", "catalog", "directory of"]),
    ("Forums & Communities",    ["forum", "board", "thread", "post", "reply", "community", "discussion", "chan", "bbs"]),
    ("News & Media",            ["news", "article", "press", "journalist", "media", "report", "daily", "times", "herald"]),
    ("Chat & Messaging",        ["chat", "message", "inbox", "jabber", "xmpp", "irc", "instant message", "messenger"]),
    ("Email & Communication",   ["email", "mail", "smtp", "inbox", "webmail"]),
    ("Blogs & Personal Sites",  ["blog", "personal", "diary", "journal", "my site", "about me", "portfolio"]),
    ("Markets & Commerce",      ["market", "shop", "store", "buy", "sell", "vendor", "listing", "product", "price", "checkout"]),
    ("Technology & Security",   ["security", "hacking", "exploit", "vulnerability", "ctf", "tech", "software", "code", "programming", "developer", "tool"]),
    ("Privacy & Anonymity",     ["privacy", "anonymous", "vpn", "tor", "encryption", "pgp", "opsec", "secure"]),
    ("Libraries & Archives",    ["library", "archive", "book", "document", "paper", "collection", "ebook", "pdf", "manuscript"]),
    ("Leak & Whistleblower",    ["leak", "whistle", "classified", "secret", "disclosure", "securedrop"]),
    ("Finance & Crypto",        ["bitcoin", "crypto", "wallet", "exchange", "monero", "ethereum", "currency", "finance", "bank"]),
    ("Hosting & Services",      ["hosting", "host", "server", "vps", "domain", "service provider"]),
]

FALLBACK_CATEGORY = "Uncategorized"


def categorize(entry):
    """Return a category string based on keyword matching."""
    title   = (entry.get("title")        or "").lower()
    preview = (entry.get("body_preview") or "").lower()
    status  = entry.get("status", 200)
    text    = f"{title} {preview}"

    # Dead sites — non-200 with no useful content
    if status != 200 and len(preview.strip()) < 30:
        return "Dead / Unreachable"

    for category, keywords in CATEGORY_RULES:
        for kw in keywords:
            if kw in text:
                return category

    return FALLBACK_CATEGORY


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  default="results.jsonl")
    parser.add_argument("--output", default="organized_results.json")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found. Run the crawler first.")
        return

    # Load all crawled entries
    entries = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    print(f"Loaded {len(entries)} entries from {input_path}")

    if not entries:
        print("No entries to categorize.")
        return

    # Categorize each entry
    organized = defaultdict(list)

    for entry in entries:
        category = categorize(entry)
        organized[category].append({
            "url":     entry.get("url", ""),
            "title":   entry.get("title", "[no title]"),
            "status":  entry.get("status", "?"),
            "preview": entry.get("body_preview", ""),
        })

    # Sort entries within each category by title
    for cat in organized:
        organized[cat].sort(key=lambda x: x["title"].lower())

    # Sort categories by number of sites descending
    sorted_organized = dict(
        sorted(organized.items(), key=lambda x: len(x[1]), reverse=True)
    )

    # Build summary
    summary = {
        "total_sites":      len(entries),
        "categories_found": len(sorted_organized),
        "breakdown": {cat: len(sites) for cat, sites in sorted_organized.items()},
    }

    output = {"summary": summary, "sites": sorted_organized}

    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nDone! Results written to {output_path}")
    print(f"\nSummary ({len(entries)} total sites):")
    for cat, count in summary["breakdown"].items():
        bar = "█" * min(count, 40)
        print(f"  {cat:<30} {bar} {count}")


if __name__ == "__main__":
    main()
