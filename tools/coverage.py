#!/usr/bin/env python3
"""Measure bouncesitrep against a corpus of real bounce text.

    python3 tools/coverage.py bounces.csv --column bounce_msg
    python3 tools/coverage.py bounces.jsonl --field msg

Prints coverage, the fault and action split, and the reasons found. Use
--unknown to print the messages it could not read, which is how new patterns
get written.

The README's coverage figure comes from this script. Run it on your own
bounces and you will get your own number -- the claim is meant to be checked,
not taken on trust.
"""

import argparse
import collections
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bouncesitrep as bc  # noqa: E402


def read_csv(path, column):
    csv.field_size_limit(2 ** 31 - 1)
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames and column not in reader.fieldnames:
            sys.exit(f"no column '{column}'. Found: {', '.join(reader.fieldnames[:12])}")
        for row in reader:
            yield row.get(column) or ""


def read_jsonl(path, field):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line).get(field) or ""
            except ValueError:
                continue


def bar(frac, width=28):
    filled = int(round(frac * width))
    return "#" * filled + "." * (width - filled)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="a CSV or JSONL file of bounce messages")
    ap.add_argument("-c", "--column", default="bounce_msg", help="CSV column")
    ap.add_argument("-f", "--field", default="msg", help="JSONL field")
    ap.add_argument("--unknown", type=int, metavar="N", default=0,
                    help="print N unclassified messages")
    args = ap.parse_args()

    path = os.path.expanduser(args.path)
    src = read_jsonl(path, args.field) if path.lower().endswith((".jsonl", ".ndjson")) \
        else read_csv(path, args.column)

    reason = collections.Counter()
    fault = collections.Counter()
    action = collections.Counter()
    conf = collections.Counter()
    tier = collections.Counter()
    provider = collections.Counter()
    unknown, total, empty = [], 0, 0

    for text in src:
        if not text.strip():
            empty += 1
            continue
        total += 1
        r = bc.classify(text)
        reason[r["reason"]] += 1
        fault[r["category"]] += 1
        action[r["action"]] += 1
        conf[r["confidence"]] += 1
        tier[r["_tier"]] += 1
        if r["rejected_by"]:
            provider[r["rejected_by"]] += 1
        if r["reason"] in ("unknown", "undefined"):
            unknown.append(text)

    if not total:
        sys.exit("no non-empty messages found")

    cov = (total - len(unknown)) / total * 100
    print(f"\n  corpus     {total:,} messages" + (f"  ({empty:,} blank, skipped)" if empty else ""))
    print(f"  coverage   {cov:.1f}%   ({len(unknown):,} unclassified)\n")

    def block(title, counter, note=""):
        print(f"  {title}{note}")
        for k, v in counter.most_common():
            print(f"    {v:>8,}  {v/total*100:5.1f}%  {bar(v/total)}  {k}")
        print()

    block("category", fault, "     who has to act")
    block("action", action, "       what to do")
    block("reason", reason)
    block("confidence", conf, "   how sure the match is")
    if provider:
        block("rejected by", provider, " which system refused it")

    names = {bc.T_TOKEN: "vendor token", bc.T_BLOCKLIST: "named blocklist",
             bc.T_ESC: "status code", bc.T_TEXT: "phrase",
             bc.T_GENERIC: "generic (says it failed, not why)",
             bc.T_CLASS: "bare SMTP class", "": "no match"}
    print("  decided by")
    for k, v in sorted(tier.items(), key=lambda x: (x[0] == "", x[0])):
        print(f"    {v:>8,}  {v/total*100:5.1f}%  {bar(v/total)}  {names.get(k, k)}")
    print()

    if args.unknown and unknown:
        print(f"  {min(args.unknown, len(unknown))} unclassified samples:")
        for u in unknown[:args.unknown]:
            print(f"    {' '.join(u.split())[:150]}")
        print()


if __name__ == "__main__":
    main()
