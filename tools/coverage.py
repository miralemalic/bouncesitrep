#!/usr/bin/env python3
# Copyright (C) 2026 miralemalic
# SPDX-License-Identifier: MIT

"""Measure bouncesitrep against a corpus of real bounce text.

    python3 tools/coverage.py bounces.csv --column bounce_msg
    python3 tools/coverage.py bounces.jsonl --field msg

Print the coverage, the category and action split, and every reason found.
--unknown prints what could not be read, which is where new rules come from.

The README's coverage figure comes from this script.  Run it on your own
bounces and you get your own number.  The claim is meant to be checked.
"""

import os
import csv
import sys
import json
import argparse
import collections

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bouncesitrep as bc  # noqa: E402


SPACE = ' '
COMMASPACE = ', '

TIER_NAMES = {
    bc.T_TOKEN: 'vendor token',
    bc.T_BLOCKLIST: 'named blocklist',
    bc.T_ESC: 'status code',
    bc.T_TEXT: 'phrase',
    bc.T_GENERIC: 'generic (says it failed, not why)',
    bc.T_CLASS: 'bare SMTP class',
    '': 'no match',
    }


def read_csv(path, column):
    csv.field_size_limit(2 ** 31 - 1)
    with open(path, newline='', encoding='utf-8-sig', errors='replace') as fp:
        reader = csv.DictReader(fp)
        if reader.fieldnames and column not in reader.fieldnames:
            found = COMMASPACE.join(reader.fieldnames[:12])
            sys.exit(f"no column '{column}'. Found: {found}")
        for row in reader:
            yield row.get(column) or ''


def read_jsonl(path, field):
    with open(path, encoding='utf-8', errors='replace') as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line).get(field) or ''
            except ValueError:
                continue


def bar(fraction, width=28):
    filled = int(round(fraction * width))
    return '#' * filled + '.' * (width - filled)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('path', help='a CSV or JSONL file of bounce messages')
    parser.add_argument('-c', '--column', default='bounce_msg',
                        help='CSV column')
    parser.add_argument('-f', '--field', default='msg', help='JSONL field')
    parser.add_argument('--unknown', type=int, metavar='N', default=0,
                        help='print N unclassified messages')
    args = parser.parse_args()

    path = os.path.expanduser(args.path)
    if path.lower().endswith(('.jsonl', '.ndjson')):
        texts = read_jsonl(path, args.field)
    else:
        texts = read_csv(path, args.column)

    reason = collections.Counter()
    category = collections.Counter()
    action = collections.Counter()
    confidence = collections.Counter()
    tier = collections.Counter()
    provider = collections.Counter()
    unread, total, empty = [], 0, 0

    for text in texts:
        if not text.strip():
            empty += 1
            continue
        total += 1
        result = bc.classify(text)
        reason[result['reason']] += 1
        category[result['category']] += 1
        action[result['action']] += 1
        confidence[result['confidence']] += 1
        tier[result['_tier']] += 1
        if result['rejected_by']:
            provider[result['rejected_by']] += 1
        if result['reason'] in ('unknown', 'undefined'):
            unread.append(text)

    if not total:
        sys.exit('no non-empty messages found')

    covered = (total - len(unread)) / total * 100
    skipped = f'  ({empty:,} blank, skipped)' if empty else ''
    print(f'\n  corpus     {total:,} messages{skipped}')
    print(f'  coverage   {covered:.1f}%   ({len(unread):,} unclassified)\n')

    def block(title, counter, note=''):
        print(f'  {title}{note}')
        for key, n in counter.most_common():
            print(f'    {n:>8,}  {n / total * 100:5.1f}%  '
                  f'{bar(n / total)}  {key}')
        print()

    block('category', category, '     who has to act')
    block('action', action, '       what to do')
    block('reason', reason)
    block('confidence', confidence, '   how sure the match is')
    if provider:
        block('rejected by', provider, ' which system refused it')

    print('  decided by')
    # Numbered tiers first, then the messages nothing matched.
    for key, n in sorted(tier.items(), key=lambda item: (item[0] == '',
                                                         item[0])):
        print(f'    {n:>8,}  {n / total * 100:5.1f}%  {bar(n / total)}  '
              f'{TIER_NAMES.get(key, key)}')
    print()

    if args.unknown and unread:
        print(f'  {min(args.unknown, len(unread))} unclassified samples:')
        for text in unread[:args.unknown]:
            print(f'    {SPACE.join(text.split())[:150]}')
        print()


if __name__ == '__main__':
    main()
