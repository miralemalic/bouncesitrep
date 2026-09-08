# bouncesitrep

```
                      │
                      │
                      │
                   ███████
                 ██   │   ██
                ██    │    ██
             ───█─────●─────█───
                ██    │    ██
                 ██   │   ██
                   ███████
                      │
                      │
                      │

    ╔╗ ╔═╗╦ ╦╔╗╔╔═╗╔═╗  ╔═╗╦╔╦╗╦═╗╔═╗╔═╗
    ╠╩╗║ ║║ ║║║║║  ║╣   ╚═╗║ ║ ╠╦╝║╣ ╠═╝
    ╚═╝╚═╝╚═╝╝╚╝╚═╝╚═╝  ╚═╝╩ ╩ ╩╚═╚═╝╩
                   v2.0.0
```

A SITREP is a situation report: where you stand, where you are taking losses,
what to do next. Point this at a bounce export from any sequencer and it writes
you one.

```
$ bouncesitrep export.csv --report

  [ bounce sitrep v2.0.0 ]
  reading 'bounce_msg', host from 'mx', dates from 'last_sent_at'
  15,635 rows -> export - classified.csv
    reputation         9,409  ( 60.2%)
    recipient          2,418  ( 15.5%)
    data               2,089  ( 13.4%)
    diagnosis -> export - diagnosis.md
```

One file. No dependencies. Python 3.9 or newer.

## Hard or soft is the wrong question

Every bounce tool sorts mail into hard and soft. That tells you nothing at 9am
with four thousand overnight bounces in front of you, because a dead address
and a blocked domain are both "hard" and they need opposite responses. Delete
the leads and you destroyed good data. Keep sending and you burn the domain.

The question worth answering is who has to fix it.

| category | means | who fixes it |
|---|---|---|
| `data` | the address is dead or wrong | clean the list |
| `reputation` | your sending identity is refused | pause, warm, get delisted |
| `authentication` | SPF, DKIM, DMARC or PTR is broken | a DNS change, today |
| `content` | a filter judged the message itself | rewrite the copy |
| `recipient` | their mailbox refuses everyone | suppress, nothing else to do |
| `transient` | nobody's fault | retry |

Six categories because they land on six different desks. Separating
`authentication` from `reputation` matters most: one takes weeks of warming,
the other is a DNS record you fix before lunch, and they look identical in a
hard/soft report.

## Install

```bash
curl -O https://raw.githubusercontent.com/miralemalic/bouncesitrep/main/bouncesitrep.py
chmod +x bouncesitrep.py
mv bouncesitrep.py ~/.local/bin/bouncesitrep
```

No pip. No virtualenv.

## Use

```bash
bouncesitrep export.csv                          # finds the columns itself
bouncesitrep export.csv --report                 # write a markdown diagnosis
bouncesitrep export.csv --suppress-list dead.txt # addresses never to mail again
bouncesitrep export.csv --dump-unknown miss.txt  # what it could not read
bouncesitrep "550 5.1.1 user unknown"            # one message
```

It reads exports from PlusVibe, Instantly, Smartlead or anything else that can
write a CSV. You do not pass `--column`: it scores every column on what the
values look like, not on the name, and reports which one it picked.

### One message

```
$ bouncesitrep "552 5.2.2 inbox is out of storage space and inactive"

  Mailbox is full and inactive - nobody is reading it

  reason      mailbox_full_abandoned
  category    data
  action      suppress
  confidence  high
  why         permanently over quota and the receiver calls it inactive
  smtp        552
  status      5.2.2
```

That distinction is worth the tool on its own. A full mailbox is normally worth
retrying. A full mailbox the receiver also calls *inactive* is an account
nobody opens, and a third of all full-mailbox bounces are that.

### Columns it adds

| column | example |
|---|---|
| `bounce_reason` | `blocklisted` |
| `bounce_meaning` | `Your sending domain or IP is on a public blocklist` |
| `bounce_category` | `reputation` |
| `bounce_action` | `pause_domain` |
| `bounce_detail` | `listed by Spamhaus - check.spamhaus.org` |
| `rejected_by` | `google` |
| `recipient_host` | `GOOGLE_WORKSPACE` |
| `smtp_code` / `status_code` | `554` / `5.7.1` |
| `blocklist` | `Spamhaus` |
| `confidence` | `high` |

`bounce_meaning` is there so somebody who does not know what 5.7.133 means can
still read the file. `rejected_by` and `recipient_host` are deliberately
different: one is who refused the mail, the other is where the mailbox lives.
A Google-hosted domain sitting behind Proofpoint shows both, and the gap tells
you whether Google is the problem or a filter in front of it is.

## The diagnosis

`--report` writes a markdown file that opens with a banner and a verdict, not
a table:

> **Your sending is the problem, not your list.** 64% of these bounces are
> receivers refusing your domains, your authentication or your copy. Only 29%
> are bad addresses.
>
> Cleaning the list will not fix this. Cutting volume, fixing authentication
> and getting delisted will.

Then who is rejecting you, a breakdown by recipient mail host, every blocklist
naming you with the URL to check it, your worst sending domains ranked by how
much of their failure is self-inflicted, whether bounces are rising or falling
across the window, and a numbered list of what to do first.

## How it decides

Real bounce text carries several signals at once and they disagree. Six tiers,
most trustworthy first:

| tier | signal | why there | share of decisions |
|---|---|---|---:|
| 1 | vendor tokens | `RESOLVER.ADR.RecipientNotFound`, `QuotaExceededException`. A program emitted these | 12% |
| 2 | named blocklists | if Spamhaus is named, you are listed | 9% |
| 3 | status codes | `5.7.708`, `5.1.1`. Specific ones only | 45% |
| 4 | phrases | "mailbox is full", "poor reputation" | 29% |
| 5 | generic | `5.7.1`, "delivery failed". Says a thing failed, not why | 4% |
| 6 | bare SMTP class | `4xx` or `5xx` and nothing else | <1% |

Two orderings, both needed. **Across tiers**, the better kind of signal wins
wherever it sits. **Within a tier**, the remote server's words beat the
relaying server's summary, because half of all bounce text looks like this:

```
5.1.351 Remote server returned unknown recipient or mailbox unavailable
   ->  550 Requested action not taken: mailbox unavailable;
       Reject due to policy restrictions.
```

The wrapper is Exchange guessing, and it reads as a dead address. The remote
server said policy. The remote server is right.

## What it refuses to do

**It will not pause a healthy domain on weak evidence.** `Recipient address
rejected: Access denied` is 2% of my corpus and Exchange returns it both for a
dead address and for a tenant block. Nothing in the text separates them, so it
resolves to `review` and says so.

**It will not suppress a lead over your own failure.** If your domain got
blocked, the recipient is still a good lead. No reason may pair a
sending-side category with `suppress`, and a test walks the whole table on
every run to enforce it.

Text it cannot read comes back as `unknown` with the raw message kept, never a
guess.

## Measured, not asserted

Built against **104,690 real bounces** from live cold email infrastructure -
Google Workspace, Microsoft 365 and plain SMTP senders, across 1,376 sending
domains, reaching 30,021 recipient domains over eleven weeks.

```
coverage, all 104,690       99.5%
worst single slice          99.2%
```

The worst slice is the number that matters, not the average. I wrote the first
set of rules reading one slice of that corpus. It scored 99.2% there and
**74.5%** on a slice it had never seen. That is what overfitting looks like,
and the only reason I caught it was testing against data the rules were not
written from. Every number above is the worst case after that.

Check it on your own bounces. The measuring stick ships with the tool:

```bash
python3 tools/coverage.py your_bounces.csv --column bounce_msg --unknown 20
```

If it scores worse on your corpus, that is a real result and I want the sample.

## Known limits

- **Input is bounce reason text, as sequencers expose it.** For parsing whole
  RFC5322 bounce emails with MIME and DSN headers, use
  [sisimai](https://libsisimai.org). It is mature, it covers dozens of mail
  servers, and it is the right tool for that job. This one starts where the API
  hands you a string.
- English NDRs. Other languages fall through to status codes, which still work.
- RFC 3463 coverage is complete across the address, mailbox, network, protocol,
  media and security families. Provider codes cover Microsoft, Google, Yahoo,
  AOL, Verizon, Proofpoint, Mimecast, Barracuda, Sophos and Open-Xchange.
  Anything else falls back to matching the prose.
- The corpus is cold email to US small business domains, so the mix leans that
  way. Transactional or European senders will see different proportions, though
  the rules themselves are not region-specific.
- No network calls. It will not check whether you are *currently* listed on a
  blocklist, only report that a receiver said so.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

88 tests, standard library only. Three of them are structural rather than
example-based: no sending-side fault may suppress an address, no transient
fault may suppress, and no data fault may pause a domain. Those are the
mistakes that cost real money, so they run against every entry in the table
rather than against a handful of samples.

## License

MIT. See [LICENSE](LICENSE). Do what you want with it. Don't blame me.
