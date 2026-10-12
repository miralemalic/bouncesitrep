# bouncesitrep

[![tests](https://github.com/miralemalic/bouncesitrep/actions/workflows/tests.yml/badge.svg)](https://github.com/miralemalic/bouncesitrep/actions/workflows/tests.yml)

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
                   v2.2.0
```

A SITREP is a situation report: where you stand, where you are taking losses,
what to do next. Point this at a bounce export and it writes you one.

```
$ bouncesitrep export.csv --report

  reading 'bounce_msg', host from 'mx', dates from 'last_sent_at'

  82,414 rows read  ->  4,227 written to export - classified.csv
  5.1% bounce rate  (4,227 of 82,414 leads)

    content            1,983   46.9%  ###########.............
    reputation           879   20.8%  #####...................
    data                 735   17.4%  ####....................
    recipient            454   10.7%  ###.....................
    unknown              160    3.8%  #.......................
    transient             16    0.4%  #.......................

    what to do
    pause_domain         579  receivers are refusing your sending domains
    suppress             996  addresses never to mail again
    rewrite_copy       1,974  filters judged the message itself
    retry_once           193  full mailboxes - one more try, then give up
    retry_later          197  temporary - safe to send again later
    review               288  could not be settled from the text alone

    blocklists      Spamhaus (33), Sophos XL (22), SURBL (10), SpamRL (2)

    diagnosis -> export - diagnosis.md
```

That is a real run on a real campaign export. The bars are coloured in a
terminal and plain when you pipe it, so the output stays greppable.

One file. No dependencies. Python 3.9 or newer.

## Hard or soft is the wrong question

Every bounce tool sorts mail into hard and soft. At 9am with four thousand
overnight bounces in front of you, that is no use: a dead address and a
blocked domain are both "hard" and they need opposite responses. Delete the
leads and you have destroyed good data. Keep sending and you burn the domain.

The question is whose problem it is.

| category | means | who fixes it |
|---|---|---|
| `data` | the address is dead or wrong | clean the list |
| `reputation` | your sending identity is refused | pause, warm, get delisted |
| `authentication` | SPF, DKIM, DMARC or PTR is broken | a DNS change, today |
| `content` | a filter judged the message itself | rewrite the copy |
| `recipient` | their mailbox refuses everyone | suppress, nothing else to do |
| `transient` | nobody's fault | retry |

Six categories, six different desks. Separating `authentication` from
`reputation` matters most: one is weeks of warming, the other is a DNS record
you fix before lunch, and a hard/soft report shows them as the same thing.

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
bouncesitrep export.csv --pause-list pause.txt   # sending domains to stop
bouncesitrep export.csv --dump-unknown miss.txt  # what it could not read
bouncesitrep export.csv --all-rows               # keep the non-bounces too
bouncesitrep export.csv -q --fail-over 3         # exit 3 above a 3% rate
bouncesitrep "550 5.1.1 user unknown"            # one message
bouncesitrep --reasons                           # every answer it can give
bouncesitrep --banner                            # just the mark
```

`--no-banner` skips the mark, for a wrapper script that has drawn it already.
`--help` lists everything, grouped, with the six categories at the bottom.

`-o` decides where everything lands. A bare filename goes there with the rest;
a full path is left where you put it:

```bash
bouncesitrep export.csv -o ~/Desktop/results --report \
  --suppress-list dead.txt --pause-list pause.txt --dump-unknown miss.txt
```

The output CSV holds **only the rows that bounced**. On a whole-campaign
export that is the difference between 300 rows you can act on and 10,000 you
have to scroll through. `--all-rows` keeps everything if you want it.

A sending domain makes the `--pause-list` when receivers refused it on
reputation at least three times and those refusals are at least half of its
bounces. Below that, a bad list explains it as well as a burnt domain does.

It reads exports from PlusVibe, Instantly, Smartlead or anything else that can
write a CSV. You do not pass `--column`: it scores every column on what the
values look like, not on the name, and reports which one it picked.

Comma, semicolon, tab or pipe separated, and `.tsv` too. It reads the header
to work out which rather than trusting the extension, because Excel writes
semicolons across most of Europe.

**Feed it the whole campaign export, not a bounces-only one.** Most leads in
that file never bounced, and those rows are the denominator - they are what
turns "1,615 blocklisted" into "a 3.0% bounce rate, half of it your own
sending". A bounces-only export still works, it just cannot tell you the rate.

### Exit status

| code | means |
|---:|---|
| 0 | done |
| 1 | something went wrong, and stderr says what |
| 2 | bad arguments |
| 3 | the bounce rate is above `--fail-over` |

A bounces-only export has no rate, so `--fail-over` treats it as an error
rather than a pass. Cron should not be told all is well when nobody checked.

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
  matched     "5.2.2 ... inactive"
```

That distinction is worth the tool on its own. A full mailbox is normally worth
retrying. A full mailbox the receiver also calls *inactive* is an account
nobody opens, and a quarter of all full-mailbox bounces are that.

`matched` is the text that decided it, so you can see why without trusting
the label.

### Columns it adds

| column | example |
|---|---|
| `bounce_reason` | `blocklisted` |
| `bounce_meaning` | `Your sending domain or IP is on a public blocklist` |
| `bounce_category` | `reputation` |
| `bounce_action` | `pause_domain` |
| `bounce_detail` | `GMX/1&1: your From domain is on a Spamhaus list` |
| `rejected_by` | `gmx` |
| `recipient_host` | `REGULAR_ACCOUNT` |
| `smtp_code` / `status_code` | `550` / `5.1.351` |
| `blocklist` | `Spamhaus` |
| `confidence` | `high` |

`bounce_meaning` is there so somebody who does not know what 5.7.133 means can
still read the file. `rejected_by` and `recipient_host` are deliberately
different: one is who refused the mail, the other is where the mailbox lives.
A Google-hosted domain sitting behind Proofpoint shows both, and the gap tells
you whether Google is the problem or a filter in front of it is.

## The diagnosis

`--report` writes a markdown file that opens with the rate, then a verdict,
before it shows you a single table:

> **4,227 of 82,414 leads bounced (5.1%)** - 2026-08-11 to 2026-10-12
>
> A 5.1% bounce rate is high enough to be doing damage on its own. Mailbox
> providers read it as a signal about you, so it compounds: the more you
> bounce, the more you get filtered.
>
> **The message is the problem, not the sender.** 1,983 bounces (47%) are
> filters judging the content.
>
> Your domains are being accepted; what you wrote is not. Look at the links,
> the attachments and the phrasing before you touch anything to do with
> sending.

The rate comes first because it decides whether the rest is urgent. "1,615
blocklisted" tells you nothing on its own.

Then who is rejecting you, a breakdown by recipient mail host, every blocklist
naming you with the URL to check it, your worst sending domains ranked by how
much of their failure is self-inflicted, whether bounces are rising or falling
across the window, and a numbered list of what to do first.

## How it decides

Real bounce text carries several signals at once and they disagree. Six tiers,
most trustworthy first:

| tier | signal | why there | share of decisions |
|---|---|---|---:|
| 1 | vendor tokens | `RESOLVER.ADR.RecipientNotFound`, `QuotaExceededException`, GMX case codes. A program emitted these | 33% |
| 2 | named blocklists | if Spamhaus is named, you are listed | 14% |
| 3 | status codes | `5.7.708`, `5.1.1`. Specific ones only | 22% |
| 4 | phrases | "mailbox is full", "poor reputation" | 26% |
| 5 | generic | `5.7.1`, "delivery failed". Says a thing failed, not why | 5% |
| 6 | bare SMTP class | `4xx` or `5xx` and nothing else | <1% |

Two orderings, both needed. **Across tiers**, the better kind of signal wins
wherever it sits. **Within a tier**, the remote server's words beat the
relaying server's summary, because half of all bounce text looks like this:

```
5.1.351 Remote server returned unknown recipient or mailbox unavailable
   ->  550 Requested action not taken: mailbox unavailable;
       Reject due to policy restrictions.;For explanation visit
       https://postmaster.gmx.net/en/case?c=r1102&...
```

The wrapper is Exchange guessing, and it reads as a dead address. The remote
server says policy, and its case code says which policy: r1102, your From
domain is on a Spamhaus list. That is nearly 12,000 bounces in the corpus
that earlier versions sent to review.

### Where the codes come from

Vendor codes are read the way the vendor documents them, and the source sits
next to the rule in the code:

- Microsoft: [Email nondelivery reports and SMTP errors in Exchange Online](https://learn.microsoft.com/en-us/troubleshoot/exchange/email-delivery/ndr/non-delivery-reports-in-exchange-online)
- [IANA's SMTP enhanced status code registry](https://www.iana.org/assignments/smtp-enhanced-status-codes/smtp-enhanced-status-codes.xhtml) - RFC 3463, RFC 7372, RFC 7505
- GMX, web.de, mail.com and 1&1: the postmaster [case pages](https://postmaster.gmx.net/en/case?c=r1102) their bounces link to
- Mimecast: its SMTP error code page, which its bounces link to

Where a vendor publishes nothing - Apple's CS01 and HM08, Outlook.com's
S2017062302 - the call rests on the corpus, and the next section is how.

## What it refuses to do

**It will not pause a healthy domain on weak evidence.** `Recipient address
rejected: Access denied` is 2.9% of the corpus. Microsoft documents it as an
address that does not exist, but when those addresses were mailed again, 3
sends in 10 arrived. Nothing in the text separates the two cases, so it
resolves to `review` and says so.

**It will not suppress a lead over your own failure.** If your domain got
blocked, the recipient is still a good lead. No reason may pair a sending-side
category with `suppress`. A test walks the whole table on every run to enforce
that.

Text it cannot read comes back as `unknown`, raw message kept. It does not
guess.

## Measured, not asserted

Built against **254,054 real bounces** from live cold email infrastructure -
eight sending workspaces on Google Workspace and Microsoft 365, 1,482 sending
domains, reaching 72,263 recipient domains between June and October 2026.

```
coverage, all 254,054         99.6%
worst workspace               99.2%
held-out workspace            99.3%
```

The worst slice is the number that matters, not the average. I wrote the first
rules against one slice of an earlier corpus. They scored 99.2% there and
**74.5%** on a slice they had never seen. That is overfitting, and the only
reason I caught it was testing against data the rules were not written from.

So one workspace is held out. No rule was written from its bounce text; it is
only scored. Version 2.1 read 98.8% of it, version 2.2 reads 99.3%.

### Checked against what happened next

Coverage says a rule matched. It does not say the rule was right, and for the
calls that delete a lead, right is what matters. So those were checked against
what happened next: take addresses that bounced, find a later send to the same
address, and see whether it arrived. A dead address bounces again. A filter
having a bad day does not.

| bounce | later sends that arrived | so |
|---|---:|---|
| `550 5.1.1 user unknown`, the control | 0 of 28 | suppress |
| Outlook.com `(S2017062302)` | 1 of 34 | suppress |
| Microsoft "storage full" | 15 of 66 | one more try |
| `Recipient address rejected: Access denied` | 3 of 10 | review |
| bare `mailbox unavailable.` | 70 of 115 | review |
| iCloud `[HM08]` | 182 of 268 | retry later |
| iCloud `[CS01]` | 78 of 106 | not the address |

Microsoft documents a bare "mailbox unavailable" from Outlook.com as an
address its lookup could not find. 70 of 115 later sends arrived anyway, so
the corpus overrules the documentation and it stays in review.

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
  media and security families, and RFC 7372's authentication codes are read as
  registered. Provider codes cover Microsoft, Google, Yahoo, AOL, Verizon,
  Apple iCloud, GMX/web.de/mail.com/1&1, Mimecast, Sophos and Open-Xchange.
  Anything else falls back to matching the prose.
- Spectrum and Cox `AUP#` codes are read as acceptable-use rejections, not by
  number. Spectrum publishes what each number means, but only behind
  JavaScript.
- The corpus is cold email, mostly to US small business domains, with some
  finance and consumer lists. Transactional or European senders will see
  different proportions, though the rules themselves are not region-specific.
- No network calls. It will not check whether you are *currently* listed on a
  blocklist, only report that a receiver said so.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

155 tests, standard library only. Three of them are structural rather than
example-based: no sending-side fault may suppress an address, no transient
fault may suppress, and no data fault may pause a domain. Those are the
mistakes that cost real money, so they run against every entry in the table
rather than against a handful of samples.

## License

MIT. See [LICENSE](LICENSE). Do what you want with it. Don't blame me.
