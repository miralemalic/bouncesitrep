#!/usr/bin/env python3
"""Read bounce text from any sequencer export and say what is actually wrong.

  bouncesitrep export.csv                  # finds the bounce column itself
  bouncesitrep export.csv --report         # writes a markdown diagnosis
  bouncesitrep export.csv --suppress-list dead.txt
  bouncesitrep "550 5.1.1 user unknown"    # one message

Every bounce tool sorts mail into hard and soft. That tells you nothing at 9am
with four thousand overnight bounces in front of you. The question worth
answering is who has to fix it: your list, your domains, your DNS, or your copy.

Input is bounce reason text as sequencers expose it. For parsing whole RFC5322
bounce emails, use sisimai (https://libsisimai.org).

Standard library only. Inputs are read-only.
"""

import argparse
import collections
import csv
import os
import re
import sys

__version__ = "2.0.0"

QUIET = False


def say(*a, **k):
    if not QUIET:
        print(*a, **k)


# ------------------------------------------------------------- what we output

# Category answers "whose problem is it", chosen so each one lands on a
# different desk. Splitting reputation from authentication matters because one
# takes weeks of warming and the other is a DNS record you fix before lunch.
DATA = "data"                    # the address is dead or wrong
REPUTATION = "reputation"        # your sending identity is being refused
AUTH = "authentication"          # SPF/DKIM/DMARC/PTR is broken
CONTENT = "content"              # the message itself tripped a filter
RECIPIENT = "recipient"          # their mailbox refuses everyone, permanently
TRANSIENT = "transient"          # nobody's fault, come back later
UNKNOWN = "unknown"

SUPPRESS = "suppress"            # never send here again
RETRY = "retry_later"            # safe to try again
RETRY_ONCE = "retry_once"        # one more attempt, then give up
PAUSE = "pause_domain"           # stop this sending domain now
FIXAUTH = "fix_auth"             # fixable today, in DNS
REWRITE = "rewrite_copy"         # the words are the problem
REVIEW = "review"                # classified, but look at it yourself

# reason -> (plain English, category, action)
# The plain English column is what makes an export readable by someone who
# does not know what 5.7.133 means, which is most people who will open it.
REASONS = {
    "user_unknown": (
        "The address does not exist", DATA, SUPPRESS),
    "host_unknown": (
        "The domain does not exist or has no mail server", DATA, SUPPRESS),
    "no_relaying": (
        "That server does not handle mail for this address", DATA, SUPPRESS),
    "syntax_error": (
        "The address is malformed", DATA, SUPPRESS),
    "ambiguous_address": (
        "The address matches more than one mailbox at the receiver",
        DATA, REVIEW),
    "sender_address_bad": (
        "Your own return address is malformed or its domain will not accept mail",
        AUTH, FIXAUTH),
    "protocol_error": (
        "The two servers could not agree on how to hand the message over",
        TRANSIENT, RETRY),
    "media_error": (
        "The receiver cannot handle the message's format or encoding",
        CONTENT, REVIEW),
    "crypto_error": (
        "TLS or message signing failed between the servers", AUTH, REVIEW),
    "list_expansion": (
        "The address is a mailing list the receiver would not expand",
        RECIPIENT, REVIEW),
    "throttled": (
        "The receiver is deferring you for sending too fast or drawing complaints",
        REPUTATION, RETRY),
    "has_moved": (
        "The address has moved and forwarding is off", DATA, SUPPRESS),

    "mailbox_full_abandoned": (
        "Mailbox is full and inactive - nobody is reading it", DATA, SUPPRESS),
    "mailbox_full": (
        "Mailbox is full right now", RECIPIENT, RETRY_ONCE),
    "suspended": (
        "The account is disabled or closed", DATA, SUPPRESS),
    "restricted_recipient": (
        "This mailbox only accepts mail from inside its own organisation",
        RECIPIENT, SUPPRESS),
    "mail_loop": (
        "The address forwards in a loop and never arrives", RECIPIENT, SUPPRESS),

    "blocklisted": (
        "Your sending domain or IP is on a public blocklist", REPUTATION, PAUSE),
    "bad_reputation": (
        "The receiver scores your sending reputation as too low",
        REPUTATION, PAUSE),
    "blocked": (
        "The receiver refused you on policy grounds", REPUTATION, PAUSE),
    "rate_limited": (
        "You are sending faster than this receiver accepts", REPUTATION, PAUSE),
    "geo_blocked": (
        "The receiver blocks mail from your server's country", REPUTATION, REVIEW),

    "auth_failure": (
        "SPF, DKIM or DMARC failed - the receiver cannot verify you is you",
        AUTH, FIXAUTH),
    "require_ptr": (
        "Your sending IP has no valid reverse DNS record", AUTH, FIXAUTH),

    "spam_detected": (
        "A spam filter judged the message itself, not the sender",
        CONTENT, REWRITE),
    "policy_violation": (
        "A policy rule refused the message - usually the sender, not the words",
        REPUTATION, REVIEW),
    "virus_detected": (
        "The message was flagged as carrying malware", CONTENT, REVIEW),
    "email_too_large": (
        "The message exceeded the receiver's size limit", CONTENT, REVIEW),

    "greylisted": (
        "Greylisted - the receiver wants you to try again shortly",
        TRANSIENT, RETRY),
    "expired": (
        "Delivery kept failing until the queue gave up", TRANSIENT, RETRY),
    "network_error": (
        "DNS or routing failure reaching the receiver", TRANSIENT, RETRY),
    "system_error": (
        "The receiving server had an internal problem", TRANSIENT, RETRY),

    "rejected": (
        "Refused without saying why - could be the address or could be you",
        UNKNOWN, REVIEW),
    "undefined": (
        "Only a bare failure code, no explanation given", UNKNOWN, REVIEW),
    "unknown": (
        "Not recognised - the raw text is kept for review", UNKNOWN, REVIEW),
    "empty": (
        "No bounce text present", UNKNOWN, REVIEW),
}

# Precedence. Lower wins. Machine tokens beat prose because a program emitted
# them; an admin typed the prose, sometimes years ago, sometimes wrongly.
T_TOKEN = 1      # RESOLVER.ADR..., STOREDRV..., vendor gateway codes
T_BLOCKLIST = 2  # a named blocklist settles it
T_ESC = 3        # specific enhanced status codes
T_TEXT = 4       # English phrases
T_GENERIC = 5    # signals that say "it failed" without saying why
T_CLASS = 6      # bare 4xx/5xx

CONFIDENCE = {T_TOKEN: "high", T_BLOCKLIST: "high", T_ESC: "high",
              T_TEXT: "medium", T_GENERIC: "low", T_CLASS: "low"}


class Rule:
    def __init__(self, tier, pattern, reason, detail=""):
        self.tier = tier
        self.rx = re.compile(pattern, re.I)
        self.reason = reason
        self.detail = detail


R = Rule

RULES = [
    # ---------------------------------------------------------- vendor tokens
    R(T_TOKEN, r'RESOLVER\.ADR\.(?:Ex)?RecipientNotFound|RESOLVER\.ADR\.InvalidInSmtp',
      "user_unknown", "Exchange could not resolve the address"),
    R(T_TOKEN, r'RESOLVER\.FWD\.NotFound', "user_unknown",
      "Exchange forwarding target does not exist"),
    R(T_TOKEN, r'STOREDRV\.Deliver.*Missing AD entry|AD Recipient Cache',
      "user_unknown", "no directory entry for the recipient"),
    R(T_TOKEN, r'QuotaExceededException|STOREDRV\.Deliver\.Exception:.*Quota',
      "mailbox_full", "Exchange reports the mailbox over quota"),
    R(T_TOKEN, r'RESOLVER\.RST\.SenderNotAuthenticatedFor(?:Group|Mailbox)|'
               r'RESOLVER\.RST\.RestrictedToRecipientsPermission|UnifiedGroupAgent|'
               r'external senders? (?:aren\'?t|are not) permitted|'
               r'sender isn\'?t (?:a group member|on the recipient)',
      "restricted_recipient", "recipient only accepts internal senders"),
    R(T_TOKEN, r'delivery will only occur if you click|recipient declines mail from',
      "restricted_recipient", "recipient uses a challenge-response gate"),
    R(T_TOKEN, r'TRANSPORT\.RULES\.RejectMessage', "policy_violation",
      "a mail-flow rule on the receiving tenant rejected it"),
    R(T_TOKEN, r'TenantInboundAttribution|RestrictDomainsTo(?:IPAddresses|Certificate)',
      "restricted_recipient", "receiving tenant only accepts partner connectors"),
    R(T_TOKEN, r'RESOLVER\.RST\.NotAuthorized|RESOLVER\.RST\.AuthRequired',
      "policy_violation", "sender not authorised for this recipient"),
    R(T_TOKEN, r'ATTR34|hop count exceeded|mail loop', "mail_loop",
      "the address forwards in a loop"),
    R(T_TOKEN, r'g_deny_country|country is banned', "geo_blocked",
      "receiver blocks the sending server's country"),
    R(T_TOKEN, r'\bAUP#', "policy_violation",
      "Comcast acceptable-use policy code"),
    # Sophos and Open-Xchange gateways emit opaque codes with no prose at all.
    R(T_TOKEN, r'\bXGEMAIL_\d+', "blocked", "Sophos gateway rejected the message"),
    R(T_TOKEN, r'\bOXSUS\d+_\d+', "blocked", "Open-Xchange gateway rejected the sender"),
    R(T_TOKEN, r'\bS\d{9,}\b', "blocked", "Barracuda-style gateway rejection code"),
    # Yahoo and AOL bracket a short code into the text. TS/TSS are throttles
    # and read as temporary; the dashboards that only show 4xx-vs-5xx lose
    # that distinction entirely.
    R(T_TOKEN, r'\[TSS?\d{2}\]|\bTSS0[1-4]\b|\bTS0[1-4]\b', "throttled",
      "Yahoo/AOL deferral - too much volume or too many complaints"),
    R(T_TOKEN, r'\bPH0[1-9]\b|\bIPv6 connections are not accepted\b', "blocked",
      "Verizon/Yahoo policy rejection code"),
    R(T_TOKEN, r'\bHVU:B1\b|\bVS3140\b|\bDNSBL:', "blocklisted",
      "Yahoo reputation or blocklist rejection"),

    # ------------------------------------------------------- named blocklists
    R(T_BLOCKLIST, r'\b(?:dbl|zen|sbl|xbl|pbl|css)\.spamhaus\.org|spamhaus',
      "blocklisted", "listed by Spamhaus - check.spamhaus.org"),
    R(T_BLOCKLIST, r'\bsurbl\b|multi\.surbl\.org', "blocklisted", "listed by SURBL"),
    R(T_BLOCKLIST, r'sophosxl\.(?:com|net)', "blocklisted", "listed by Sophos XL"),
    R(T_BLOCKLIST, r'spamrl\.com', "blocklisted", "listed by SpamRL"),
    R(T_BLOCKLIST, r'spamcop|barracudacentral|uceprotect|sorbs|invaluement|truncate\.gbudb',
      "blocklisted", "listed by a public DNSBL"),
    R(T_BLOCKLIST, r'listed by dbl|blocked using|block list|blocklist|blacklist|'
                   r'listed (?:on|in|by)\b[^.]{0,40}?(?:rbl|dnsbl|list)',
      "blocklisted", "the receiver named a blocklist"),

    # --------------------------------------------------- enhanced status codes
    R(T_ESC, r'\b5\.7\.(?:70[0-9]|71[0-9]|750)\b', "bad_reputation",
      "Microsoft: sending IP reputation too low"),
    R(T_ESC, r'\b5\.7\.6[0-4][0-9]\b', "blocked",
      "Microsoft: tenant or IP policy block"),
    R(T_ESC, r'\b5\.7\.(?:12[0-9]|13[0-9]|19[0-9]|5[12][0-9])\b', "restricted_recipient",
      "Microsoft: recipient refuses external or forwarded mail"),
    R(T_ESC, r'\b5\.7\.26\b', "auth_failure", "Gmail: unauthenticated sender"),
    R(T_ESC, r'\b5\.7\.2[0-5]\b', "require_ptr", "Gmail: PTR or authentication problem"),
    R(T_ESC, r'\b[45]\.7\.2[89]\b', "rate_limited",
      "Gmail: unusual rate or unsolicited-mail pattern"),
    R(T_ESC, r'\b[45]\.7\.30\b', "rate_limited", "receiver rate limit"),
    R(T_ESC, r'\b5\.1\.(?:[0-36]|10)\b', "user_unknown", "address does not exist"),
    R(T_ESC, r'\b5\.4\.1\b', "user_unknown", "no route to the recipient address"),
    R(T_ESC, r'\b5\.2\.2\b', "mailbox_full",
      "over quota - permanent code, but mailboxes do get emptied"),
    R(T_ESC, r'\b5\.2\.1\b', "suspended", "mailbox disabled"),
    R(T_ESC, r'\b5\.3\.4\b', "email_too_large", "message above the size limit"),
    R(T_ESC, r'\b4\.2\.2\b', "mailbox_full", "mailbox over quota, temporary"),
    R(T_ESC, r'\b4\.4\.[17]\b', "expired", "delivery attempts timed out"),
    R(T_ESC, r'\b4\.3\.\d+\b', "system_error", "receiving system problem"),
    # Yahoo's own policy refusal. Sender-side, and distinct from 5.7.1.
    R(T_ESC, r'\b5\.7\.9\b', "policy_violation",
      "Yahoo: refused on policy, usually DMARC or content"),
    R(T_ESC, r'\b[45]\.7\.2\b', "list_expansion",
      "the receiver refuses to expand this list"),
    R(T_ESC, r'\b[45]\.7\.0\b', "policy_violation", "refused on security policy"),
    R(T_ESC, r'\b[45]\.7\.[4-7]\b', "crypto_error", "TLS or signing failure"),
    # X.1.x address family
    R(T_ESC, r'\b5\.1\.4\b', "ambiguous_address", "address matches several mailboxes"),
    R(T_ESC, r'\b[45]\.1\.[78]\b', "sender_address_bad",
      "your return address or its domain is the problem"),
    # X.2.x mailbox family
    R(T_ESC, r'\b[45]\.2\.3\b', "email_too_large", "over the receiver's size limit"),
    R(T_ESC, r'\b[45]\.2\.4\b', "list_expansion", "mailing list expansion problem"),
    # X.4.x network family
    R(T_ESC, r'\b[45]\.4\.6\b', "mail_loop", "routing loop detected"),
    R(T_ESC, r'\b[45]\.4\.4\b', "host_unknown", "no route to the destination"),
    R(T_ESC, r'\b[45]\.4\.[025]\b', "network_error", "network or connection failure"),
    # X.5.x protocol family
    R(T_ESC, r'\b[45]\.5\.3\b', "protocol_error",
      "more recipients in one transaction than the receiver allows"),
    R(T_ESC, r'\b[45]\.5\.[0-2456]\b', "protocol_error", "SMTP protocol disagreement"),
    # X.6.x content family
    R(T_ESC, r'\b[45]\.6\.\d+\b', "media_error", "message format or encoding rejected"),

    # ---------------------------------------------------------------- phrases
    R(T_TEXT, r'over quota|quota exceeded|out of storage|mailbox (?:is )?full|'
              r'inode limit|blocks limit exceeded|insufficient system storage',
      "mailbox_full", "the receiver says the mailbox is full"),
    R(T_TEXT, r'user unknown|unknown recipient|no such (?:user|recipient|mailbox)|'
              r'does not exist|recipient not found|invalid recipient|'
              r'unrouteable address|no mailbox (?:here|by that name)|'
              r'mailbox not found|address (?:could not be found|not found)|'
              r'user doesn\'?t exist|email address invalid|address is invalid|'
              r'was misspelled|no valid recipients',
      "user_unknown", "the receiver says there is no such address"),
    R(T_TEXT, r'domain (?:does not|doesn\'?t) exist|host unknown|unrouteable domain|'
              r'no such domain|domain not found|dns record is (?:invalid|misconfigured)',
      "host_unknown", "the domain has no working mail server"),
    R(T_TEXT, r'mailbox (?:is )?disabled|account (?:is )?(?:disabled|suspended|inactive)|'
              r'no longer (?:employed|with|active)|account closed|'
              r'disabled recipient|user disabled|cannot receive new mail',
      "suspended", "the account is switched off"),
    R(T_TEXT, r'has moved|address has changed|forwarding disabled', "has_moved",
      "the address moved"),
    R(T_TEXT, r'(?:detect\w*|identif\w*|flagg\w*|classif\w*|reject\w*)[^.;]{0,40}?\bas spam|'
              r'spam message rejected|high probability of spam|considered spam|'
              r'looks like spam|spam content|message (?:is|was) spam|appears to be spam|'
              r'content rejected as spam',
      "spam_detected", "a content filter judged the message as spam"),
    R(T_TEXT, r'poor reputation|bad reputation|low reputation|reputation of (?:the |a )?domain|'
              r'sender reputation|suspicious due to',
      "bad_reputation", "the receiver scored your reputation as too low"),
    R(T_TEXT, r'administrative prohibition|policy (?:restrict|reason|violation)|'
              r'local (?:policy|security policy)|organization policy|rejected by policy|'
              r'delivery requirements|content filter|denied due to|'
              r'mailbox delivery failure policy',
      "policy_violation", "a policy rule rejected the message"),
    R(T_TEXT, r'relay(?:ing)? (?:denied|not permitted|access denied)|unable to relay|'
              r'relay access denied',
      "no_relaying", "that server does not accept mail for this address"),
    R(T_TEXT, r'your access to [^.]{0,40}?(?:e-?mail )?system[^.]{0,30}?(?:rejected|denied)|'
              r'sender (?:email )?address rejected|sender rejected|blocked\b|prohibited|'
              r'not permitted|refused|banned|host network not allowed',
      "blocked", "the receiver refused the sender outright"),
    R(T_TEXT, r'\bspf\b|\bdkim\b|\bdmarc\b|not authenticated|'
              r'authentication (?:required|failed)|unauthenticated',
      "auth_failure", "sender authentication did not pass"),
    R(T_TEXT, r'reverse dns|ptr record|no rdns|missing ptr', "require_ptr",
      "no valid reverse DNS for the sending IP"),
    R(T_TEXT, r'greylist|grey-list|try again later|please retry|'
              r'temporarily (?:deferred|unavailable|rejected)|deferred',
      "greylisted", "the receiver asked you to try again"),
    R(T_TEXT, r'too many (?:messages|connections|recipients)|rate limit|throttl|'
              r'sending quota|exceeded the maximum',
      "rate_limited", "you exceeded the receiver's rate"),
    R(T_TEXT, r'message expired|delivery time expired|retry timeout|'
              r'repeated attempts to deliver|could not be delivered.*\bdays\b',
      "expired", "the queue gave up after repeated attempts"),
    R(T_TEXT, r'virus|malware|infected', "virus_detected", "flagged as malware"),
    R(T_TEXT, r'message (?:is )?too large|size limit|exceeds.*size', "email_too_large",
      "over the size limit"),
    R(T_TEXT, r'connection (?:refused|timed out)|network (?:is )?unreachable|'
              r'no route to host|dns (?:error|failure)',
      "network_error", "could not reach the receiving server"),

    # ------------------------------------------- says it failed, not why
    R(T_GENERIC, r'\b5\.7\.1\b', "blocked", "generic policy refusal"),
    R(T_GENERIC, r'\b5\.1\.0\b|\baddress rejected\b', "rejected",
      "address refused without a stated reason"),
    R(T_GENERIC, r'\b4\.7\.\d+\b', "greylisted", "temporary policy refusal"),
    R(T_GENERIC, r'mailbox unavailable|action not taken|recipient (?:address )?rejected|'
                 r'delivery failed|undeliverable|command rejected|access denied',
      "rejected", "refused without a stated reason"),

    # ------------------------------------------------------- bare SMTP class
    R(T_CLASS, r'\b4\d\d\b', "undefined", "temporary failure, no detail"),
    R(T_CLASS, r'\b5\d\d\b', "undefined", "permanent failure, no detail"),
]

RULES.sort(key=lambda r: r.tier)

RULES_BY_TIER = []
for _r in RULES:
    if not RULES_BY_TIER or RULES_BY_TIER[-1][0] != _r.tier:
        RULES_BY_TIER.append((_r.tier, []))
    RULES_BY_TIER[-1][1].append(_r)


# -------------------------------------------------------------------- parsing

_ARROW = re.compile(r'\s*->\s*')
_ESC_RE = re.compile(r'\b([245])\.(\d{1,3})\.(\d{1,3})\b')
_SMTP_RE = re.compile(r'\b([245]\d\d)\b')
_BLOCKLIST_RE = re.compile(
    r'\b((?:[\w-]+\.)*(?:spamhaus\.org|surbl\.org|sophosxl\.(?:com|net)|spamrl\.com|'
    r'spamcop\.net|barracudacentral\.org|uceprotect\.net|sorbs\.net|'
    r'dnsbl\.[\w.-]+|rbl\.[\w.-]+))\b', re.I)
# Google says the quiet part out loud: over quota AND nobody has logged in.
_INACTIVE_RE = re.compile(r'inactive|not been accessed|dormant|abandoned', re.I)

_PROVIDERS = [
    ("microsoft", re.compile(r'RESOLVER\.|STOREDRV\.|TRANSPORT\.RULES|TenantInbound|'
                             r'protection\.outlook\.com|\bATTR\d+\b|outlook\.com|'
                             r'office365|exchangelabs', re.I)),
    ("google", re.compile(r'gsmtp\b|googlemail|google\.com|gmail-smtp|aspmx\.l\.google', re.I)),
    ("proofpoint", re.compile(r'proofpoint|pphosted', re.I)),
    ("mimecast", re.compile(r'mimecast', re.I)),
    ("barracuda", re.compile(r'barracuda', re.I)),
    ("sophos", re.compile(r'sophos|XGEMAIL', re.I)),
    ("cloudmark", re.compile(r'cloudmark', re.I)),
    ("yahoo", re.compile(r'yahoo|yahoodns', re.I)),
    ("apple", re.compile(r'icloud|apple\.com', re.I)),
]


def split_layers(text):
    """Return (wrapper, remote).

    Half of real bounce text is a relay's summary, an arrow, then the remote
    server's own words:

        5.1.351 Remote server returned unknown recipient or mailbox unavailable
          -> 550 Requested action not taken; Reject due to policy restrictions.

    The wrapper is Exchange guessing. The remote half is what happened.
    """
    if "->" not in text:
        return "", text
    parts = _ARROW.split(text)
    return parts[0].strip(), parts[-1].strip()


def find_provider(text):
    for name, rx in _PROVIDERS:
        if rx.search(text):
            return name
    return ""


# Operators run many hostnames. uri.cal1.sophosxl.com and uri.vir1.sophosxl.com
# are one listing to deal with, not two, so report the operator.
_BL_OPERATOR = [
    (re.compile(r'spamhaus', re.I), "Spamhaus"),
    (re.compile(r'surbl', re.I), "SURBL"),
    (re.compile(r'sophosxl', re.I), "Sophos XL"),
    (re.compile(r'spamrl', re.I), "SpamRL"),
    (re.compile(r'spamcop', re.I), "SpamCop"),
    (re.compile(r'barracuda', re.I), "Barracuda"),
    (re.compile(r'uceprotect', re.I), "UCEPROTECT"),
    (re.compile(r'sorbs', re.I), "SORBS"),
    (re.compile(r'invaluement', re.I), "Invaluement"),
    (re.compile(r'gbudb', re.I), "GBUdb"),
]

BL_URLS = {
    "Spamhaus": "https://check.spamhaus.org/",
    "SURBL": "https://surbl.org/surbl-analysis",
    "SpamCop": "https://www.spamcop.net/bl.shtml",
    "Barracuda": "https://www.barracudacentral.org/lookups",
    "UCEPROTECT": "https://www.uceprotect.net/en/rblcheck.php",
    "SORBS": "https://www.sorbs.net/lookup.shtml",
}


def find_blocklist(text):
    """Named blocklists, as operator names rather than raw hostnames."""
    seen, out = set(), []
    for m in _BLOCKLIST_RE.finditer(text):
        host = m.group(1).lower().strip(".")
        name = next((n for rx, n in _BL_OPERATOR if rx.search(host)), host)
        if name not in seen:
            seen.add(name)
            out.append(name)
    if not out and re.search(r'\bDBL\b', text):
        out.append("Spamhaus")
    return ";".join(out)


def classify(text, recipient_host=""):
    """Classify one bounce message. Returns a dict; never raises."""
    text = (text or "").strip()
    esc = smtp = None
    provider = blocklist = ""

    if text:
        wrapper, remote = split_layers(text)
        provider = find_provider(text)
        blocklist = find_blocklist(text)
        # Read codes from the remote half first; the wrapper's code is the
        # relay describing itself, not the rejection.
        esc = _ESC_RE.search(remote) or _ESC_RE.search(wrapper) or _ESC_RE.search(text)
        smtp = _SMTP_RE.search(remote) or _SMTP_RE.search(text)

        hit = None
        # Two orderings at once. Across tiers the better kind of signal wins
        # wherever it sits. Within a tier the remote half wins, because it is
        # the server that actually refused the mail.
        for _tier, rules in RULES_BY_TIER:
            for candidate in (remote, text):
                if not candidate:
                    continue
                for rule in rules:
                    if rule.rx.search(candidate):
                        hit = rule
                        break
                if hit:
                    break
            if hit:
                break
    else:
        hit = None

    reason = hit.reason if hit else ("empty" if not text else "unknown")
    detail = hit.detail if hit else ""

    # A full mailbox that the receiver also calls inactive is not a mailbox
    # that will drain. It is an account nobody opens any more.
    if reason == "mailbox_full" and text:
        permanent = bool(re.search(r'\b5\.2\.2\b', text)) or (
            smtp and smtp.group(1).startswith("5"))
        if permanent and _INACTIVE_RE.search(text):
            reason = "mailbox_full_abandoned"
            detail = "permanently over quota and the receiver calls it inactive"

    meaning, category, action = REASONS[reason]
    return {
        "reason": reason,
        "meaning": meaning,
        "category": category,
        "action": action,
        "detail": detail,
        "rejected_by": provider or (blocklist.split(";")[0] if blocklist else ""),
        "recipient_host": recipient_host or "",
        "smtp_code": smtp.group(1) if smtp else "",
        "status_code": ".".join(esc.groups()) if esc else "",
        "blocklist": blocklist,
        "confidence": CONFIDENCE.get(hit.tier, "none") if hit else "none",
        "_tier": hit.tier if hit else "",
    }


FIELDS = ["bounce_reason", "bounce_meaning", "bounce_category", "bounce_action",
          "bounce_detail", "rejected_by", "recipient_host", "smtp_code",
          "status_code", "blocklist", "confidence"]

_KEY = {"bounce_reason": "reason", "bounce_meaning": "meaning",
        "bounce_category": "category", "bounce_action": "action",
        "bounce_detail": "detail", "rejected_by": "rejected_by",
        "recipient_host": "recipient_host", "smtp_code": "smtp_code",
        "status_code": "status_code", "blocklist": "blocklist",
        "confidence": "confidence"}


# ---------------------------------------------------- finding the right column

_BOUNCE_NAMES = ("bounce_msg", "bounce_message", "bounce_reason", "bounce_text",
                 "bounce_description", "diagnostic_code", "diagnostic-code",
                 "smtp_response", "error_message", "failure_reason", "reason",
                 "error", "message", "description", "response", "detail")
_HOST_NAMES = ("mx", "recipient_host", "provider", "esp", "mail_provider",
               "recipient_provider", "recp_provider", "mx_provider")
_EMAIL_NAMES = ("email", "recipient", "to", "address", "email_address", "lead_email")
_DATE_NAMES = ("last_sent_at", "sent_at", "sent", "date", "sent_date",
               "modified_at", "bounced_at", "created_at", "timestamp")

_LOOKS_LIKE_BOUNCE = re.compile(
    r'\b[245]\.\d{1,3}\.\d{1,3}\b|\b[245]\d\d\b|'
    r'mailbox|recipient|undeliverable|spam|blocked|quota|smtp|relay|rejected',
    re.I)
_ISO_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}')


def detect_columns(fieldnames, rows):
    """Work out which columns hold the bounce text, the host and the date.

    Names alone are unreliable -- every sequencer invents its own schema -- so
    the bounce column is chosen by scoring what the values actually look like,
    with the name only breaking ties.
    """
    found = {"bounce": None, "host": None, "email": None, "date": None}
    lower = {f: f.strip().lower() for f in fieldnames}

    best, best_score = None, 0.0
    named = None
    for f in fieldnames:
        if lower[f] in _BOUNCE_NAMES and named is None:
            named = f
        vals = [(r.get(f) or "").strip() for r in rows]
        vals = [v for v in vals if v]
        if not vals:
            continue
        hits = sum(1 for v in vals if _LOOKS_LIKE_BOUNCE.search(v))
        avg_len = sum(len(v) for v in vals) / len(vals)
        score = (hits / len(vals)) * min(avg_len / 25.0, 2.0)
        if lower[f] in _BOUNCE_NAMES:
            score += 1.0
        if score > best_score:
            best, best_score = f, score
    if best_score >= 0.35:
        found["bounce"] = best
    elif named:
        # Scoring found nothing, but a column is named like bounce text. On a
        # full lead export most rows never bounced, so a sample of the first
        # few hundred can be entirely blank while the column is still right.
        found["bounce"] = named

    for f in fieldnames:
        vals = [(r.get(f) or "").strip() for r in rows if (r.get(f) or "").strip()]
        if not vals:
            continue
        if found["host"] is None and (
                lower[f] in _HOST_NAMES
                or sum(1 for v in vals if v.upper() in
                       ("GOOGLE_WORKSPACE", "MICROSOFT365", "REGULAR_ACCOUNT")) > len(vals) / 2):
            found["host"] = f
        if found["email"] is None and (
                lower[f] in _EMAIL_NAMES
                or sum(1 for v in vals if "@" in v) > len(vals) * 0.8):
            found["email"] = f
        if found["date"] is None and (
                lower[f] in _DATE_NAMES
                and sum(1 for v in vals if _ISO_DATE.match(v)) > len(vals) / 2):
            found["date"] = f
    return found


# ------------------------------------------------------------------- the report

BANNER = """                      │
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
                   v{version}"""


def _bar(frac, width=22):
    return "#" * int(round(frac * width)) + "." * (width - int(round(frac * width)))


def build_report(stats, source_name):
    """A markdown diagnosis. Written to be read by a person who wants to know
    what to do, not by someone auditing a classifier."""
    total = stats["total"]
    cat = stats["category"]
    out = []
    w = out.append

    period = ""
    if stats["dates"]:
        period = f" - {min(stats['dates'])} to {max(stats['dates'])}"
    w("```")
    w(BANNER.format(version=__version__))
    w("```")
    w("")
    w(f"# Bounce diagnosis: {source_name}")
    w("")
    w(f"{total:,} bounces analysed{period}")
    w("")

    # --- verdict ---------------------------------------------------------
    yours = cat[REPUTATION] + cat[AUTH] + cat[CONTENT]
    theirs = cat[DATA] + cat[RECIPIENT]
    w("## Verdict")
    w("")
    if total == 0:
        w("No bounce text found.")
        return "\n".join(out)
    if yours > theirs:
        w(f"**Your sending is the problem, not your list.** "
          f"{yours/total*100:.0f}% of these bounces are receivers refusing "
          f"your domains, your authentication or your copy. Only "
          f"{theirs/total*100:.0f}% are bad addresses.")
        w("")
        w("Cleaning the list will not fix this. Cutting volume, fixing "
          "authentication and getting delisted will.")
    elif theirs > yours * 2:
        w(f"**Your list is the problem.** {theirs/total*100:.0f}% of these "
          f"bounces are addresses that do not exist or cannot receive mail. "
          f"Sending infrastructure looks healthy.")
    else:
        w(f"**Split problem.** {yours/total*100:.0f}% sending-side, "
          f"{theirs/total*100:.0f}% list-side. Fix the sending side first; "
          f"bad addresses are cheap by comparison.")
    w("")

    # --- categories ------------------------------------------------------
    w("## Where the bounces come from")
    w("")
    w("| What | Bounces | Share | |")
    w("|---|---:|---:|---|")
    for k, v in cat.most_common():
        if v:
            w(f"| {k} | {v:,} | {v/total*100:.1f}% | `{_bar(v/total)}` |")
    w("")

    # --- who rejected ----------------------------------------------------
    if stats["rejected_by"]:
        w("## Who is rejecting you")
        w("")
        w("| Rejected by | Bounces | Share |")
        w("|---|---:|---:|")
        for k, v in stats["rejected_by"].most_common(8):
            w(f"| {k} | {v:,} | {v/total*100:.1f}% |")
        w("")

    # --- host comparison -------------------------------------------------
    if len(stats["by_host"]) > 1:
        w("## By recipient mail host")
        w("")
        w("| Host | Bounces | Sending-side |")
        w("|---|---:|---:|")
        for host, c in stats["by_host"].most_common(6):
            yc = stats["host_yours"][host]
            w(f"| {host} | {c:,} | {yc/c*100:.0f}% |")
        w("")
        w("A large gap between hosts is a placement signal. Same copy and the "
          "same mailboxes reaching one provider and not another points at "
          "reputation with that provider, not at your data.")
        w("")

    # --- blocklists ------------------------------------------------------
    if stats["blocklist"]:
        w("## Blocklists naming you")
        w("")
        for bl, n in stats["blocklist"].most_common(10):
            url = BL_URLS.get(bl, "")
            w(f"- **{bl}** - {n:,} bounces" + (f" - {url}" if url else ""))
        w("")
        w("Every one of these is costing you delivery on every send until "
          "it is resolved.")
        w("")

    # --- worst sending domains -------------------------------------------
    if stats["by_sender"]:
        rows = [(d, c, stats["sender_yours"][d]) for d, c in stats["by_sender"].items()
                if c >= max(20, total * 0.002)]
        rows.sort(key=lambda r: (-r[2] / r[1], -r[1]))
        if rows:
            w("## Worst sending domains")
            w("")
            w("| Sending domain | Bounces | Sending-side |")
            w("|---|---:|---:|")
            for d, c, y in rows[:10]:
                w(f"| {d} | {c:,} | {y/c*100:.0f}% |")
            w("")

    # --- trend -----------------------------------------------------------
    if len(stats["by_date"]) >= 4:
        w("## Trend")
        w("")
        days = sorted(stats["by_date"])
        half = len(days) // 2
        early = sum(stats["by_date"][d] for d in days[:half])
        late = sum(stats["by_date"][d] for d in days[half:])
        ey = sum(stats["date_yours"][d] for d in days[:half])
        ly = sum(stats["date_yours"][d] for d in days[half:])
        w(f"| Period | Days | Bounces | Sending-side |")
        w(f"|---|---:|---:|---:|")
        w(f"| {days[0]} to {days[half-1]} | {half} | {early:,} | "
          f"{ey/max(early,1)*100:.0f}% |")
        w(f"| {days[half]} to {days[-1]} | {len(days)-half} | {late:,} | "
          f"{ly/max(late,1)*100:.0f}% |")
        w("")
        if late > early * 1.3:
            w(f"Bounces are **rising**: {late/max(early,1):.1f}x more in the "
              f"second half of this window.")
        elif early > late * 1.3:
            w(f"Bounces are **falling**: {early/max(late,1):.1f}x fewer in the "
              f"second half of this window.")
        else:
            w("Volume is broadly flat across the window.")
        w("")
        peak = max(stats["by_date"], key=lambda d: stats["by_date"][d])
        w(f"Worst single day: **{peak}** with {stats['by_date'][peak]:,} bounces.")
        w("")

    # --- what to do ------------------------------------------------------
    w("## Do this first")
    w("")
    n = 1
    if stats["blocklist"]:
        hits = sum(stats["blocklist"].values())
        w(f"{n}. **Get delisted.** {hits:,} bounces cite a public blocklist. "
          f"Nothing else you change matters while that stands.")
        n += 1
    if cat[AUTH]:
        w(f"{n}. **Fix authentication.** {cat[AUTH]:,} bounces are SPF, DKIM, "
          f"DMARC or PTR failures. This is a DNS change, not a warming problem "
          f"- it can be done today.")
        n += 1
    if stats["action"][PAUSE]:
        w(f"{n}. **Pause the worst domains.** {stats['action'][PAUSE]:,} bounces "
          f"are receivers refusing your sending identity. Continuing to send "
          f"deepens it.")
        n += 1
    if stats["action"][SUPPRESS]:
        w(f"{n}. **Suppress {stats['action'][SUPPRESS]:,} addresses** that will "
          f"never accept mail. Use --suppress-list to export them.")
        n += 1
    if cat[CONTENT]:
        w(f"{n}. **Rewrite the copy.** {cat[CONTENT]:,} bounces are filters "
          f"judging the message rather than the sender.")
        n += 1
    if stats["unknown"]:
        w(f"{n}. {stats['unknown']:,} bounces could not be read. "
          f"Use --dump-unknown to see them.")
    w("")
    w("---")
    w(f"Generated by bouncesitrep {__version__}")
    return "\n".join(out)


# ------------------------------------------------------------------------ CLI

def run_one(text, as_json):
    r = classify(text)
    if as_json:
        import json
        print(json.dumps({k: v for k, v in r.items() if not k.startswith("_")}, indent=2))
        return 0
    print(f"  {r['meaning']}")
    print()
    print(f"  reason      {r['reason']}")
    print(f"  category    {r['category']}")
    print(f"  action      {r['action']}")
    print(f"  confidence  {r['confidence']}")
    for label, key in (("why", "detail"), ("rejected by", "rejected_by"),
                       ("smtp", "smtp_code"), ("status", "status_code"),
                       ("blocklist", "blocklist")):
        if r[key]:
            print(f"  {label:11} {r[key]}")
    return 0


def run_csv(path, args):
    csv.field_size_limit(2 ** 31 - 1)
    outdir = os.path.expanduser(args.outdir) if args.outdir \
        else os.path.dirname(os.path.abspath(path))
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(path))[0]
    out_path = os.path.join(outdir, f"{base} - classified.csv")
    if os.path.exists(out_path) and not args.force:
        print(f"{os.path.basename(out_path)} exists (use --force)", file=sys.stderr)
        return 1

    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            print(f"{path}: empty file", file=sys.stderr)
            return 1
        sample = []
        for i, row in enumerate(reader):
            sample.append(row)
            if i >= 199:
                break
        cols = detect_columns(reader.fieldnames, sample)

    bounce_col = args.column or cols["bounce"]
    if not bounce_col:
        print(f"{path}: could not find a bounce-text column. Pass --column.\n"
              f"  columns: {', '.join(reader.fieldnames[:15])}", file=sys.stderr)
        return 1
    if bounce_col not in reader.fieldnames:
        print(f"{path}: no column '{bounce_col}'", file=sys.stderr)
        return 1
    host_col = args.host_column or cols["host"]
    date_col = cols["date"]

    say(f"  [ bounce sitrep v{__version__} ]")
    say(f"  reading '{bounce_col}'"
        + (f", host from '{host_col}'" if host_col else "")
        + (f", dates from '{date_col}'" if date_col else ""))

    stats = {
        "total": 0, "unknown": 0, "empty": 0, "rows": 0,
        "category": collections.Counter(), "action": collections.Counter(),
        "reason": collections.Counter(), "rejected_by": collections.Counter(),
        "blocklist": collections.Counter(), "confidence": collections.Counter(),
        "by_host": collections.Counter(), "host_yours": collections.Counter(),
        "by_sender": collections.Counter(), "sender_yours": collections.Counter(),
        "by_date": collections.Counter(), "date_yours": collections.Counter(),
        "dates": [],
    }
    for c in (DATA, REPUTATION, AUTH, CONTENT, RECIPIENT, TRANSIENT, UNKNOWN):
        stats["category"][c] += 0
    for a in (SUPPRESS, RETRY, RETRY_ONCE, PAUSE, FIXAUTH, REWRITE, REVIEW):
        stats["action"][a] += 0

    suppress, unknowns = [], []
    email_col = cols["email"]
    sender_col = next((f for f in reader.fieldnames
                       if f.strip().lower() in ("email_acc_name", "sending_email",
                                                "from_email", "sender", "sdom",
                                                "sending_domain")), None)

    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh, \
            open(out_path, "w", newline="", encoding="utf-8") as out:
        reader = csv.DictReader(fh)
        writer = csv.DictWriter(out, fieldnames=reader.fieldnames + FIELDS,
                                lineterminator="\n")
        writer.writeheader()
        for row in reader:
            text = row.get(bounce_col) or ""
            host = (row.get(host_col) or "") if host_col else ""
            r = classify(text, recipient_host=host)
            row.update({f: r[_KEY[f]] for f in FIELDS})
            writer.writerow(row)

            stats["rows"] += 1
            # A row with no bounce text is not a bounce. Counting it as
            # "unknown" makes a healthy run look like a 97% failure, which is
            # exactly what a full lead export looks like next to a bounce one.
            if r["reason"] == "empty":
                stats["empty"] += 1
                continue
            stats["total"] += 1
            stats["category"][r["category"]] += 1
            stats["action"][r["action"]] += 1
            stats["reason"][r["reason"]] += 1
            stats["confidence"][r["confidence"]] += 1
            mine = r["category"] in (REPUTATION, AUTH, CONTENT)
            if r["rejected_by"]:
                stats["rejected_by"][r["rejected_by"]] += 1
            for bl in filter(None, r["blocklist"].split(";")):
                stats["blocklist"][bl] += 1
            if host:
                stats["by_host"][host] += 1
                stats["host_yours"][host] += 1 if mine else 0
            if sender_col:
                sd = (row.get(sender_col) or "").strip().lower()
                sd = sd.rsplit("@", 1)[-1] if "@" in sd else sd
                if sd:
                    stats["by_sender"][sd] += 1
                    stats["sender_yours"][sd] += 1 if mine else 0
            if date_col:
                d = (row.get(date_col) or "")[:10]
                if _ISO_DATE.match(d):
                    stats["by_date"][d] += 1
                    stats["date_yours"][d] += 1 if mine else 0
                    stats["dates"].append(d)
            if r["reason"] in ("unknown", "undefined") and text.strip():
                stats["unknown"] += 1
                unknowns.append(text)
            if r["action"] == SUPPRESS and email_col:
                addr = (row.get(email_col) or "").strip()
                if "@" in addr:
                    suppress.append(addr)

    total = max(stats["total"], 1)
    say(f"  {stats['rows']:,} rows -> {os.path.basename(out_path)}")
    if stats["empty"]:
        share = stats["empty"] / max(stats["rows"], 1) * 100
        say(f"    {stats['empty']:,} rows ({share:.0f}%) had no bounce text and "
            f"were skipped")
        if share > 50:
            say("    that usually means the export is all your leads rather "
                "than just the bounced ones")
    say(f"    {stats['total']:,} bounces classified:")
    for c, v in stats["category"].most_common():
        if v:
            say(f"      {c:15} {v:>8,}  ({v/total*100:5.1f}%)")

    if args.suppress_list and suppress:
        seen, uniq = set(), []
        for a in suppress:
            k = a.lower()
            if k not in seen:
                seen.add(k)
                uniq.append(a)
        with open(args.suppress_list, "w", encoding="utf-8") as fh:
            fh.write("\n".join(uniq) + "\n")
        say(f"    {len(uniq):,} addresses -> {args.suppress_list}")
    elif args.suppress_list and not email_col:
        print("  no email column found, cannot write a suppression list",
              file=sys.stderr)

    if args.dump_unknown and unknowns:
        with open(args.dump_unknown, "w", encoding="utf-8") as fh:
            for u in unknowns:
                fh.write(" ".join(u.split()) + "\n")
        say(f"    {len(unknowns):,} unreadable -> {args.dump_unknown}")

    if args.report:
        rp = args.report if isinstance(args.report, str) else \
            os.path.join(outdir, f"{base} - diagnosis.md")
        with open(rp, "w", encoding="utf-8") as fh:
            fh.write(build_report(stats, os.path.basename(path)) + "\n")
        say(f"    diagnosis -> {os.path.basename(rp)}")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Read bounce text from a sequencer export and say what is wrong.")
    ap.add_argument("input", help="a bounce message, or a path to a CSV export")
    ap.add_argument("-c", "--column", help="bounce-text column (default: detect)")
    ap.add_argument("--host-column", help="recipient mail host column (default: detect)")
    ap.add_argument("-o", "--outdir", help="output directory")
    ap.add_argument("--report", nargs="?", const=True, metavar="FILE",
                    help="write a markdown diagnosis")
    ap.add_argument("--suppress-list", metavar="FILE",
                    help="write addresses that should never be mailed again")
    ap.add_argument("--dump-unknown", metavar="FILE",
                    help="write every message it could not read")
    ap.add_argument("--json", action="store_true", help="JSON output for one message")
    ap.add_argument("--force", action="store_true", help="overwrite existing output")
    ap.add_argument("-q", "--quiet", action="store_true", help="report only errors")
    ap.add_argument("--version", action="version", version=f"bouncesitrep {__version__}")
    args = ap.parse_args()

    global QUIET
    QUIET = args.quiet

    path = os.path.expanduser(args.input)
    # Anything ending .csv/.tsv was meant to be a file. No bounce message ever
    # ends that way, so a missing one is a typo, not something to classify --
    # silently treating the path as bounce text sends you looking in the wrong
    # place entirely.
    if path.lower().endswith((".csv", ".tsv")):
        if os.path.isdir(path):
            print(f"{args.input}: is a directory, not a file", file=sys.stderr)
            return 1
        if not os.path.isfile(path):
            print(f"{args.input}: no such file", file=sys.stderr)
            return 1
        return run_csv(path, args)
    return run_one(args.input, args.json)


if __name__ == "__main__":
    sys.exit(main())
