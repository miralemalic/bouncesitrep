#!/usr/bin/env python3
"""Read a bounce export. Report whose problem it is.

  bouncesitrep export.csv                  finds the bounce column itself
  bouncesitrep export.csv --report         writes a markdown diagnosis
  bouncesitrep export.csv --suppress-list dead.txt
  bouncesitrep "550 5.1.1 user unknown"    one message

Bounce tools sort mail into hard and soft. That is no use at 9am with four
thousand overnight bounces in front of you. The question is whose problem it
is: your list, your domains, your DNS, or your copy.

Takes bounce text as sequencers expose it. For whole RFC5322 bounce mail, use
sisimai (https://libsisimai.org).

Standard library only. Inputs are never modified.
"""

import argparse
import collections
import csv
import os
import re
import sys

__version__ = "2.1.0"

QUIET = False


# ---------------------------------------------------------------- the console
#
# Colour only when a person is looking. Piped output stays plain so it can be
# grepped. Windows 10 speaks ANSI once asked; older consoles do not, and get
# plain text instead of a screen of escape codes.

def _colour_ok():
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        return False
    if os.name == "nt":
        try:
            import ctypes
            h = ctypes.windll.kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                return False
            # 0x0004 is ENABLE_VIRTUAL_TERMINAL_PROCESSING
            return bool(ctypes.windll.kernel32.SetConsoleMode(h, mode.value | 4))
        except Exception:
            return False
    return True


COLOUR = _colour_ok()

_C = {"dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m",
      "cyan": "\033[36m", "red": "\033[31m", "yellow": "\033[33m",
      "green": "\033[32m", "blue": "\033[34m", "grey": "\033[90m"}


def paint(text, *names):
    """Colour the text, or hand it back untouched when colour is off."""
    if not COLOUR:
        return text
    return "".join(_C[n] for n in names) + text + _C["off"]


def _unicode_ok():
    """Can this console print the block banner?

    A legacy Windows code page raises UnicodeEncodeError on these characters.
    Crashing over decoration is not acceptable.
    """
    enc = getattr(sys.stdout, "encoding", None) or ""
    try:
        "\u2588\u2500\u2502\u256d".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError, TypeError):
        return False


UNICODE = _unicode_ok()


def say(*a, **k):
    if not QUIET:
        print(*a, **k)


# ------------------------------------------------------------- what we output

# Category answers "whose problem is it". Each one lands on a different desk.
# Reputation and authentication are split because one is weeks of warming and
# the other is a DNS record you fix before lunch.
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
# The plain English column is what lets someone read the export without
# knowing what 5.7.133 means. That is most people who will open it.
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

# Precedence. Lower wins. Machine tokens beat prose: a program emitted the
# token, an admin typed the prose, sometimes years ago and sometimes wrong.
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
    # Yahoo and AOL bracket a short code into the text. TS/TSS are throttles,
    # not refusals. A dashboard showing only 4xx-vs-5xx loses that.
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
    """Split "relay summary -> remote reply" into its two halves.

    Half of real bounce text arrives like this:

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
# are one listing to clear, not two. Report the operator.
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
    """Named blocklists, reported as operators rather than hostnames."""
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
    """Classify one message. Returns a dict. Never raises."""
    text = (text or "").strip()
    esc = smtp = None
    provider = blocklist = ""

    if text:
        wrapper, remote = split_layers(text)
        provider = find_provider(text)
        blocklist = find_blocklist(text)
        # Read codes from the remote half first. The wrapper's code describes
        # the relay, not the rejection.
        esc = _ESC_RE.search(remote) or _ESC_RE.search(wrapper) or _ESC_RE.search(text)
        smtp = _SMTP_RE.search(remote) or _SMTP_RE.search(text)

        hit = None
        # Two orderings at once. Across tiers, the better kind of signal wins
        # wherever it sits. Within a tier, the remote half wins: that is the
        # server that actually refused the mail.
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

    # A full mailbox the receiver also calls inactive will not drain. Nobody
    # opens that account any more.
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
    """Find the bounce text, host and date columns.

    Every sequencer invents its own schema, so score the values rather than
    trust the headings. Names only break ties.
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
        # Scoring found nothing, but a column is named like bounce text. Most
        # rows in a lead export never bounced, so the first few hundred can be
        # blank while the column is still the right one.
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

# Same mark in plain ASCII, for a console that cannot encode the blocks above.
BANNER_ASCII = """                      |
                      |
                      |
                   #######
                 ##   |   ##
                ##    |    ##
             ---#-----O-----#---
                ##    |    ##
                 ##   |   ##
                   #######
                      |
                      |
                      |

        B O U N C E   S I T R E P
                   v{version}"""


def banner(version):
    """The mark, in a character set this console can print."""
    return (BANNER if UNICODE else BANNER_ASCII).format(version=version)


# How much trouble each category means, and therefore its colour.
CAT_COLOUR = {REPUTATION: "red", AUTH: "yellow", CONTENT: "yellow",
              DATA: "cyan", RECIPIENT: "blue", TRANSIENT: "grey",
              UNKNOWN: "grey"}


def _bar(frac, width=22):
    return "#" * int(round(frac * width)) + "." * (width - int(round(frac * width)))


def _verdict(stats, total):
    """Name the problem, sized to the situation.

    Nine of these, not three. "Sending-side" covers a domain on Spamhaus, a
    typo in an SPF record, and copy that trips filters. Three different
    mornings.
    """
    cat, reason = stats["category"], stats["reason"]
    yours = cat[REPUTATION] + cat[AUTH] + cat[CONTENT]
    theirs = cat[DATA] + cat[RECIPIENT]
    pct = lambda n: n / total * 100
    w = ["## Verdict", ""]

    blocked = reason.get("blocklisted", 0)
    auth = cat[AUTH]
    content = cat[CONTENT]
    dead = reason.get("user_unknown", 0) + reason.get("host_unknown", 0)
    abandoned = reason.get("mailbox_full_abandoned", 0) + reason.get("suspended", 0)
    walled = reason.get("restricted_recipient", 0)

    if blocked and pct(blocked) >= 25:
        w += [f"**You are on a blocklist.** {blocked:,} of these bounces "
              f"({pct(blocked):.0f}%) name one outright.",
              "",
              "Nothing else in this report matters until that is cleared. While "
              "a listing stands, every provider that consults it is refusing you "
              "before your copy is ever read, and the domains keep aging badly "
              "the whole time."]
    elif auth and pct(auth) >= 25:
        w += [f"**Your authentication is broken, and that is good news.** "
              f"{auth:,} bounces ({pct(auth):.0f}%) are SPF, DKIM, DMARC or PTR "
              f"failures.",
              "",
              "This is the cheapest problem on the list. It is a DNS record, not "
              "a reputation you have to earn back over weeks. Fix the records "
              "and these stop the same day."]
    elif content and pct(content) >= 30:
        w += [f"**The message is the problem, not the sender.** {content:,} "
              f"bounces ({pct(content):.0f}%) are filters judging the content.",
              "",
              "Your domains are being accepted; what you wrote is not. Look at "
              "the links, the attachments and the phrasing before you touch "
              "anything to do with sending."]
    elif yours > theirs:
        w += [f"**Your sending is the problem, not your list.** "
              f"{pct(yours):.0f}% of these bounces are receivers refusing your "
              f"domains, your authentication or your copy. Only "
              f"{pct(theirs):.0f}% are addresses that do not work.",
              "",
              "Cleaning the list will not move this number. Cutting volume, "
              "fixing authentication and getting delisted will."]
    elif walled and pct(walled) >= 20:
        w += [f"**A lot of these addresses were never reachable.** {walled:,} "
              f"({pct(walled):.0f}%) are mailboxes that only accept mail from "
              f"inside their own company.",
              "",
              "They exist, the domains are healthy, and no amount of warming "
              "will get you in. Suppress them and judge the campaign on what "
              "is left."]
    elif abandoned and pct(abandoned) >= 20:
        w += [f"**You are mailing abandoned accounts.** {abandoned:,} bounces "
              f"({pct(abandoned):.0f}%) are mailboxes the provider itself "
              f"calls full and inactive, or switched off.",
              "",
              "That is a list-age problem rather than a list-quality one. The "
              "addresses were real once. Suppress them, and treat the source "
              "they came from as older than it looks."]
    elif dead and pct(dead) >= 40:
        w += [f"**Your list is stale.** {dead:,} of these bounces "
              f"({pct(dead):.0f}%) are addresses or domains that simply do not "
              f"exist.",
              "",
              "Sending infrastructure looks healthy. This is a data problem, "
              "and it is the easy kind: suppress them, then work out which "
              "source they came from before you buy from it again."]
    elif cat[TRANSIENT] and pct(cat[TRANSIENT]) >= 40:
        w += [f"**Mostly temporary.** {pct(cat[TRANSIENT]):.0f}% of these are "
              f"deferrals rather than refusals - greylisting, throttles, "
              f"queues that gave up.",
              "",
              "There may be nothing wrong here at all. Retry and see what is "
              "left before you change anything."]
    elif cat[UNKNOWN] and pct(cat[UNKNOWN]) >= 40:
        w += [f"**No clear signal.** {pct(cat[UNKNOWN]):.0f}% of this text does "
              f"not say why delivery failed.",
              "",
              "That is usually a sequencer that truncates what the receiving "
              "server said. Run with --dump-unknown and read a few by hand "
              "before drawing conclusions."]
    elif theirs > yours * 2:
        w += [f"**Your list is the problem.** {pct(theirs):.0f}% of these "
              f"bounces are addresses that do not exist or cannot receive "
              f"mail. Sending infrastructure looks healthy."]
    else:
        w += [f"**It is split.** {pct(yours):.0f}% is your sending side, "
              f"{pct(theirs):.0f}% is your data.",
              "",
              "Fix the sending side first. Bad addresses cost you one send "
              "each; a reputation problem taxes every send you make."]
    w.append("")
    return w


def _trend(stats):
    """Rising or falling. A single total cannot say."""
    if len(stats["by_date"]) < 4:
        return []
    days = sorted(stats["by_date"])
    half = len(days) // 2
    early = sum(stats["by_date"][d] for d in days[:half])
    late = sum(stats["by_date"][d] for d in days[half:])
    ey = sum(stats["date_yours"][d] for d in days[:half])
    ly = sum(stats["date_yours"][d] for d in days[half:])

    w = ["## Trend", "",
         "| Period | Days | Bounces | Sending-side |",
         "|---|---:|---:|---:|",
         f"| {days[0]} to {days[half-1]} | {half} | {early:,} | "
         f"{ey / max(early, 1) * 100:.0f}% |",
         f"| {days[half]} to {days[-1]} | {len(days) - half} | {late:,} | "
         f"{ly / max(late, 1) * 100:.0f}% |", ""]
    if late > early * 1.3:
        w.append(f"Bounces are **rising**: {late / max(early, 1):.1f}x more in "
                 f"the second half of this window.")
    elif early > late * 1.3:
        w.append(f"Bounces are **falling**: {early / max(late, 1):.1f}x fewer in "
                 f"the second half of this window.")
    else:
        w.append("Volume is broadly flat across the window.")
    peak = max(stats["by_date"], key=lambda d: stats["by_date"][d])
    w += ["", f"Worst single day: **{peak}** with {stats['by_date'][peak]:,} "
              f"bounces.", ""]
    return w


def _next_steps(stats, cat):
    """What to do, most urgent first.

    Delisting leads: nothing else you change matters while a listing stands.
    Authentication is next, being a DNS edit rather than weeks of warming.
    """
    w = ["## Do this first", ""]
    n = 1
    if stats["blocklist"]:
        hits = sum(stats["blocklist"].values())
        w.append(f"{n}. **Get delisted.** {hits:,} bounces cite a public "
                 f"blocklist. Nothing else you change matters while that stands.")
        n += 1
    if cat[AUTH]:
        w.append(f"{n}. **Fix authentication.** {cat[AUTH]:,} bounces are SPF, "
                 f"DKIM, DMARC or PTR failures. This is a DNS change, not a "
                 f"warming problem - it can be done today.")
        n += 1
    if stats["action"][PAUSE]:
        w.append(f"{n}. **Pause the worst domains.** {stats['action'][PAUSE]:,} "
                 f"bounces are receivers refusing your sending identity. "
                 f"Continuing to send deepens it.")
        n += 1
    if stats["action"][SUPPRESS]:
        w.append(f"{n}. **Suppress {stats['action'][SUPPRESS]:,} addresses** "
                 f"that will never accept mail. Use --suppress-list to export "
                 f"them.")
        n += 1
    if cat[CONTENT]:
        w.append(f"{n}. **Rewrite the copy.** {cat[CONTENT]:,} bounces are "
                 f"filters judging the message rather than the sender.")
        n += 1
    if stats["unknown"]:
        w.append(f"{n}. {stats['unknown']:,} bounces could not be read. Use "
                 f"--dump-unknown to see them.")
    w.append("")
    return w


def build_report(stats, source_name):
    """The markdown diagnosis. Written for someone who wants to act on it,
    not audit the classifier."""
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
    if stats.get("empty"):
        rows = stats.get("rows", total)
        rate = total / max(rows, 1) * 100
        w(f"**{total:,} of {rows:,} leads bounced ({rate:.1f}%)**{period}")
        w("")
        if rate >= 5:
            w(f"A {rate:.1f}% bounce rate is high enough to be doing damage on "
              f"its own. Mailbox providers read it as a signal about you, so it "
              f"compounds: the more you bounce, the more you get filtered.")
        elif rate >= 2:
            w(f"A {rate:.1f}% bounce rate is survivable but worth pulling down. "
              f"Under 2% is where you want to be.")
        else:
            w(f"A {rate:.1f}% bounce rate is healthy.")
        w("")
    else:
        w(f"{total:,} bounces analysed{period}")
        w("")

    out += _verdict(stats, total)

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

    out += _trend(stats)

    out += _next_steps(stats, cat)

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


def sniff_delimiter(path):
    """Find the column separator.

    A .csv is not always comma separated. Excel writes semicolons across most
    of Europe, plenty of exports are tab separated, and a .tsv always is. Read
    a semicolon file as commas and you get one column named "email;bounce_msg"
    and output nobody can use. Trust the header, not the extension.
    """
    if path.lower().endswith(".tsv"):
        return "\t"
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        head = fh.readline()
    if not head.strip():
        return ","
    # Winner is whichever candidate splits the header into the most fields.
    # A comma inside a quoted heading fools a naive count, so let the csv
    # module do the splitting.
    best, best_n = ",", 0
    for cand in (",", ";", "\t", "|"):
        try:
            n = len(next(csv.reader([head], delimiter=cand)))
        except csv.Error:
            continue
        if n > best_n:
            best, best_n = cand, n
    return best


def _out_path(name, outdir):
    """A bare filename goes to the output directory. A path is left alone.

    -o ~/Desktop --suppress-list dead.txt lands on the Desktop.
    --suppress-list /tmp/dead.txt still goes to /tmp.
    """
    p = os.path.expanduser(name)
    return p if os.path.dirname(p) else os.path.join(outdir, p)


def _summarise(stats, args, out_path, total):
    """Print the run summary. False means nothing to diagnose."""
    kept = stats["rows"] if args.all_rows else stats["total"]
    arrow = "\u2192" if UNICODE else "->"
    say("")
    name = paint(os.path.basename(out_path), "bold")
    say(f"  {stats['rows']:,} rows read  {arrow}  {kept:,} written to {name}")

    if not stats["total"]:
        say(paint("  nothing in that file looks like a bounce", "yellow"))
        say("")
        return False

    # The rate needs a denominator, so it only appears when the export also
    # carried the leads that did not bounce.
    if stats["empty"]:
        rate = stats["total"] / max(stats["rows"], 1) * 100
        tint = "red" if rate >= 5 else ("yellow" if rate >= 2 else "green")
        of = paint(f"({stats['total']:,} of {stats['rows']:,} leads)", "grey")
        say(f"  {paint('%.1f%%' % rate, 'bold', tint)} bounce rate  {of}")
    say("")

    block = "\u2588" if UNICODE else "#"
    rest = "\u00b7" if UNICODE else "."
    for cat, v in stats["category"].most_common():
        if not v:
            continue
        frac = v / total
        fill = max(1, int(round(frac * 24)))
        bar = (paint(block * fill, CAT_COLOUR.get(cat, "grey"))
               + paint(rest * (24 - fill), "grey"))
        say(f"    {cat:<15} {v:>8,}  {frac * 100:5.1f}%  {bar}")
    say("")
    return True


def _write_extras(stats, args, outdir, base, path, suppress, unknowns, email_col):
    """Optional outputs: suppression list, unreadable dump, diagnosis."""
    if args.suppress_list:
        args.suppress_list = _out_path(args.suppress_list, outdir)
    if args.dump_unknown:
        args.dump_unknown = _out_path(args.dump_unknown, outdir)

    if args.suppress_list and suppress:
        # The same dead address turns up once per campaign it was mailed in.
        seen, uniq = set(), []
        for a in suppress:
            if a.lower() not in seen:
                seen.add(a.lower())
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
        rp = _out_path(args.report, outdir) if isinstance(args.report, str) \
            else os.path.join(outdir, f"{base} - diagnosis.md")
        with open(rp, "w", encoding="utf-8") as fh:
            fh.write(build_report(stats, os.path.basename(path)) + "\n")
        say(f"    diagnosis -> {os.path.basename(rp)}")


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

    delim = sniff_delimiter(path)
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh, delimiter=delim)
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

    if not (QUIET or args.no_banner):
        say(paint(banner(__version__), "cyan"))
        say("")
    shown = {",": "", ";": " (semicolon separated)", "\t": " (tab separated)",
             "|": " (pipe separated)"}[delim]
    say(f"  reading '{bounce_col}'{shown}"
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
        reader = csv.DictReader(fh, delimiter=delim)
        writer = csv.DictWriter(out, fieldnames=reader.fieldnames + FIELDS,
                                lineterminator="\n")
        writer.writeheader()
        for row in reader:
            text = row.get(bounce_col) or ""
            host = (row.get(host_col) or "") if host_col else ""
            r = classify(text, recipient_host=host)
            row.update({f: r[_KEY[f]] for f in FIELDS})
            # A whole-campaign export is mostly leads that never bounced.
            # Copying them through means scrolling past 97% blank rows to
            # reach the ones you can act on.
            if r["reason"] != "empty" or args.all_rows:
                writer.writerow(row)

            stats["rows"] += 1
            # A row with no bounce text is not a bounce. Counted as "unknown"
            # it makes a healthy run read as a 97% failure.
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
    if not _summarise(stats, args, out_path, total):
        return 0

    _write_extras(stats, args, outdir, base, path, suppress, unknowns, email_col)
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Read bounce text from a sequencer export and say what is wrong.")
    ap.add_argument("input", nargs="?",
                    help="a bounce message, or a path to a CSV export")
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
    ap.add_argument("--banner", action="store_true",
                    help="print the mark and exit")
    ap.add_argument("--no-banner", action="store_true",
                    help="skip the mark, for wrappers that drew it already")
    ap.add_argument("--all-rows", action="store_true",
                    help="keep every row in the output, not just the bounces")
    ap.add_argument("--force", action="store_true", help="overwrite existing output")
    ap.add_argument("-q", "--quiet", action="store_true", help="report only errors")
    ap.add_argument("--version", action="version", version=f"bouncesitrep {__version__}")
    args = ap.parse_args()

    global QUIET
    QUIET = args.quiet

    if args.banner:
        print(paint(banner(__version__), "cyan"))
        return 0
    if args.input is None:
        ap.error("give it a CSV export or a single bounce message")

    path = os.path.expanduser(args.input)
    # Anything ending .csv/.tsv was meant to be a file. No bounce message ends
    # that way, so a missing one is a typo. Classifying the path as bounce text
    # would send you looking in entirely the wrong place.
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
