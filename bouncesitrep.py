#!/usr/bin/env python3
# Copyright (C) 2026 miralemalic
# SPDX-License-Identifier: MIT

"""Read a bounce export and report whose problem it is.

    bouncesitrep export.csv                  find the bounce column itself
    bouncesitrep export.csv --report         write a markdown diagnosis
    bouncesitrep export.csv --suppress-list dead.txt --pause-list pause.txt
    bouncesitrep '550 5.1.1 user unknown'    classify one message
    bouncesitrep --reasons                   every answer it can give

Bounce tools sort mail into hard and soft, which is no help at 9am with four
thousand overnight bounces to get through.  What you need to know is whose
problem each one is: your list, your domains, your DNS, or your copy.

The input is bounce text as sequencers expose it.  For whole RFC 5322 bounce
messages, use sisimai (https://libsisimai.org) instead.

Standard library only.  Input files are never modified.
"""

import os
import re
import csv
import sys
import json
import argparse
import itertools
import collections


__version__ = '2.2.0'

__all__ = [
    'build_report',
    'classify',
    'detect_columns',
    'main',
    'run_csv',
    'split_layers',
    ]


NL = '\n'
SPACE = ' '
EMPTYSTRING = ''
SEMICOLON = ';'
COMMASPACE = ', '

# Set by -q.
QUIET = False


# Colour only when a person is reading.  Piped output stays plain so it can
# still be grepped.  Windows 10 consoles understand ANSI escapes once asked;
# older ones don't, and get plain text rather than a screen of escape codes.

def _colour_ok():
    if os.environ.get('NO_COLOR') or os.environ.get('TERM') == 'dumb':
        return False
    if not (hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()):
        return False
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            # 4 is ENABLE_VIRTUAL_TERMINAL_PROCESSING.
            return bool(kernel32.SetConsoleMode(handle, mode.value | 4))
        except Exception:
            return False
    return True


COLOUR = _colour_ok()

ESCAPES = {
    'dim': '\033[2m',
    'bold': '\033[1m',
    'off': '\033[0m',
    'cyan': '\033[36m',
    'red': '\033[31m',
    'yellow': '\033[33m',
    'green': '\033[32m',
    'blue': '\033[34m',
    'grey': '\033[90m',
    }


def paint(text, *names):
    """Return text in the named colours, or untouched when colour is off."""
    if not COLOUR:
        return text
    start = EMPTYSTRING.join(ESCAPES[name] for name in names)
    return start + text + ESCAPES['off']


def _unicode_ok():
    # A legacy Windows code page can't encode the block characters in the
    # banner, and printing them would raise UnicodeEncodeError.
    encoding = getattr(sys.stdout, 'encoding', None) or ''
    try:
        '\u2588\u2500\u2502\u256d'.encode(encoding)
    except (UnicodeEncodeError, LookupError, TypeError):
        return False
    return True


UNICODE = _unicode_ok()


def say(*args, **kws):
    if not QUIET:
        print(*args, **kws)


# Categories answer "whose problem is it?" and each one lands on a different
# desk.  Reputation and authentication are kept apart because one takes weeks
# of warming and the other is a DNS record you can fix before lunch.
DATA = 'data'                       # the address is dead or wrong
REPUTATION = 'reputation'           # your sending identity is refused
AUTH = 'authentication'             # SPF, DKIM, DMARC or PTR is broken
CONTENT = 'content'                 # the message itself tripped a filter
RECIPIENT = 'recipient'             # their mailbox refuses everyone
TRANSIENT = 'transient'             # nobody's fault, try again later
UNKNOWN = 'unknown'

CATEGORIES = (DATA, REPUTATION, AUTH, CONTENT, RECIPIENT, TRANSIENT, UNKNOWN)
SENDING_SIDE = (REPUTATION, AUTH, CONTENT)

# Actions answer "what now?"
SUPPRESS = 'suppress'               # never mail this address again
RETRY = 'retry_later'               # safe to try again
RETRY_ONCE = 'retry_once'           # one more attempt, then give up
PAUSE = 'pause_domain'              # stop the sending domain now
FIXAUTH = 'fix_auth'                # fixable today, in DNS
REWRITE = 'rewrite_copy'            # the words are the problem
REVIEW = 'review'                   # classified, but look at it yourself

ACTIONS = (SUPPRESS, RETRY, RETRY_ONCE, PAUSE, FIXAUTH, REWRITE, REVIEW)

# reason -> (meaning, category, action).  The meaning is what lets somebody
# who has never heard of 5.7.133 read the export, and that is most of the
# people who will open it.
REASONS = {
    'user_unknown': (
        'The address does not exist', DATA, SUPPRESS),
    'host_unknown': (
        'The domain does not exist or has no mail server', DATA, SUPPRESS),
    'no_relaying': (
        'That server does not handle mail for this address', DATA, SUPPRESS),
    'syntax_error': (
        'The address is malformed', DATA, SUPPRESS),
    'ambiguous_address': (
        'The address matches more than one mailbox at the receiver',
        DATA, REVIEW),
    'sender_address_bad': (
        'Your own return address is malformed or its domain will not '
        'accept mail',
        AUTH, FIXAUTH),
    'protocol_error': (
        'The two servers could not agree on how to hand the message over',
        TRANSIENT, RETRY),
    'media_error': (
        "The receiver cannot handle the message's format or encoding",
        CONTENT, REVIEW),
    'crypto_error': (
        'TLS or message signing failed between the servers', AUTH, REVIEW),
    'list_expansion': (
        'The address is a mailing list the receiver would not expand',
        RECIPIENT, REVIEW),
    'throttled': (
        'The receiver is deferring you for sending too fast or drawing '
        'complaints',
        REPUTATION, RETRY),
    'has_moved': (
        'The address has moved and forwarding is off', DATA, SUPPRESS),

    'mailbox_full_abandoned': (
        'Mailbox is full and inactive - nobody is reading it', DATA, SUPPRESS),
    'mailbox_full': (
        'Mailbox is full right now', RECIPIENT, RETRY_ONCE),
    'suspended': (
        'The account is disabled or closed', DATA, SUPPRESS),
    'restricted_recipient': (
        'This mailbox only accepts mail from inside its own organisation',
        RECIPIENT, SUPPRESS),
    'mail_loop': (
        'The address forwards in a loop and never arrives', RECIPIENT,
        SUPPRESS),
    'recipient_blocked': (
        'This person has put you on their own block list', RECIPIENT,
        SUPPRESS),

    'blocklisted': (
        'Your sending domain or IP is on a public blocklist', REPUTATION,
        PAUSE),
    'bad_reputation': (
        'The receiver scores your sending reputation as too low',
        REPUTATION, PAUSE),
    'blocked': (
        'The receiver refused you on policy grounds', REPUTATION, PAUSE),
    'rate_limited': (
        'You are sending faster than this receiver accepts', REPUTATION,
        PAUSE),
    'geo_blocked': (
        "The receiver blocks mail from your server's country", REPUTATION,
        REVIEW),

    'auth_failure': (
        'SPF, DKIM or DMARC failed - the receiver cannot verify you is you',
        AUTH, FIXAUTH),
    'require_ptr': (
        'Your sending IP has no valid reverse DNS record', AUTH, FIXAUTH),

    'spam_detected': (
        'A spam filter judged the message itself, not the sender',
        CONTENT, REWRITE),
    'policy_violation': (
        'A policy rule refused the message - usually the sender, not the '
        'words',
        REPUTATION, REVIEW),
    'virus_detected': (
        'The message was flagged as carrying malware', CONTENT, REVIEW),
    'email_too_large': (
        "The message exceeded the receiver's size limit", CONTENT, REVIEW),

    'greylisted': (
        'Greylisted - the receiver wants you to try again shortly',
        TRANSIENT, RETRY),
    'expired': (
        'Delivery kept failing until the queue gave up', TRANSIENT, RETRY),
    'network_error': (
        'DNS or routing failure reaching the receiver', TRANSIENT, RETRY),
    'system_error': (
        'The receiving server had an internal problem', TRANSIENT, RETRY),

    'rejected': (
        'Refused without saying why - could be the address or could be you',
        UNKNOWN, REVIEW),
    'undefined': (
        'Only a bare failure code, no explanation given', UNKNOWN, REVIEW),
    'unknown': (
        'Not recognised - the raw text is kept for review', UNKNOWN, REVIEW),
    'empty': (
        'No bounce text present', UNKNOWN, REVIEW),
    }


# Rules are tried in tiers, most trustworthy first.  Machine tokens beat
# prose: a program emitted the token, while a person typed the prose,
# sometimes years ago and sometimes wrongly.
T_TOKEN = 1         # RESOLVER.ADR..., STOREDRV..., vendor gateway codes
T_BLOCKLIST = 2     # a named blocklist settles it
T_ESC = 3           # specific enhanced status codes
T_TEXT = 4          # English phrases
T_GENERIC = 5       # says something failed, but not why
T_CLASS = 6         # a bare 4xx or 5xx

CONFIDENCE = {
    T_TOKEN: 'high',
    T_BLOCKLIST: 'high',
    T_ESC: 'high',
    T_TEXT: 'medium',
    T_GENERIC: 'low',
    T_CLASS: 'low',
    }


class Rule:
    """A pattern, the reason it implies, and the tier it belongs to."""

    def __init__(self, tier, pattern, reason, detail=''):
        self.tier = tier
        self.cre = re.compile(pattern, re.IGNORECASE)
        self.reason = reason
        self.detail = detail

    def __repr__(self):
        return f'<Rule {self.tier} {self.reason} {self.cre.pattern[:40]!r}>'


# Short, because the table is long.
R = Rule

RULES = [
    # Vendor tokens.
    R(T_TOKEN, r'RESOLVER\.ADR\.(?:Ex)?Recip(?:ient)?NotFound|'
               r'RESOLVER\.ADR\.InvalidInSmtp',
      'user_unknown', 'Exchange could not resolve the address'),
    R(T_TOKEN, r'RESOLVER\.FWD\.NotFound', 'user_unknown',
      'Exchange forwarding target does not exist'),
    R(T_TOKEN, r'STOREDRV\.Deliver.*Missing AD entry|AD Recipient Cache',
      'user_unknown', 'no directory entry for the recipient'),
    # Directory-based edge blocking: the tenant checked its directory and
    # the address is not in it.
    R(T_TOKEN, r'AS\(201806281\)', 'user_unknown',
      'Microsoft: the recipient is not in the tenant directory'),
    # Microsoft's NDR reference lists 5.5.0 "mailbox unavailable" as a
    # hotmail.com or outlook.com address that SMTP lookup could not find.
    # The S2017062302 tag is the Outlook.com flavour of it.  It used to be
    # caught by a Barracuda pattern below, which said to pause the domain.
    R(T_TOKEN, r'mailbox unavailable \(S2017062302\)', 'user_unknown',
      'Outlook.com: no such mailbox'),
    R(T_TOKEN, r'QuotaExceededException|STOREDRV\.Deliver\.Exception:.*Quota',
      'mailbox_full', 'Exchange reports the mailbox over quota'),
    R(T_TOKEN, r'RESOLVER\.RST\.SenderNotAuthenticatedFor(?:Group|Mailbox)|'
               r'RESOLVER\.RST\.RestrictedToRecipientsPermission|'
               r'UnifiedGroupAgent|'
               r"external senders? (?:aren'?t|are not) permitted|"
               r"sender isn'?t (?:a group member|on the recipient)",
      'restricted_recipient', 'recipient only accepts internal senders'),
    R(T_TOKEN, r'delivery will only occur if you click|'
               r'recipient declines mail from|not on the friends list',
      'restricted_recipient', 'recipient uses a challenge-response gate'),
    R(T_TOKEN, r'TRANSPORT\.RULES\.RejectMessage', 'policy_violation',
      'a mail-flow rule on the receiving tenant rejected it'),
    R(T_TOKEN, r'TenantInboundAttribution|'
               r'RestrictDomainsTo(?:IPAddresses|Certificate)',
      'restricted_recipient',
      'receiving tenant only accepts partner connectors'),
    R(T_TOKEN, r'RESOLVER\.RST\.NotAuthorized|RESOLVER\.RST\.AuthRequired',
      'policy_violation', 'sender not authorised for this recipient'),
    # "The account was blocked for sending too much spam."  This is your
    # own mailbox, not the recipient's.
    R(T_TOKEN, r'bad outbound sender', 'bad_reputation',
      'Microsoft blocked the sending mailbox for spam'),
    R(T_TOKEN, r'ATTR34|hop count exceeded|mail loop', 'mail_loop',
      'the address forwards in a loop'),
    R(T_TOKEN, r'g_deny_country|country is banned', 'geo_blocked',
      "receiver blocks the sending server's country"),
    # GMX, web.de, mail.com and 1&1 link every rejection to a postmaster
    # case page, and the case code says why.  r1102 and r1103 mean the
    # envelope or header From domain is on a Spamhaus list:
    # https://postmaster.gmx.net/en/case?c=r1102
    R(T_TOKEN, r'/case\?c=r110[23]\b', 'blocklisted',
      'GMX/1&1: your From domain is on a Spamhaus list'),
    R(T_TOKEN, r'/case\?c=r1601\b', 'user_unknown',
      'GMX/1&1: no such recipient, or disabled for inactivity'),
    R(T_TOKEN, r'/case\?c=r1503\b', 'mailbox_full', 'GMX/1&1: mailbox full'),
    # Verizon retired its email-to-text gateways, so a vtext.com address
    # will never take mail again.  It arrives tagged AUP#MXRT.
    R(T_TOKEN, r'Decommission of Email to Text', 'host_unknown',
      'Verizon shut down email-to-text (vtext.com)'),
    # Spectrum and Cox tag rejections with AUP# codes.  Spectrum's table
    # of what each number means is only published behind JavaScript.
    # XXX: once it can be read, split this by code.
    R(T_TOKEN, r'\bAUP#', 'policy_violation',
      'ISP acceptable-use rejection (Spectrum, Cox)'),
    # iCloud Mail.  Neither code is about the address: in our corpus, when
    # the same address was mailed again later, 74% of CS01 and 68% of HM08
    # bounces were delivered.  HM07/HM08 behave like a throttle.
    R(T_TOKEN, r'\[CS01\]', 'policy_violation',
      "iCloud Mail's filter refused this send (CS01)"),
    R(T_TOKEN, r'\[HM0[78]\]', 'throttled',
      'iCloud Mail refused this send (HM07/HM08) - later ones often land'),
    # Mimecast links each rejection to an anchor on its error code page,
    # community.mimecast.com/docs/DOC-1369.  "Security policies" is its spam
    # and malware scanning; "User Entry" is one person's blocked senders.
    R(T_TOKEN, r'Email rejected due to security policies', 'spam_detected',
      'Mimecast: spam or malware signature in the message'),
    R(T_TOKEN, r'Envelope blocked - User Entry', 'recipient_blocked',
      "Mimecast: the recipient's own blocked senders list"),
    # Sophos and Open-Xchange gateways emit opaque codes with no prose.
    R(T_TOKEN, r'\bXGEMAIL_\d+', 'blocked',
      'Sophos gateway rejected the message'),
    R(T_TOKEN, r'\bOXSUS\d+_\d+', 'blocked',
      'Open-Xchange gateway rejected the sender'),
    # Yahoo and AOL bracket a short code into the text.  TS and TSS are
    # throttles, not refusals, which a 4xx/5xx split alone would lose.
    R(T_TOKEN, r'\[TSS?\d{2}\]|\bTSS0[1-4]\b|\bTS0[1-4]\b', 'throttled',
      'Yahoo/AOL deferral - too much volume or too many complaints'),
    R(T_TOKEN, r'\bPH0[1-9]\b|\bIPv6 connections are not accepted\b',
      'blocked', 'Verizon/Yahoo policy rejection code'),
    R(T_TOKEN, r'\bHVU:B1\b|\bVS3140\b|\bDNSBL:', 'blocklisted',
      'Yahoo reputation or blocklist rejection'),

    # Named blocklists.
    R(T_BLOCKLIST, r'\b(?:dbl|zen|sbl|xbl|pbl|css)\.spamhaus\.org|spamhaus',
      'blocklisted', 'listed by Spamhaus - check.spamhaus.org'),
    R(T_BLOCKLIST, r'\bsurbl\b|multi\.surbl\.org', 'blocklisted',
      'listed by SURBL'),
    R(T_BLOCKLIST, r'sophosxl\.(?:com|net)', 'blocklisted',
      'listed by Sophos XL'),
    R(T_BLOCKLIST, r'spamrl\.com', 'blocklisted', 'listed by SpamRL'),
    R(T_BLOCKLIST, r'spamcop|barracudacentral|uceprotect|sorbs|invaluement|'
                   r'truncate\.gbudb|abusix',
      'blocklisted', 'listed by a public DNSBL'),
    R(T_BLOCKLIST, r'listed by dbl|blocked using|block list|blocklist|'
                   r'blacklist|'
                   r'listed (?:on|in|by)\b[^.]{0,40}?(?:rbl|dnsbl|list)',
      'blocklisted', 'the receiver named a blocklist'),

    # Enhanced status codes.  Microsoft's own come first, from "Email
    # nondelivery reports and SMTP errors in Exchange Online" on
    # learn.microsoft.com, because some reuse numbers from the RFC families
    # below with a narrower meaning.
    R(T_ESC, r'\b5\.7\.70[58]\b', 'bad_reputation',
      'Microsoft banned your sending tenant for suspicious traffic'),
    R(T_ESC, r'\b5\.7\.750\b', 'bad_reputation',
      'Microsoft: your tenant is sending from unregistered domains'),
    R(T_ESC, r'\b5\.7\.703\b', 'policy_violation',
      "your own tenant's block list stops this recipient"),
    R(T_ESC, r'\b5\.7\.7[01][0-9]\b', 'bad_reputation',
      'Microsoft: sending tenant or IP blocked'),
    R(T_ESC, r'\b5\.7\.(?:50[123]|511|800)\b|\b5\.7\.6[0-4][0-9]\b',
      'blocked', 'Microsoft banned the sender or its IP for spam'),
    R(T_ESC, r'\b5\.7\.50[45]\b', 'user_unknown',
      'Microsoft: the recipient address is not valid'),
    R(T_ESC, r'\b5\.7\.(?:507|513)\b', 'blocked',
      "the recipient's organisation blocks your sending IP"),
    R(T_ESC, r'\b5\.7\.508\b', 'rate_limited',
      'Microsoft: your IP range exceeded its limits'),
    R(T_ESC, r'\b5\.7\.509\b', 'auth_failure',
      'Microsoft: your From domain failed DMARC'),
    R(T_ESC, r'\b5\.7\.(?:1[23]|12[0-9]|13[0-9]|19[0-9]|52[0-9])\b',
      'restricted_recipient',
      'Microsoft: recipient refuses external or forwarded mail'),
    R(T_ESC, r'\b5\.5\.0\b[^.]{0,60}mailbox unavailable', 'user_unknown',
      'Outlook.com: no such mailbox'),
    R(T_ESC, r'\b[45]\.4\.31[01]\b', 'host_unknown',
      "Exchange: the recipient domain's DNS is missing or broken"),
    R(T_ESC, r'\b[45]\.4\.31[2-8]\b', 'network_error',
      "Exchange could not connect to the recipient's mail server"),
    R(T_ESC, r'\b5\.4\.1\b', 'user_unknown',
      'Microsoft: no such recipient, or the domain is not hosted there'),
    # RFC 7372 numbers the authentication failures and RFC 7505 the null
    # MX.  Gmail uses them as registered.
    R(T_ESC, r'\b5\.7\.2[0-46]\b', 'auth_failure',
      'DKIM or SPF did not pass'),
    R(T_ESC, r'\b5\.7\.25\b', 'require_ptr',
      'no reverse DNS for the sending IP'),
    R(T_ESC, r'\b5\.7\.27\b', 'sender_address_bad',
      'your sending domain publishes a null MX'),
    R(T_ESC, r'\b[45]\.7\.28\b', 'rate_limited',
      'Gmail: unusual rate or unsolicited-mail pattern'),
    R(T_ESC, r'\b5\.7\.29\b', 'auth_failure', 'ARC validation failed'),
    R(T_ESC, r'\b[45]\.7\.30\b', 'crypto_error', 'REQUIRETLS not supported'),
    # 5.1.10 is "recipient has a null MX" in RFC 7505 and "recipient not
    # found" at Microsoft.  The address is dead either way.
    R(T_ESC, r'\b5\.1\.(?:[0-36]|10)\b', 'user_unknown',
      'address does not exist'),
    R(T_ESC, r'\b5\.2\.2\b', 'mailbox_full',
      'over quota - permanent code, but mailboxes do get emptied'),
    R(T_ESC, r'\b5\.2\.1\b', 'suspended', 'mailbox disabled'),
    R(T_ESC, r'\b5\.3\.4\b', 'email_too_large',
      'message above the size limit'),
    R(T_ESC, r'\b4\.2\.2\b', 'mailbox_full', 'mailbox over quota, temporary'),
    R(T_ESC, r'\b4\.4\.[17]\b', 'expired', 'delivery attempts timed out'),
    R(T_ESC, r'\b4\.3\.\d+\b', 'system_error', 'receiving system problem'),
    # RFC 4954 registers 5.7.9 as "authentication mechanism is too weak",
    # but Yahoo uses it for its own policy refusals and that is what turns
    # up in practice.
    R(T_ESC, r'\b5\.7\.9\b', 'policy_violation',
      'Yahoo: refused on policy, usually DMARC or content'),
    R(T_ESC, r'\b[45]\.7\.2\b', 'list_expansion',
      'the receiver refuses to expand this list'),
    R(T_ESC, r'\b[45]\.7\.0\b', 'policy_violation',
      'refused on security policy'),
    R(T_ESC, r'\b[45]\.7\.[4-7]\b', 'crypto_error', 'TLS or signing failure'),
    # X.1.x, the address family.
    R(T_ESC, r'\b5\.1\.4\b', 'ambiguous_address',
      'address matches several mailboxes'),
    R(T_ESC, r'\b[45]\.1\.[78]\b', 'sender_address_bad',
      'your return address or its domain is the problem'),
    # X.2.x, the mailbox family.
    R(T_ESC, r'\b[45]\.2\.3\b', 'email_too_large',
      "over the receiver's size limit"),
    R(T_ESC, r'\b[45]\.2\.4\b', 'list_expansion',
      'mailing list expansion problem'),
    # X.4.x, the network family.
    R(T_ESC, r'\b[45]\.4\.6\b', 'mail_loop', 'routing loop detected'),
    R(T_ESC, r'\b[45]\.4\.4\b', 'host_unknown', 'no route to the destination'),
    R(T_ESC, r'\b[45]\.4\.[025]\b', 'network_error',
      'network or connection failure'),
    # X.5.x, the protocol family.
    R(T_ESC, r'\b[45]\.5\.3\b', 'protocol_error',
      'more recipients in one transaction than the receiver allows'),
    R(T_ESC, r'\b[45]\.5\.[0-2456]\b', 'protocol_error',
      'SMTP protocol disagreement'),
    # X.6.x, the media family.
    R(T_ESC, r'\b[45]\.6\.\d+\b', 'media_error',
      'message format or encoding rejected'),

    # Phrases.  Order matters within the tier: the first rule to match the
    # remote half wins, so narrow phrases go above the broad ones.
    R(T_TEXT, r'over quota|quota exceeded|out of storage|mailbox (?:is )?full|'
              r'inode limit|blocks limit exceeded|insufficient system storage',
      'mailbox_full', 'the receiver says the mailbox is full'),
    R(T_TEXT, r"domain (?:[\w.-]+ )?(?:does not|doesn'?t) exist|"
              r'host unknown|unrouteable domain|no such domain|'
              r'domain not found|dns record is (?:invalid|misconfigured)|'
              r'unable to find the recipient domain',
      'host_unknown', 'the domain has no working mail server'),
    R(T_TEXT, r'user unknown|unknown user|unknown recipient|'
              r'no such (?:user|recipient|mailbox|person)|'
              r'does not exist|recipient not found|invalid recipient|'
              r'recipient unrecognized|(?<!sender )invalid address|'
              r'unrouteable address|no mailbox (?:here|by that name)|'
              r'mailbox not found|address (?:could not be found|not found)|'
              r"user doesn'?t exist|email address invalid|address is invalid|"
              r'was misspelled|no valid recipients',
      'user_unknown', 'the receiver says there is no such address'),
    R(T_TEXT, r'mailbox (?:is )?disabled|'
              r'account (?:is )?(?:disabled|suspended|inactive)|'
              r'no longer (?:employed|with|active)|account closed|'
              r'no longer on (?:the |this )?system|'
              r'disabled recipient|user disabled|cannot receive new mail',
      'suspended', 'the account is switched off'),
    R(T_TEXT, r'has moved|address has changed|forwarding disabled',
      'has_moved', 'the address moved'),
    R(T_TEXT, r'(?:detect\w*|identif\w*|flagg\w*|classif\w*|reject\w*)'
              r'[^.;]{0,40}?\bas spam|'
              r'spam message rejected|high probability of spam|'
              r'considered spam|looks like spam|spam content|'
              r'message (?:is|was) spam|appears to be spam|'
              r'content rejected as spam|judged to be spam|'
              r'appears to be unsolicited|unacceptable content',
      'spam_detected', 'a content filter judged the message as spam'),
    R(T_TEXT, r'poor reputation|bad reputation|low reputation|'
              r'reputation of (?:the |a )?domain|sender reputation|'
              r'reputation too low|suspicious due to|'
              r'source is flagged as bad|too many complaints',
      'bad_reputation', 'the receiver scored your reputation as too low'),
    R(T_TEXT, r'location screening|blocked[- ]country|IP-Country|'
              r'country[- ]region[- ]list',
      'geo_blocked', "the receiver blocks your server's country"),
    R(T_TEXT, r'administrative prohibition|'
              r'policy (?:restrict|reason|violation)|'
              r'local (?:policy|security policy)|organization policy|'
              r'rejected by policy|delivery requirements|content filter|'
              r'denied due to|mailbox delivery failure policy',
      'policy_violation', 'a policy rule rejected the message'),
    # A server that asks you to log in before it will take the message is
    # treating you as a relay, so it isn't the mail host for that address.
    R(T_TEXT, r'relay(?:ing)? (?:denied|not permitted|access denied|'
              r'disallowed|is not allowed|not allowed)|'
              r'unable to relay|relay access denied|not our customer|'
              r'authentication required to relay|'
              r'turn on SMTP Authentication|'
              r'requires authentication when attempting to send to a '
              r'non-local',
      'no_relaying', 'that server does not accept mail for this address'),
    R(T_TEXT, r'has no real MX records', 'sender_address_bad',
      'your sending domain has no MX record'),
    R(T_TEXT, r"sender's policy prohibits", 'auth_failure',
      "your domain's DMARC policy told them to refuse it"),
    R(T_TEXT, r'refused to accept a connection', 'network_error',
      "the recipient's mail server refused every connection"),
    R(T_TEXT, r'your access to [^.]{0,40}?(?:e-?mail )?system'
              r'[^.]{0,30}?(?:rejected|denied)|'
              r'sender (?:email )?address rejected|sender rejected|'
              r'blocked\b|prohibited|not permitted|refused|banned|'
              r'host network not allowed',
      'blocked', 'the receiver refused the sender outright'),
    R(T_TEXT, r'\bspf\b|\bdkim\b|\bdmarc\b|not authenticated|'
              r'authentication (?:required|failed)|unauthenticated',
      'auth_failure', 'sender authentication did not pass'),
    R(T_TEXT, r'reverse dns|ptr record|no rdns|missing ptr', 'require_ptr',
      'no valid reverse DNS for the sending IP'),
    R(T_TEXT, r'greylist|grey-list|try again later|please retry|'
              r'temporarily (?:deferred|unavailable|rejected)|deferred',
      'greylisted', 'the receiver asked you to try again'),
    R(T_TEXT, r'too many (?:messages|connections|recipients)|rate limit|'
              r'throttl|sending quota|exceeded the maximum',
      'rate_limited', "you exceeded the receiver's rate"),
    R(T_TEXT, r'message expired|delivery time expired|retry timeout|'
              r'repeated attempts to deliver|'
              r'could not be delivered.*\bdays\b',
      'expired', 'the queue gave up after repeated attempts'),
    R(T_TEXT, r'virus|malware|infected', 'virus_detected',
      'flagged as malware'),
    R(T_TEXT, r'message (?:is )?too large|size limit|exceeds.*size',
      'email_too_large', 'over the size limit'),
    R(T_TEXT, r'connection (?:refused|timed out)|'
              r'network (?:is )?unreachable|no route to host|'
              r'dns (?:error|failure)',
      'network_error', 'could not reach the receiving server'),
    # Cloudflare Email Routing could not hand the message on.
    R(T_TEXT, r'Upstream error, please check', 'system_error',
      "the recipient's forwarding service failed"),

    # Signals that say something failed, but not why.
    R(T_GENERIC, r'\b5\.7\.1\b', 'blocked', 'generic policy refusal'),
    R(T_GENERIC, r'\b5\.1\.0\b|\baddress rejected\b', 'rejected',
      'address refused without a stated reason'),
    R(T_GENERIC, r'\b4\.7\.\d+\b', 'greylisted', 'temporary policy refusal'),
    R(T_GENERIC, r'mailbox unavailable|action not taken|'
                 r'recipient (?:address )?rejected|delivery failed|'
                 r'undeliverable|command rejected|access denied',
      'rejected', 'refused without a stated reason'),

    # A bare SMTP class and nothing else.
    R(T_CLASS, r'\b4\d\d\b', 'undefined', 'temporary failure, no detail'),
    R(T_CLASS, r'\b5\d\d\b', 'undefined', 'permanent failure, no detail'),
    ]

RULES.sort(key=lambda rule: rule.tier)
RULES_BY_TIER = [(tier, list(rules)) for tier, rules
                 in itertools.groupby(RULES, key=lambda rule: rule.tier)]


arrowcre = re.compile(r'\s*->\s*')
esccre = re.compile(r'\b([245])\.(\d{1,3})\.(\d{1,3})\b')
smtpcre = re.compile(r'\b([245]\d\d)\b')
blocklistcre = re.compile(
    r'\b((?:[\w-]+\.)*(?:spamhaus\.(?:org|net)|surbl\.org|'
    r'sophosxl\.(?:com|net)|abusix\.(?:com|org|zone)|'
    r'spamrl\.com|spamcop\.net|barracudacentral\.org|uceprotect\.net|'
    r'sorbs\.net|dnsbl\.[\w.-]+|rbl\.[\w.-]+))\b', re.IGNORECASE)
dblcre = re.compile(r'\bDBL\b')
# GMX names Spamhaus only on the case page its bounce links to.
gmxlistedcre = re.compile(r'/case\?c=r110[23]\b')
quotacre = re.compile(r'\b5\.2\.2\b')
# Gmail says so when an over-quota mailbox has also gone unused.
inactivecre = re.compile(r'inactive|not been accessed|dormant|abandoned',
                         re.IGNORECASE)

PROVIDERS = [
    ('microsoft', r'RESOLVER\.|STOREDRV\.|TRANSPORT\.RULES|TenantInbound|'
                  r'protection\.outlook\.com|\bATTR\d+\b|outlook\.com|'
                  r'office365|exchangelabs'),
    ('google', r'gsmtp\b|googlemail|google\.com|gmail-smtp|'
               r'aspmx\.l\.google'),
    ('proofpoint', r'proofpoint|pphosted'),
    ('mimecast', r'mimecast'),
    ('barracuda', r'barracuda'),
    ('sophos', r'sophos|XGEMAIL'),
    ('cloudmark', r'cloudmark'),
    ('yahoo', r'yahoo|yahoodns'),
    ('apple', r'icloud|apple\.com'),
    ('gmx', r'postmaster\.(?:1und1|gmx|web|mail)\.'),
    ('spectrum', r'spectrum\.net'),
    ]
PROVIDERS = [(name, re.compile(pattern, re.IGNORECASE))
             for name, pattern in PROVIDERS]

# Operators run many hostnames.  uri.cal1.sophosxl.com and
# uri.vir1.sophosxl.com are one listing to clear, not two, so report the
# operator rather than the host.
OPERATORS = [
    ('spamhaus', 'Spamhaus'),
    ('surbl', 'SURBL'),
    ('sophosxl', 'Sophos XL'),
    ('spamrl', 'SpamRL'),
    ('spamcop', 'SpamCop'),
    ('barracuda', 'Barracuda'),
    ('uceprotect', 'UCEPROTECT'),
    ('sorbs', 'SORBS'),
    ('invaluement', 'Invaluement'),
    ('gbudb', 'GBUdb'),
    ('abusix', 'Abusix'),
    ]
OPERATORS = [(re.compile(pattern, re.IGNORECASE), name)
             for pattern, name in OPERATORS]

BL_URLS = {
    'Spamhaus': 'https://check.spamhaus.org/',
    'SURBL': 'https://surbl.org/surbl-analysis',
    'SpamCop': 'https://www.spamcop.net/bl.shtml',
    'Barracuda': 'https://www.barracudacentral.org/lookups',
    'UCEPROTECT': 'https://www.uceprotect.net/en/rblcheck.php',
    'SORBS': 'https://www.sorbs.net/lookup.shtml',
    'Abusix': 'https://lookup.abusix.com/',
    }


def split_layers(text):
    """Split 'relay summary -> remote reply' into its two halves.

    Return (wrapper, remote).  Text with no arrow is all remote.  About half
    of real bounce text arrives like this:

        5.1.351 Remote server returned unknown recipient or mailbox unavailable
          -> 550 Requested action not taken; Reject due to policy restrictions.

    The wrapper is Exchange guessing.  The remote half is what the receiving
    server actually said.
    """
    if '->' not in text:
        return '', text
    parts = arrowcre.split(text)
    return parts[0].strip(), parts[-1].strip()


def find_provider(text):
    """Return the name of the system that refused the mail, or ''."""
    for name, cre in PROVIDERS:
        if cre.search(text):
            return name
    return ''


def find_blocklist(text):
    """Return the blocklist operators named in text, joined by semicolons."""
    names = []
    for mo in blocklistcre.finditer(text):
        host = mo.group(1).lower().strip('.')
        name = next((op for cre, op in OPERATORS if cre.search(host)), host)
        if name not in names:
            names.append(name)
    if not names and (dblcre.search(text) or gmxlistedcre.search(text)):
        names.append('Spamhaus')
    return SEMICOLON.join(names)


def _first_rule(remote, text):
    # Two orderings at once.  Across tiers the better kind of signal wins
    # wherever it appears.  Within a tier the remote half wins, since that is
    # the server that actually refused the mail.
    for tier, rules in RULES_BY_TIER:
        for candidate in (remote, text):
            if not candidate:
                continue
            for rule in rules:
                mo = rule.cre.search(candidate)
                if mo:
                    return rule, mo.group(0)
    return None, ''


def classify(text, recipient_host=''):
    """Classify one bounce message.

    :param text: The bounce text, as the sequencer exported it.
    :param recipient_host: The recipient's mail host, when the export has it.
    :return: A dict keyed by reason, meaning, category, action, detail,
        rejected_by, recipient_host, smtp_code, status_code, blocklist,
        confidence and evidence, the words that decided it, plus `_tier`
        for the rule that matched.  Never raises.
    """
    text = (text or '').strip()
    esc = smtp = hit = None
    provider = blocklist = evidence = ''
    if text:
        wrapper, remote = split_layers(text)
        provider = find_provider(text)
        blocklist = find_blocklist(text)
        # The wrapper's codes describe the relay, not the rejection, so read
        # the remote half first.
        esc = (esccre.search(remote) or esccre.search(wrapper)
               or esccre.search(text))
        smtp = smtpcre.search(remote) or smtpcre.search(text)
        hit, evidence = _first_rule(remote, text)

    if hit:
        reason, detail = hit.reason, hit.detail
    else:
        reason, detail = ('unknown' if text else 'empty'), ''
    # A full mailbox the receiver also calls inactive is not going to drain.
    if reason == 'mailbox_full' and text:
        permanent = bool(quotacre.search(text)) or (
            smtp and smtp.group(1).startswith('5'))
        mo = inactivecre.search(text)
        if permanent and mo:
            reason = 'mailbox_full_abandoned'
            evidence = f'{evidence} ... {mo.group(0)}'
            detail = ('permanently over quota and the receiver calls it '
                      'inactive')

    meaning, category, action = REASONS[reason]
    if blocklist:
        first_list = blocklist.split(SEMICOLON)[0]
    else:
        first_list = ''
    return {
        'reason': reason,
        'meaning': meaning,
        'category': category,
        'action': action,
        'detail': detail,
        'rejected_by': provider or first_list,
        'recipient_host': recipient_host or '',
        'smtp_code': smtp.group(1) if smtp else '',
        'status_code': '.'.join(esc.groups()) if esc else '',
        'blocklist': blocklist,
        'confidence': CONFIDENCE.get(hit.tier, 'none') if hit else 'none',
        'evidence': evidence,
        '_tier': hit.tier if hit else '',
        }


# Output column -> classify() key, in the order the columns are written.
COLUMNS = [
    ('bounce_reason', 'reason'),
    ('bounce_meaning', 'meaning'),
    ('bounce_category', 'category'),
    ('bounce_action', 'action'),
    ('bounce_detail', 'detail'),
    ('rejected_by', 'rejected_by'),
    ('recipient_host', 'recipient_host'),
    ('smtp_code', 'smtp_code'),
    ('status_code', 'status_code'),
    ('blocklist', 'blocklist'),
    ('confidence', 'confidence'),
    ]
FIELDS = [column for column, key in COLUMNS]


BOUNCE_NAMES = (
    'bounce_msg', 'bounce_message', 'bounce_reason', 'bounce_text',
    'bounce_description', 'diagnostic_code', 'diagnostic-code',
    'smtp_response', 'error_message', 'failure_reason', 'reason', 'error',
    'message', 'description', 'response', 'detail',
    )
HOST_NAMES = (
    'mx', 'recipient_host', 'provider', 'esp', 'mail_provider',
    'recipient_provider', 'recp_provider', 'mx_provider',
    )
EMAIL_NAMES = (
    'email', 'recipient', 'to', 'address', 'email_address', 'lead_email',
    )
DATE_NAMES = (
    'last_sent_at', 'sent_at', 'sent', 'date', 'sent_date', 'modified_at',
    'bounced_at', 'created_at', 'timestamp',
    )
SENDER_NAMES = (
    'email_acc_name', 'sending_email', 'from_email', 'sender', 'sdom',
    'sending_domain',
    )
HOST_VALUES = ('GOOGLE_WORKSPACE', 'MICROSOFT365', 'REGULAR_ACCOUNT')

bouncelikecre = re.compile(
    r'\b[245]\.\d{1,3}\.\d{1,3}\b|\b[245]\d\d\b|'
    r'mailbox|recipient|undeliverable|spam|blocked|quota|smtp|relay|rejected',
    re.IGNORECASE)
isodatecre = re.compile(r'^\d{4}-\d{2}-\d{2}')


def detect_columns(fieldnames, rows):
    """Find the bounce text, host, email and date columns.

    Every sequencer invents its own schema, so score what the values look
    like and use the column names only to break ties.

    :param fieldnames: The header, in file order.
    :param rows: A sample of rows, as dicts.
    :return: A dict keyed by bounce, host, email and date.  A value is None
        when no column fits.
    """
    found = dict(bounce=None, host=None, email=None, date=None)
    lower = {name: name.strip().lower() for name in fieldnames}

    best, best_score, named = None, 0.0, None
    for name in fieldnames:
        if named is None and lower[name] in BOUNCE_NAMES:
            named = name
        values = [(row.get(name) or '').strip() for row in rows]
        values = [value for value in values if value]
        if not values:
            continue
        hits = sum(1 for value in values if bouncelikecre.search(value))
        average = sum(len(value) for value in values) / len(values)
        score = hits / len(values) * min(average / 25.0, 2.0)
        if lower[name] in BOUNCE_NAMES:
            score += 1.0
        if score > best_score:
            best, best_score = name, score
    if best_score >= 0.35:
        found['bounce'] = best
    elif named:
        # Nothing scored, but a column is named like bounce text.  Most rows
        # in a whole-campaign export never bounced, so the sample can be all
        # blanks while the column is still the right one.
        found['bounce'] = named

    for name in fieldnames:
        values = [(row.get(name) or '').strip() for row in rows]
        values = [value for value in values if value]
        if not values:
            continue
        if found['host'] is None and (
                lower[name] in HOST_NAMES
                or sum(1 for value in values
                       if value.upper() in HOST_VALUES) > len(values) / 2):
            found['host'] = name
        if found['email'] is None and (
                lower[name] in EMAIL_NAMES
                or sum(1 for value in values
                       if '@' in value) > len(values) * 0.8):
            found['email'] = name
        if found['date'] is None and (
                lower[name] in DATE_NAMES
                and sum(1 for value in values
                        if isodatecre.match(value)) > len(values) / 2):
            found['date'] = name
    return found


class Stats:
    """Running totals for one export."""

    def __init__(self):
        self.rows = 0               # every row read
        self.total = 0              # rows that carried bounce text
        self.empty = 0              # rows that did not
        self.unknown = 0
        self.first = self.last = None
        self.category = collections.Counter(dict.fromkeys(CATEGORIES, 0))
        self.action = collections.Counter(dict.fromkeys(ACTIONS, 0))
        self.reason = collections.Counter()
        self.rejected_by = collections.Counter()
        self.blocklist = collections.Counter()
        self.confidence = collections.Counter()
        # Each by_* counter has a *_yours twin holding the sending-side part.
        self.by_host = collections.Counter()
        self.host_yours = collections.Counter()
        self.by_sender = collections.Counter()
        self.sender_yours = collections.Counter()
        self.sender_pause = collections.Counter()
        self.by_date = collections.Counter()
        self.date_yours = collections.Counter()
        self.dead = []              # addresses never to mail again
        self.unread = []            # text no rule could read

    @property
    def rate(self):
        return self.total / max(self.rows, 1) * 100

    def to_pause(self):
        """Return the sending domains to pause, worst first.

        A domain makes the list when receivers refused it on reputation at
        least three times, and those refusals are at least half its bounces.
        Below that it is as likely to be a bad list as a burnt domain.
        """
        domains = [domain for domain, n in self.sender_pause.items()
                   if n >= 3 and n * 2 >= self.by_sender[domain]]
        return sorted(domains, key=lambda d: (-self.sender_pause[d], d))

    def add(self, result, text, host='', sender='', date='', email=''):
        """Count one classified row."""
        self.rows += 1
        # A row with no bounce text is not a bounce.  Counted as unknown, it
        # made a healthy campaign read as a 97% failure.
        if result['reason'] == 'empty':
            self.empty += 1
            return
        self.total += 1
        self.category[result['category']] += 1
        self.action[result['action']] += 1
        self.reason[result['reason']] += 1
        self.confidence[result['confidence']] += 1
        yours = int(result['category'] in SENDING_SIDE)
        if result['rejected_by']:
            self.rejected_by[result['rejected_by']] += 1
        for name in filter(None, result['blocklist'].split(SEMICOLON)):
            self.blocklist[name] += 1
        if host:
            self.by_host[host] += 1
            self.host_yours[host] += yours
        if sender:
            self.by_sender[sender] += 1
            self.sender_yours[sender] += yours
            if result['action'] == PAUSE:
                self.sender_pause[sender] += 1
        if date:
            self.by_date[date] += 1
            self.date_yours[date] += yours
            self.first = min(self.first or date, date)
            self.last = max(self.last or date, date)
        if result['reason'] in ('unknown', 'undefined') and text.strip():
            self.unknown += 1
            self.unread.append(text)
        if result['action'] == SUPPRESS and '@' in email:
            self.dead.append(email)


BANNER = """\
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
                   v{version}"""

# The same mark in ASCII, for consoles that can't encode the one above.
BANNER_ASCII = """\
                      |
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
    """Return the mark in a character set this console can print."""
    return (BANNER if UNICODE else BANNER_ASCII).format(version=version)


# How much trouble each category means, and so its colour.
CAT_COLOUR = {
    REPUTATION: 'red',
    AUTH: 'yellow',
    CONTENT: 'yellow',
    DATA: 'cyan',
    RECIPIENT: 'blue',
    TRANSIENT: 'grey',
    UNKNOWN: 'grey',
    }


def _bar(fraction, width=22):
    filled = int(round(fraction * width))
    return '#' * filled + '.' * (width - filled)


def _headline(stats):
    total = stats.total
    period = ''
    if stats.first:
        period = f' - {stats.first} to {stats.last}'
    # The rate needs a denominator, which only a whole-campaign export has.
    if not stats.empty:
        return [f'{total:,} bounces analysed{period}', '']
    rate = stats.rate
    lines = [f'**{total:,} of {stats.rows:,} leads bounced ({rate:.1f}%)**'
             f'{period}', '']
    if rate >= 5:
        lines.append(
            f'A {rate:.1f}% bounce rate is high enough to be doing damage on '
            f'its own. Mailbox providers read it as a signal about you, so it '
            f'compounds: the more you bounce, the more you get filtered.')
    elif rate >= 2:
        lines.append(
            f'A {rate:.1f}% bounce rate is survivable but worth pulling down. '
            f'Under 2% is where you want to be.')
    else:
        lines.append(f'A {rate:.1f}% bounce rate is healthy.')
    lines.append('')
    return lines


def _verdict(stats):
    """Return the verdict section, which names the single biggest problem."""
    # "Sending side" covers a Spamhaus listing, a broken SPF record and copy
    # that trips filters.  Those need different fixes, so name which one.
    total = stats.total
    category, reason = stats.category, stats.reason
    yours = category[REPUTATION] + category[AUTH] + category[CONTENT]
    theirs = category[DATA] + category[RECIPIENT]

    def pct(n):
        return n / total * 100

    blocked = reason.get('blocklisted', 0)
    auth = category[AUTH]
    content = category[CONTENT]
    transient = category[TRANSIENT]
    unknown = category[UNKNOWN]
    dead = reason.get('user_unknown', 0) + reason.get('host_unknown', 0)
    abandoned = (reason.get('mailbox_full_abandoned', 0)
                 + reason.get('suspended', 0))
    walled = reason.get('restricted_recipient', 0)

    lines = ['## Verdict', '']
    if blocked and pct(blocked) >= 25:
        lines += [
            f'**You are on a blocklist.** {blocked:,} of these bounces '
            f'({pct(blocked):.0f}%) name one outright.',
            '',
            'Nothing else in this report matters until that is cleared. '
            'While a listing stands, every provider that consults it is '
            'refusing you before your copy is ever read, and the domains '
            'keep aging badly the whole time.']
    elif auth and pct(auth) >= 25:
        lines += [
            f'**Your authentication is broken, and that is good news.** '
            f'{auth:,} bounces ({pct(auth):.0f}%) are SPF, DKIM, DMARC or PTR '
            f'failures.',
            '',
            'This is the cheapest problem on the list. It is a DNS record, '
            'not a reputation you have to earn back over weeks. Fix the '
            'records and these stop the same day.']
    elif content and pct(content) >= 30:
        lines += [
            f'**The message is the problem, not the sender.** {content:,} '
            f'bounces ({pct(content):.0f}%) are filters judging the content.',
            '',
            'Your domains are being accepted; what you wrote is not. Look at '
            'the links, the attachments and the phrasing before you touch '
            'anything to do with sending.']
    elif yours > theirs:
        lines += [
            f'**Your sending is the problem, not your list.** '
            f'{pct(yours):.0f}% of these bounces are receivers refusing your '
            f'domains, your authentication or your copy. Only '
            f'{pct(theirs):.0f}% are addresses that do not work.',
            '',
            'Cleaning the list will not move this number. Cutting volume, '
            'fixing authentication and getting delisted will.']
    elif walled and pct(walled) >= 20:
        lines += [
            f'**A lot of these addresses were never reachable.** {walled:,} '
            f'({pct(walled):.0f}%) are mailboxes that only accept mail from '
            f'inside their own company.',
            '',
            'They exist, the domains are healthy, and no amount of warming '
            'will get you in. Suppress them and judge the campaign on what '
            'is left.']
    elif abandoned and pct(abandoned) >= 20:
        lines += [
            f'**You are mailing abandoned accounts.** {abandoned:,} bounces '
            f'({pct(abandoned):.0f}%) are mailboxes the provider itself '
            f'calls full and inactive, or switched off.',
            '',
            'That is a list-age problem rather than a list-quality one. The '
            'addresses were real once. Suppress them, and treat the source '
            'they came from as older than it looks.']
    elif dead and pct(dead) >= 40:
        lines += [
            f'**Your list is stale.** {dead:,} of these bounces '
            f'({pct(dead):.0f}%) are addresses or domains that simply do not '
            f'exist.',
            '',
            'Sending infrastructure looks healthy. This is a data problem, '
            'and it is the easy kind: suppress them, then work out which '
            'source they came from before you buy from it again.']
    elif transient and pct(transient) >= 40:
        lines += [
            f'**Mostly temporary.** {pct(transient):.0f}% of these are '
            f'deferrals rather than refusals - greylisting, throttles, '
            f'queues that gave up.',
            '',
            'There may be nothing wrong here at all. Retry and see what is '
            'left before you change anything.']
    elif unknown and pct(unknown) >= 40:
        lines += [
            f'**No clear signal.** {pct(unknown):.0f}% of this text does '
            f'not say why delivery failed.',
            '',
            'That is usually a sequencer that truncates what the receiving '
            'server said. Run with --dump-unknown and read a few by hand '
            'before drawing conclusions.']
    elif theirs > yours * 2:
        lines += [
            f'**Your list is the problem.** {pct(theirs):.0f}% of these '
            f'bounces are addresses that do not exist or cannot receive '
            f'mail. Sending infrastructure looks healthy.']
    else:
        lines += [
            f'**It is split.** {pct(yours):.0f}% is your sending side, '
            f'{pct(theirs):.0f}% is your data.',
            '',
            'Fix the sending side first. Bad addresses cost you one send '
            'each; a reputation problem taxes every send you make.']
    lines.append('')
    return lines


def _categories(stats):
    total = stats.total
    lines = ['## Where the bounces come from', '',
             '| What | Bounces | Share | |',
             '|---|---:|---:|---|']
    for name, n in stats.category.most_common():
        if n:
            lines.append(f'| {name} | {n:,} | {n / total * 100:.1f}% | '
                         f'`{_bar(n / total)}` |')
    lines.append('')
    return lines


def _rejectors(stats):
    if not stats.rejected_by:
        return []
    total = stats.total
    lines = ['## Who is rejecting you', '',
             '| Rejected by | Bounces | Share |',
             '|---|---:|---:|']
    for name, n in stats.rejected_by.most_common(8):
        lines.append(f'| {name} | {n:,} | {n / total * 100:.1f}% |')
    lines.append('')
    return lines


def _hosts(stats):
    if len(stats.by_host) <= 1:
        return []
    lines = ['## By recipient mail host', '',
             '| Host | Bounces | Sending-side |',
             '|---|---:|---:|']
    for host, n in stats.by_host.most_common(6):
        yours = stats.host_yours[host]
        lines.append(f'| {host} | {n:,} | {yours / n * 100:.0f}% |')
    lines += [
        '',
        'A large gap between hosts is a placement signal. Same copy and the '
        'same mailboxes reaching one provider and not another points at '
        'reputation with that provider, not at your data.',
        '']
    return lines


def _blocklists(stats):
    if not stats.blocklist:
        return []
    lines = ['## Blocklists naming you', '']
    for name, n in stats.blocklist.most_common(10):
        url = BL_URLS.get(name)
        lines.append(f'- **{name}** - {n:,} bounces'
                     + (f' - {url}' if url else ''))
    lines += [
        '',
        'Every one of these is costing you delivery on every send until it '
        'is resolved.',
        '']
    return lines


def _senders(stats):
    # Only domains with enough volume to mean something, worst first.
    floor = max(20, stats.total * 0.002)
    rows = [(domain, n, stats.sender_yours[domain])
            for domain, n in stats.by_sender.items() if n >= floor]
    if not rows:
        return []
    rows.sort(key=lambda row: (-row[2] / row[1], -row[1]))
    lines = ['## Worst sending domains', '',
             '| Sending domain | Bounces | Sending-side |',
             '|---|---:|---:|']
    for domain, n, yours in rows[:10]:
        lines.append(f'| {domain} | {n:,} | {yours / n * 100:.0f}% |')
    lines.append('')
    return lines


def _trend(stats):
    """Return the trend section: are bounces rising or falling?"""
    by_date = stats.by_date
    if len(by_date) < 4:
        return []
    days = sorted(by_date)
    half = len(days) // 2
    early = sum(by_date[day] for day in days[:half])
    late = sum(by_date[day] for day in days[half:])
    early_yours = sum(stats.date_yours[day] for day in days[:half])
    late_yours = sum(stats.date_yours[day] for day in days[half:])

    lines = [
        '## Trend', '',
        '| Period | Days | Bounces | Sending-side |',
        '|---|---:|---:|---:|',
        f'| {days[0]} to {days[half - 1]} | {half} | {early:,} | '
        f'{early_yours / max(early, 1) * 100:.0f}% |',
        f'| {days[half]} to {days[-1]} | {len(days) - half} | {late:,} | '
        f'{late_yours / max(late, 1) * 100:.0f}% |',
        '']
    if late > early * 1.3:
        lines.append(f'Bounces are **rising**: {late / max(early, 1):.1f}x '
                     f'more in the second half of this window.')
    elif early > late * 1.3:
        lines.append(f'Bounces are **falling**: {early / max(late, 1):.1f}x '
                     f'fewer in the second half of this window.')
    else:
        lines.append('Volume is broadly flat across the window.')
    peak = max(by_date, key=lambda day: by_date[day])
    lines += ['', f'Worst single day: **{peak}** with {by_date[peak]:,} '
                  f'bounces.', '']
    return lines


def _next_steps(stats):
    """Return the to-do list, most urgent first."""
    # Delisting comes first because nothing else you change matters while a
    # listing stands.  Authentication is next: it is a DNS edit, not weeks of
    # warming.
    category, action = stats.category, stats.action
    steps = []
    if stats.blocklist:
        hits = sum(stats.blocklist.values())
        steps.append(f'**Get delisted.** {hits:,} bounces cite a public '
                     f'blocklist. Nothing else you change matters while that '
                     f'stands.')
    if category[AUTH]:
        steps.append(f'**Fix authentication.** {category[AUTH]:,} bounces '
                     f'are SPF, DKIM, DMARC or PTR failures. This is a DNS '
                     f'change, not a warming problem - it can be done today.')
    if action[PAUSE]:
        steps.append(f'**Pause the worst domains.** {action[PAUSE]:,} '
                     f'bounces are receivers refusing your sending identity. '
                     f'Continuing to send deepens it. Use --pause-list to '
                     f'export the domains.')
    if action[SUPPRESS]:
        steps.append(f'**Suppress {action[SUPPRESS]:,} addresses** that will '
                     f'never accept mail. Use --suppress-list to export '
                     f'them.')
    if category[CONTENT]:
        steps.append(f'**Rewrite the copy.** {category[CONTENT]:,} bounces '
                     f'are filters judging the message rather than the '
                     f'sender.')
    if stats.unknown:
        steps.append(f'{stats.unknown:,} bounces could not be read. Use '
                     f'--dump-unknown to see them.')
    lines = ['## Do this first', '']
    lines += [f'{n}. {step}' for n, step in enumerate(steps, 1)]
    lines.append('')
    return lines


def build_report(stats, source_name):
    """Return the markdown diagnosis for one export.

    It is written for somebody who wants to act on it, not for somebody
    auditing the classifier.
    """
    lines = ['```', BANNER.format(version=__version__), '```', '',
             f'# Bounce diagnosis: {source_name}', '']
    for section in (_headline, _verdict, _categories, _rejectors, _hosts,
                    _blocklists, _senders, _trend, _next_steps):
        lines += section(stats)
    lines += ['---', f'Generated by bouncesitrep {__version__}']
    return NL.join(lines)


def run_one(text, as_json):
    """Classify one message and print the result.  Return the exit status."""
    result = classify(text)
    if as_json:
        public = {key: value for key, value in result.items()
                  if not key.startswith('_')}
        print(json.dumps(public, indent=2))
        return 0
    print(f"  {result['meaning']}")
    print()
    print(f"  reason      {result['reason']}")
    print(f"  category    {result['category']}")
    print(f"  action      {result['action']}")
    print(f"  confidence  {result['confidence']}")
    for label, key in (('why', 'detail'), ('rejected by', 'rejected_by'),
                       ('smtp', 'smtp_code'), ('status', 'status_code'),
                       ('blocklist', 'blocklist')):
        if result[key]:
            print(f'  {label:11} {result[key]}')
    if result['evidence']:
        print(f"  matched     \"{result['evidence']}\"")
    return 0


def sniff_delimiter(path):
    """Return the column separator, judged from the header line.

    Not every .csv is comma separated.  Excel writes semicolons across most
    of Europe and plenty of exports use tabs.  Read a semicolon file as
    commas and you get a single column called "email;bounce_msg".  A .tsv
    is always tabs.
    """
    if path.lower().endswith('.tsv'):
        return '\t'
    with open(path, newline='', encoding='utf-8-sig', errors='replace') as fp:
        header = fp.readline()
    if not header.strip():
        return ','
    # Whichever candidate splits the header into the most fields wins.  Let
    # the csv module do the splitting, since a comma inside a quoted heading
    # would fool a plain count.
    best, best_count = ',', 0
    for candidate in (',', ';', '\t', '|'):
        try:
            count = len(next(csv.reader([header], delimiter=candidate)))
        except csv.Error:
            continue
        if count > best_count:
            best, best_count = candidate, count
    return best


def _out_path(name, outdir):
    # A bare filename goes to the output directory; a path is left alone.
    # So `-o ~/Desktop --suppress-list dead.txt` lands on the Desktop, and
    # `--suppress-list /tmp/dead.txt` still goes to /tmp.
    path = os.path.expanduser(name)
    return path if os.path.dirname(path) else os.path.join(outdir, path)


# What each action asks of you, most urgent first.
ACTION_HINTS = {
    PAUSE: 'receivers are refusing your sending domains',
    FIXAUTH: 'SPF, DKIM, DMARC or PTR - a DNS fix, today',
    SUPPRESS: 'addresses never to mail again',
    REWRITE: 'filters judged the message itself',
    RETRY_ONCE: 'full mailboxes - one more try, then give up',
    RETRY: 'temporary - safe to send again later',
    REVIEW: 'could not be settled from the text alone',
    }


def print_summary(stats, args, out_path):
    """Print the console summary.  Return False if nothing bounced."""
    total = max(stats.total, 1)
    kept = stats.rows if args.all_rows else stats.total
    arrow = '\u2192' if UNICODE else '->'
    name = paint(os.path.basename(out_path), 'bold')
    say('')
    say(f'  {stats.rows:,} rows read  {arrow}  {kept:,} written to {name}')
    if not stats.total:
        say(paint('  nothing in that file looks like a bounce', 'yellow'))
        say('')
        return False
    if stats.empty:
        rate = stats.rate
        tint = 'red' if rate >= 5 else ('yellow' if rate >= 2 else 'green')
        leads = paint(f'({stats.total:,} of {stats.rows:,} leads)', 'grey')
        say(f"  {paint('%.1f%%' % rate, 'bold', tint)} bounce rate  {leads}")
    say('')
    block = '\u2588' if UNICODE else '#'
    rest = '\u00b7' if UNICODE else '.'
    for category, n in stats.category.most_common():
        if not n:
            continue
        fraction = n / total
        filled = max(1, int(round(fraction * 24)))
        bar = (paint(block * filled, CAT_COLOUR.get(category, 'grey'))
               + paint(rest * (24 - filled), 'grey'))
        say(f'    {category:<15} {n:>8,}  {fraction * 100:5.1f}%  {bar}')
    say('')
    todo = [(action, stats.action[action]) for action in ACTION_HINTS
            if stats.action[action]]
    if todo:
        say(paint('    what to do', 'bold'))
        for action, n in todo:
            say(f'    {action:<15} {n:>8,}  {ACTION_HINTS[action]}')
        say('')
    if stats.blocklist:
        named = COMMASPACE.join(f'{name} ({n:,})' for name, n
                                in stats.blocklist.most_common(4))
        say(f"    {paint('blocklists', 'bold')}      {named}")
        say('')
    return True


def _write_extras(stats, args, outdir, base, path, use):
    # The optional outputs: suppression list, pause list, unread dump and
    # the diagnosis.
    if args.suppress_list:
        args.suppress_list = _out_path(args.suppress_list, outdir)
    if args.pause_list:
        args.pause_list = _out_path(args.pause_list, outdir)
    if args.dump_unknown:
        args.dump_unknown = _out_path(args.dump_unknown, outdir)

    if args.suppress_list and stats.dead:
        # The same dead address turns up once per campaign it was mailed in.
        seen, addresses = set(), []
        for address in stats.dead:
            if address.lower() not in seen:
                seen.add(address.lower())
                addresses.append(address)
        with open(args.suppress_list, 'w', encoding='utf-8') as fp:
            fp.write(NL.join(addresses) + NL)
        say(f'    {len(addresses):,} addresses -> {args.suppress_list}')
    elif args.suppress_list and not use['email']:
        print('  no email column found, cannot write a suppression list',
              file=sys.stderr)

    if args.pause_list and not use['sender']:
        print('  no sending-mailbox column found, cannot write a pause list',
              file=sys.stderr)
    elif args.pause_list:
        domains = stats.to_pause()
        with open(args.pause_list, 'w', encoding='utf-8') as fp:
            fp.write(EMPTYSTRING.join(domain + NL for domain in domains))
        say(f'    {len(domains):,} sending domains -> {args.pause_list}')

    if args.dump_unknown and stats.unread:
        with open(args.dump_unknown, 'w', encoding='utf-8') as fp:
            for text in stats.unread:
                fp.write(SPACE.join(text.split()) + NL)
        say(f'    {len(stats.unread):,} unreadable -> {args.dump_unknown}')

    if args.report:
        if isinstance(args.report, str):
            report = _out_path(args.report, outdir)
        else:
            report = os.path.join(outdir, f'{base} - diagnosis.md')
        with open(report, 'w', encoding='utf-8') as fp:
            fp.write(build_report(stats, os.path.basename(path)) + NL)
        say(f'    diagnosis -> {os.path.basename(report)}')


def _survey(path, delimiter):
    # Return the header and a guess at its columns from the first 200 rows.
    with open(path, newline='', encoding='utf-8-sig', errors='replace') as fp:
        reader = csv.DictReader(fp, delimiter=delimiter)
        if not reader.fieldnames:
            return None, None
        sample = list(itertools.islice(reader, 200))
        return reader.fieldnames, detect_columns(reader.fieldnames, sample)


def _sender_domain(row, column):
    if not column:
        return ''
    value = (row.get(column) or '').strip().lower()
    return value.rsplit('@', 1)[-1] if '@' in value else value


def _iso_date(row, column):
    if not column:
        return ''
    value = (row.get(column) or '')[:10]
    return value if isodatecre.match(value) else ''


def _classify_file(path, out_path, delimiter, use, stats, all_rows):
    with open(path, newline='', encoding='utf-8-sig',
              errors='replace') as fp, \
            open(out_path, 'w', newline='', encoding='utf-8') as out:
        reader = csv.DictReader(fp, delimiter=delimiter)
        writer = csv.DictWriter(out, fieldnames=reader.fieldnames + FIELDS,
                                lineterminator=NL)
        writer.writeheader()
        for row in reader:
            text = row.get(use['bounce']) or ''
            host = (row.get(use['host']) or '') if use['host'] else ''
            result = classify(text, recipient_host=host)
            row.update((column, result[key]) for column, key in COLUMNS)
            # A whole-campaign export is mostly leads that never bounced.
            # Copying them through would bury the rows you can act on.
            if result['reason'] != 'empty' or all_rows:
                writer.writerow(row)
            email = ''
            if use['email']:
                email = (row.get(use['email']) or '').strip()
            stats.add(result, text, host,
                      sender=_sender_domain(row, use['sender']),
                      date=_iso_date(row, use['date']),
                      email=email)


def run_csv(path, args):
    """Classify every row of a CSV export.  Return the exit status."""
    csv.field_size_limit(2 ** 31 - 1)
    if args.outdir:
        outdir = os.path.expanduser(args.outdir)
    else:
        outdir = os.path.dirname(os.path.abspath(path))
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(path))[0]
    out_path = os.path.join(outdir, f'{base} - classified.csv')
    if os.path.exists(out_path) and not args.force:
        print(f'{os.path.basename(out_path)} exists (use --force)',
              file=sys.stderr)
        return 1

    delimiter = sniff_delimiter(path)
    fieldnames, found = _survey(path, delimiter)
    if not fieldnames:
        print(f'{path}: empty file', file=sys.stderr)
        return 1
    bounce = args.column or found['bounce']
    if not bounce:
        print(f'{path}: could not find a bounce-text column. Pass --column.\n'
              f'  columns: {COMMASPACE.join(fieldnames[:15])}',
              file=sys.stderr)
        return 1
    if bounce not in fieldnames:
        print(f"{path}: no column '{bounce}'", file=sys.stderr)
        return 1
    sender = next((name for name in fieldnames
                   if name.strip().lower() in SENDER_NAMES), None)
    use = dict(bounce=bounce, host=args.host_column or found['host'],
               date=found['date'], email=found['email'], sender=sender)

    if not (QUIET or args.no_banner):
        say(paint(banner(__version__), 'cyan'))
        say('')
    shown = {',': '', ';': ' (semicolon separated)',
             '\t': ' (tab separated)', '|': ' (pipe separated)'}[delimiter]
    say(f"  reading '{bounce}'{shown}"
        + (f", host from '{use['host']}'" if use['host'] else '')
        + (f", dates from '{use['date']}'" if use['date'] else ''))

    stats = Stats()
    _classify_file(path, out_path, delimiter, use, stats, args.all_rows)
    if print_summary(stats, args, out_path):
        _write_extras(stats, args, outdir, base, path, use)
    return _exit_status(stats, args)


def _exit_status(stats, args):
    # 0 is fine, 1 an error, 2 bad arguments (argparse's own) and 3 means
    # the bounce rate is over --fail-over.  Cron cares about the last one.
    if args.fail_over is None:
        return 0
    if stats.total and not stats.empty:
        print('  --fail-over needs a whole-campaign export; without the '
              'leads that did not bounce there is no rate', file=sys.stderr)
        return 1
    return 3 if stats.rate > args.fail_over else 0


EPILOG = """\
whose problem it is:
  data            the address is dead or wrong        clean the list
  reputation      your sending identity is refused    pause, warm, delist
  authentication  SPF, DKIM, DMARC or PTR is broken   a DNS fix, today
  content         a filter judged the message itself  rewrite the copy
  recipient       their mailbox refuses everyone      suppress, nothing more
  transient       nobody's fault                      retry

examples:
  bouncesitrep export.csv --report
  bouncesitrep export.csv -o ~/Desktop/results --suppress-list dead.txt \\
      --pause-list pause.txt
  bouncesitrep '550 5.1.1 user unknown'
  bouncesitrep --reasons

Feed it the whole campaign export, not just the bounces. The leads that
did not bounce are what turn a count into a bounce rate.
"""


def print_reasons():
    """Print every reason with its category, action and meaning."""
    for category in CATEGORIES:
        print(paint(category, 'bold', CAT_COLOUR.get(category, 'grey')))
        for reason, (meaning, cat, action) in REASONS.items():
            if cat == category:
                print(f'  {reason:<24}{action:<14}{meaning}')
        print()
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog='bouncesitrep',
        description='Read bounce text from a sequencer export and say whose '
                    'problem each bounce is.',
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input', nargs='?',
                        help='a CSV export, or one bounce message in quotes')

    reading = parser.add_argument_group('reading the export')
    reading.add_argument('-c', '--column', metavar='NAME',
                         help='the bounce-text column (default: detected)')
    reading.add_argument('--host-column', metavar='NAME',
                         help='the recipient mail host column '
                              '(default: detected)')
    reading.add_argument('--all-rows', action='store_true',
                         help='keep every row in the output CSV, not just '
                              'the bounces')

    writing = parser.add_argument_group(
        'what to write',
        'A bare filename goes in the output directory; a path is used as is.')
    writing.add_argument('-o', '--outdir', metavar='DIR',
                         help="where results go (default: the export's own "
                              'folder)')
    writing.add_argument('--report', nargs='?', const=True, metavar='FILE',
                         help='a markdown diagnosis: the rate, the verdict '
                              'and what to do first')
    writing.add_argument('--suppress-list', metavar='FILE',
                         help='addresses never to mail again')
    writing.add_argument('--pause-list', metavar='FILE',
                         help='sending domains receivers are refusing')
    writing.add_argument('--dump-unknown', metavar='FILE',
                         help='every message it could not read, one per '
                              'line')
    writing.add_argument('--force', action='store_true',
                         help='overwrite earlier output')

    showing = parser.add_argument_group('display and exit status')
    showing.add_argument('--json', action='store_true',
                         help="print one message's result as JSON")
    showing.add_argument('--reasons', action='store_true',
                         help='list every reason it can give, and exit')
    showing.add_argument('--fail-over', type=float, metavar='PCT',
                         help='exit 3 when the bounce rate is above PCT')
    showing.add_argument('--banner', action='store_true',
                         help='print the mark and exit')
    showing.add_argument('--no-banner', action='store_true',
                         help='skip the mark, for wrappers that drew it '
                              'already')
    showing.add_argument('-q', '--quiet', action='store_true',
                         help='print errors only')
    showing.add_argument('--version', action='version',
                         version=f'bouncesitrep {__version__}')
    args = parser.parse_args()

    global QUIET
    QUIET = args.quiet

    if args.banner:
        print(paint(banner(__version__), 'cyan'))
        return 0
    if args.reasons:
        return print_reasons()
    if args.input is None:
        parser.error('give it a CSV export or a single bounce message')

    path = os.path.expanduser(args.input)
    # Anything ending in .csv or .tsv was meant to be a file; no bounce
    # message ends that way.  If it's missing it's a typo, and classifying
    # the path as bounce text would send you looking in the wrong place.
    if path.lower().endswith(('.csv', '.tsv')):
        if os.path.isdir(path):
            print(f'{args.input}: is a directory, not a file',
                  file=sys.stderr)
            return 1
        if not os.path.isfile(path):
            print(f'{args.input}: no such file', file=sys.stderr)
            return 1
        return run_csv(path, args)
    return run_one(args.input, args.json)


if __name__ == '__main__':
    sys.exit(main())
