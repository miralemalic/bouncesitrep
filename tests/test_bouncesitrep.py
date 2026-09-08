#!/usr/bin/env python3
"""Tests for bouncesitrep:

    python3 -m unittest discover -s tests -v

Fixtures are real bounce text with the addresses and sending domains replaced.
No real address, domain or campaign name appears in this repo.
"""

import argparse
import csv
import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bouncesitrep as bc  # noqa: E402

bc.QUIET = True


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def read_lines(path):
    return [l.strip() for l in read(path).splitlines() if l.strip()]


def cls(text, host=""):
    return bc.classify(text, recipient_host=host)


def cat_act(text):
    r = cls(text)
    return r["category"], r["action"]


# ---------------------------------------------------------------- the promise

class TestSafetyRails(unittest.TestCase):
    """These two mistakes cost real money, so they are checked against every
    entry in the table rather than by example."""

    def test_never_suppress_a_lead_over_your_own_problem(self):
        """If YOUR domain got blocked, the recipient is still a good lead.
        Deleting them would be destroying data over a sending fault."""
        for reason, (_meaning, category, action) in bc.REASONS.items():
            if category in (bc.REPUTATION, bc.AUTH, bc.CONTENT):
                self.assertNotEqual(action, bc.SUPPRESS, reason)

    def test_transient_never_suppresses(self):
        for reason, (_m, category, action) in bc.REASONS.items():
            if category == bc.TRANSIENT:
                self.assertNotEqual(action, bc.SUPPRESS, reason)

    def test_data_faults_never_pause_a_sending_domain(self):
        """A dead address says nothing about your domain's health."""
        for reason, (_m, category, action) in bc.REASONS.items():
            if category == bc.DATA:
                self.assertNotEqual(action, bc.PAUSE, reason)


class TestVocabulary(unittest.TestCase):

    def test_every_rule_points_at_a_known_reason(self):
        for rule in bc.RULES:
            self.assertIn(rule.reason, bc.REASONS, rule.rx.pattern[:40])

    def test_every_reason_has_a_plain_english_meaning(self):
        for reason, (meaning, _c, _a) in bc.REASONS.items():
            self.assertTrue(meaning and meaning[0].isupper(), reason)
            self.assertGreater(len(meaning), 15, f"{reason}: meaning too terse")

    def test_categories_and_actions_are_from_the_fixed_set(self):
        cats = {bc.DATA, bc.REPUTATION, bc.AUTH, bc.CONTENT, bc.RECIPIENT,
                bc.TRANSIENT, bc.UNKNOWN}
        acts = {bc.SUPPRESS, bc.RETRY, bc.RETRY_ONCE, bc.PAUSE, bc.FIXAUTH,
                bc.REWRITE, bc.REVIEW}
        for reason, (_m, category, action) in bc.REASONS.items():
            self.assertIn(category, cats, reason)
            self.assertIn(action, acts, reason)

    def test_rules_are_tier_sorted(self):
        tiers = [r.tier for r in bc.RULES]
        self.assertEqual(tiers, sorted(tiers))

    def test_no_duplicate_rule_patterns(self):
        seen = set()
        for rule in bc.RULES:
            key = (rule.tier, rule.rx.pattern)
            self.assertNotIn(key, seen)
            seen.add(key)


# ------------------------------------------------------------- vendor tokens

class TestVendorTokens(unittest.TestCase):
    """Exchange and the security gateways emit these from code, so they beat
    any English in the same message."""

    def test_recipient_not_found(self):
        self.assertEqual(cat_act("RESOLVER.ADR.RecipientNotFound; Recipient "
                                 "user@example.com not found"),
                         (bc.DATA, bc.SUPPRESS))

    def test_quota_exception(self):
        self.assertEqual(cls("STOREDRV.Deliver.Exception:QuotaExceededException"
                             )["reason"], "mailbox_full")

    def test_transport_rule(self):
        self.assertEqual(cls("TRANSPORT.RULES.RejectMessage")["reason"],
                         "policy_violation")

    def test_mail_loop(self):
        self.assertEqual(cls("Hop count exceeded - possible mail loop ATTR34"
                             )["reason"], "mail_loop")

    def test_sophos_gateway_code(self):
        self.assertEqual(cls("XGEMAIL_0009 Command rejected")["reason"], "blocked")

    def test_open_xchange_code(self):
        self.assertEqual(cls("Recipient rejected - OXSUS001_403")["reason"], "blocked")

    def test_token_beats_conflicting_prose(self):
        r = cls("user unknown STOREDRV.Deliver.Exception:QuotaExceededException")
        self.assertEqual(r["reason"], "mailbox_full")
        self.assertEqual(r["_tier"], bc.T_TOKEN)


class TestRestrictedRecipient(unittest.TestCase):
    """The address exists and the domain is healthy, but it will never accept
    outside mail. Not the sender's fault, and retrying is pointless."""

    def test_group_only_accepts_internal(self):
        self.assertEqual(cat_act("5.7.133 RESOLVER.RST."
                                 "SenderNotAuthenticatedForGroup"),
                         (bc.RECIPIENT, bc.SUPPRESS))

    def test_external_forwarding_blocked(self):
        self.assertEqual(cls("5.7.520 Access denied, Your organization does not "
                             "allow external forwarding")["reason"],
                         "restricted_recipient")

    def test_partner_connector_only(self):
        self.assertEqual(cls("TenantInboundAttribution; Rejecting. Recipient has "
                             "a partner connector with RestrictDomainsToIPAddresses"
                             )["reason"], "restricted_recipient")

    def test_challenge_response_gate(self):
        self.assertEqual(cls("READ THIS: Delivery will ONLY occur if you click "
                             "on this link")["reason"], "restricted_recipient")

    def test_never_pauses_a_domain(self):
        for t in ("5.7.520 external forwarding",
                  "5.7.133 RESOLVER.RST.SenderNotAuthenticatedForGroup"):
            with self.subTest(t=t):
                self.assertNotEqual(cls(t)["action"], bc.PAUSE)


# ------------------------------------------------------------- the full mailbox

class TestMailboxFull(unittest.TestCase):
    """A full mailbox that the receiver also calls inactive is an abandoned
    account, not a mailbox that will drain."""

    def test_permanent_and_inactive_is_abandoned(self):
        r = cls("552 5.2.2 The recipient's inbox is out of storage space and "
                "inactive. Please direct the recipient to OverQuotaPerm")
        self.assertEqual((r["reason"], r["category"], r["action"]),
                         ("mailbox_full_abandoned", bc.DATA, bc.SUPPRESS))

    def test_temporary_full_is_retried_not_suppressed(self):
        r = cls("452 4.2.2 The recipient's inbox is out of storage space")
        self.assertEqual(r["reason"], "mailbox_full")
        self.assertNotEqual(r["action"], bc.SUPPRESS)

    def test_permanent_without_inactivity_is_not_abandoned(self):
        r = cls("552 5.2.2 Mailbox full")
        self.assertEqual(r["reason"], "mailbox_full")

    def test_plain_over_quota_is_not_abandoned(self):
        self.assertEqual(cls("user is over quota")["reason"], "mailbox_full")


# ------------------------------------------------------------------ blocklists

class TestBlocklists(unittest.TestCase):

    def test_spamhaus(self):
        r = cls("554 5.7.1 Sender address blocked using dbl.spamhaus.org")
        self.assertEqual((r["reason"], r["category"], r["action"]),
                         ("blocklisted", bc.REPUTATION, bc.PAUSE))
        self.assertEqual(r["blocklist"], "Spamhaus")

    def test_hostnames_roll_up_to_the_operator(self):
        """uri.cal1 and uri.vir1 are one listing to fix, not two."""
        r = cls("blocked using uri.cal1.sophosxl.com and uri.vir1.sophosxl.com")
        self.assertEqual(r["blocklist"], "Sophos XL")

    def test_several_operators_are_all_named(self):
        r = cls("listed on dbl.spamhaus.org and multi.surbl.org")
        self.assertIn("Spamhaus", r["blocklist"])
        self.assertIn("SURBL", r["blocklist"])

    def test_blocklist_beats_a_status_code(self):
        r = cls("550 5.1.1 rejected; blocked using dbl.spamhaus.org")
        self.assertEqual(r["reason"], "blocklisted")
        self.assertEqual(r["_tier"], bc.T_BLOCKLIST)


# ---------------------------------------------------------------- status codes

class TestStatusCodes(unittest.TestCase):

    def test_microsoft_ip_reputation(self):
        self.assertEqual(cat_act("550 5.7.708 Access denied, traffic not "
                                 "accepted from this IP"),
                         (bc.REPUTATION, bc.PAUSE))

    def test_gmail_unauthenticated_is_fixable_today(self):
        self.assertEqual(cat_act("550 5.7.26 Unauthenticated email is not accepted"),
                         (bc.AUTH, bc.FIXAUTH))

    def test_gmail_rate_pattern(self):
        self.assertEqual(cls("421 4.7.28 unusual rate of unsolicited mail"
                             )["reason"], "rate_limited")

    def test_user_unknown_codes(self):
        for code in ("5.1.1", "5.1.2", "5.1.3", "5.1.10"):
            with self.subTest(code=code):
                self.assertEqual(cls(f"550 {code} bad destination")["reason"],
                                 "user_unknown")

    def test_codes_are_extracted(self):
        r = cls("550 5.7.708 denied")
        self.assertEqual((r["smtp_code"], r["status_code"]), ("550", "5.7.708"))


# ------------------------------------------------------ wrapper / remote split

class TestLayerSplit(unittest.TestCase):

    def test_split(self):
        w, rem = bc.split_layers("5.7.350 detected as spam -> 554 5.7.1 rejected")
        self.assertTrue(w.startswith("5.7.350"))
        self.assertTrue(rem.startswith("554"))

    def test_no_arrow_is_all_remote(self):
        self.assertEqual(bc.split_layers("550 user unknown"), ("", "550 user unknown"))

    def test_remote_half_wins_over_the_relay_guess(self):
        r = cls("5.1.351 Remote server returned unknown recipient or mailbox "
                "unavailable -> 550 Requested action not taken: mailbox "
                "unavailable;Reject due to policy restrictions.")
        self.assertEqual(r["reason"], "policy_violation")

    def test_wrapper_used_when_the_remote_says_nothing(self):
        r = cls("5.7.350 Remote server returned message detected as spam -> "
                "550 delivery failed")
        self.assertEqual(r["reason"], "spam_detected")

    def test_expiry_wrapper_keeps_the_underlying_cause(self):
        r = cls("5.4.300 Message expired -> 452 4.2.2 The recipient's inbox is "
                "out of storage space")
        self.assertEqual(r["reason"], "mailbox_full")


# --------------------------------------------------------------------- phrases

class TestPhrases(unittest.TestCase):

    def test_user_unknown_variants(self):
        for t in ("550 User unknown", "no such user here", "mailbox not found",
                  "Email address could not be found, or was misspelled",
                  "Email Address Invalid or Incorrect",
                  "1 Requested mail action aborted, mailbox not found"):
            with self.subTest(t=t):
                self.assertEqual(cls(t)["reason"], "user_unknown")

    def test_reputation_phrases(self):
        r = cls("554 Your access to this mail system has been rejected due to "
                "poor reputation of a domain used in message transfer")
        self.assertEqual(r["reason"], "bad_reputation")

    def test_gmail_low_reputation(self):
        r = cls("550 5.7.1 Gmail has detected that this message is likely "
                "suspicious due to the very low reputation of the sending domain")
        self.assertEqual(r["category"], bc.REPUTATION)

    def test_spam_phrases(self):
        for t in ('550 "The mail server detected your message as spam"',
                  "Message content rejected as Spam",
                  "Message not accepted as it appears to be spam"):
            with self.subTest(t=t):
                self.assertEqual(cls(t)["reason"], "spam_detected")

    def test_relay_denied_is_a_data_problem(self):
        self.assertEqual(cat_act("554 5.7.1 <a@example.com>: Relay access denied"),
                         (bc.DATA, bc.SUPPRESS))

    def test_suspended_variants(self):
        for t in ("User's mailbox is disabled", "Disabled recipient address",
                  "user disabled; cannot receive new mail"):
            with self.subTest(t=t):
                self.assertEqual(cls(t)["reason"], "suspended")


# ------------------------------------------------------------------ precedence

class TestPrecedence(unittest.TestCase):

    def test_generic_code_loses_to_an_explicit_phrase(self):
        self.assertEqual(cls("554 5.7.1 detected your message as spam")["reason"],
                         "spam_detected")

    def test_generic_code_still_catches_a_bare_message(self):
        r = cls("550 5.7.1 Service unavailable")
        self.assertEqual(r["reason"], "blocked")
        self.assertEqual(r["_tier"], bc.T_GENERIC)

    def test_bare_access_denied_does_not_pause_a_domain(self):
        """Exchange returns this for a dead address AND for a tenant block.
        2% of a production corpus looks like this, so guessing is expensive."""
        r = cls("Recipient address rejected: Access denied. For more information "
                "see https://aka.ms/EXOSmtpErrors")
        self.assertEqual(r["action"], bc.REVIEW)
        self.assertNotEqual(r["action"], bc.PAUSE)

    def test_deterministic(self):
        t = "5.7.350 detected as spam -> 554 5.7.1 blocked using dbl.spamhaus.org"
        self.assertEqual(cls(t), cls(t))


# ---------------------------------------------------------------- confidence

class TestConfidence(unittest.TestCase):

    def test_machine_signals_are_high_confidence(self):
        for t in ("RESOLVER.ADR.RecipientNotFound",
                  "blocked using dbl.spamhaus.org",
                  "550 5.7.708 denied"):
            with self.subTest(t=t):
                self.assertEqual(cls(t)["confidence"], "high")

    def test_a_phrase_is_medium(self):
        self.assertEqual(cls("the mailbox is full")["confidence"], "medium")

    def test_a_bare_code_is_low(self):
        self.assertEqual(cls("550 nope")["confidence"], "low")

    def test_unreadable_has_no_confidence(self):
        self.assertEqual(cls("qqqq zzzz")["confidence"], "none")


# ------------------------------------------------------------------ extraction

class TestExtraction(unittest.TestCase):

    def test_provider_fingerprints(self):
        self.assertEqual(cls("RESOLVER.ADR.RecipientNotFound")["rejected_by"],
                         "microsoft")
        self.assertEqual(cls("550 rejected - gsmtp")["rejected_by"], "google")

    def test_recipient_host_is_carried_through(self):
        r = cls("550 5.1.1 user unknown", host="GOOGLE_WORKSPACE")
        self.assertEqual(r["recipient_host"], "GOOGLE_WORKSPACE")

    def test_rejecting_system_and_host_can_differ(self):
        """A Google-hosted domain behind a third-party filter."""
        r = cls("550 rejected by proofpoint filter", host="GOOGLE_WORKSPACE")
        self.assertEqual(r["rejected_by"], "proofpoint")
        self.assertEqual(r["recipient_host"], "GOOGLE_WORKSPACE")

    def test_empty_and_none(self):
        for v in ("", None, "   "):
            with self.subTest(v=v):
                self.assertEqual(cls(v)["reason"], "empty")

    def test_unreadable_is_admitted_not_guessed(self):
        r = cls("something entirely unparseable")
        self.assertEqual((r["reason"], r["action"]), ("unknown", bc.REVIEW))


# ------------------------------------------------------------ column detection

class TestColumnDetection(unittest.TestCase):
    """Every sequencer invents its own schema, so the bounce column is found by
    what the values look like, not by hoping for a familiar name."""

    def test_finds_an_oddly_named_bounce_column(self):
        rows = [{"id": "1", "who": "a@example.com",
                 "smtp_response_text": "550 5.1.1 user unknown, address rejected"},
                {"id": "2", "who": "b@example.com",
                 "smtp_response_text": "552 5.2.2 mailbox full quota exceeded"}]
        found = bc.detect_columns(list(rows[0]), rows)
        self.assertEqual(found["bounce"], "smtp_response_text")

    def test_prefers_bounce_text_over_a_long_unrelated_column(self):
        rows = [{"notes": "Spoke to them at the conference last year about "
                          "renewing their annual maintenance contract",
                 "bounce_msg": "550 5.1.1 user unknown"}] * 5
        found = bc.detect_columns(list(rows[0]), rows)
        self.assertEqual(found["bounce"], "bounce_msg")

    def test_finds_host_column_by_its_values(self):
        rows = [{"x": "GOOGLE_WORKSPACE", "b": "550 5.1.1 user unknown"},
                {"x": "MICROSOFT365", "b": "550 mailbox full"}]
        self.assertEqual(bc.detect_columns(list(rows[0]), rows)["host"], "x")

    def test_finds_email_and_date_columns(self):
        rows = [{"email": "a@example.com", "last_sent_at": "2026-09-01",
                 "bounce_msg": "550 5.1.1 user unknown"}] * 3
        found = bc.detect_columns(list(rows[0]), rows)
        self.assertEqual(found["email"], "email")
        self.assertEqual(found["date"], "last_sent_at")

    def test_no_bounce_column_is_reported_not_guessed(self):
        rows = [{"name": "Ada", "city": "London"}] * 3
        self.assertIsNone(bc.detect_columns(list(rows[0]), rows)["bounce"])


# -------------------------------------------------------------------- CSV mode

def _args(**kw):
    d = dict(column=None, host_column=None, outdir=None, report=None,
             suppress_list=None, dump_unknown=None, force=False, quiet=True)
    d.update(kw)
    return argparse.Namespace(**d)


class TestCsv(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bouncesitrep-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write_csv(self, rows, header=("email", "mx", "last_sent_at", "bounce_msg")):
        p = os.path.join(self.tmp, "in.csv")
        with io.open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(header)
            w.writerows(rows)
        return p

    def out_rows(self):
        p = os.path.join(self.tmp, "in - classified.csv")
        with io.open(p, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    def test_columns_appended_originals_kept(self):
        p = self.write_csv([["a@example.com", "GOOGLE_WORKSPACE", "2026-09-01",
                             "550 5.1.1 user unknown"]])
        self.assertEqual(bc.run_csv(p, _args(outdir=self.tmp)), 0)
        r = self.out_rows()[0]
        self.assertEqual(r["bounce_reason"], "user_unknown")
        self.assertEqual(r["bounce_category"], bc.DATA)
        self.assertEqual(r["recipient_host"], "GOOGLE_WORKSPACE")
        self.assertTrue(r["bounce_meaning"])
        self.assertEqual(r["email"], "a@example.com")

    def test_suppression_list_holds_only_dead_addresses(self):
        p = self.write_csv([
            ["dead@example.com", "", "2026-09-01", "550 5.1.1 user unknown"],
            ["good@example.com", "", "2026-09-01",
             "554 5.7.1 blocked using dbl.spamhaus.org"],   # OUR fault, keep them
            ["full@example.com", "", "2026-09-01", "452 4.2.2 mailbox full"],
        ])
        sl = os.path.join(self.tmp, "sup.txt")
        bc.run_csv(p, _args(outdir=self.tmp, suppress_list=sl))
        self.assertEqual(read_lines(sl), ["dead@example.com"])

    def test_suppression_list_is_deduplicated(self):
        p = self.write_csv([["dup@example.com", "", "", "550 5.1.1 user unknown"],
                            ["DUP@example.com", "", "", "550 5.1.1 user unknown"]])
        sl = os.path.join(self.tmp, "sup.txt")
        bc.run_csv(p, _args(outdir=self.tmp, suppress_list=sl))
        self.assertEqual(len(read_lines(sl)), 1)

    def test_report_is_written_and_names_the_problem(self):
        rows = [["a%d@example.com" % i, "GOOGLE_WORKSPACE", "2026-09-0%d" % (i % 9 + 1),
                 "554 5.7.1 blocked using dbl.spamhaus.org"] for i in range(30)]
        p = self.write_csv(rows)
        rp = os.path.join(self.tmp, "diag.md")
        bc.run_csv(p, _args(outdir=self.tmp, report=rp))
        text = read(rp)
        self.assertIn("Bounce diagnosis", text)
        self.assertIn("Spamhaus", text)
        self.assertIn("Your sending is the problem", text)

    def test_report_opens_with_the_banner_and_a_live_version(self):
        rows = [["a%d@example.com" % i, "", "2026-09-01", "550 5.1.1 user unknown"]
                for i in range(30)]
        p = self.write_csv(rows)
        rp = os.path.join(self.tmp, "diag.md")
        bc.run_csv(p, _args(outdir=self.tmp, report=rp))
        text = read(rp)
        self.assertTrue(text.startswith("```"), "banner must be fenced for markdown")
        self.assertIn("\u2588", text, "reticle should render")
        self.assertIn("v" + bc.__version__, text, "version tracks the module")
        self.assertNotIn("{version}", text, "placeholder must be interpolated")

    def test_banner_fits_a_terminal(self):
        widest = max(len(l) for l in bc.BANNER.split("\n"))
        self.assertLessEqual(widest, 80, "banner must not wrap at 80 columns")

    def test_report_says_list_problem_when_it_is_one(self):
        rows = [["a%d@example.com" % i, "", "2026-09-01", "550 5.1.1 user unknown"]
                for i in range(30)]
        p = self.write_csv(rows)
        rp = os.path.join(self.tmp, "diag.md")
        bc.run_csv(p, _args(outdir=self.tmp, report=rp))
        self.assertIn("Your list is the problem", read(rp))

    def test_missing_bounce_column_is_an_error(self):
        p = self.write_csv([["a@example.com", "", "", ""]],
                           header=("email", "mx", "last_sent_at", "notes"))
        self.assertEqual(bc.run_csv(p, _args(outdir=self.tmp)), 1)

    def test_existing_output_not_clobbered(self):
        p = self.write_csv([["a@example.com", "", "", "550 5.1.1 user unknown"]])
        self.assertEqual(bc.run_csv(p, _args(outdir=self.tmp)), 0)
        self.assertEqual(bc.run_csv(p, _args(outdir=self.tmp)), 1)
        self.assertEqual(bc.run_csv(p, _args(outdir=self.tmp, force=True)), 0)

    def test_blank_bounce_text_is_not_dumped_as_unknown(self):
        p = self.write_csv([["a@example.com", "", "", ""],
                            ["b@example.com", "", "", "qqq zzz"]])
        d = os.path.join(self.tmp, "u.txt")
        bc.run_csv(p, _args(outdir=self.tmp, dump_unknown=d))
        self.assertEqual(read_lines(d), ["qqq zzz"])

    def test_newline_inside_bounce_text(self):
        p = self.write_csv([["a@example.com", "", "", "550 5.1.1\nuser unknown"]])
        bc.run_csv(p, _args(outdir=self.tmp))
        self.assertEqual(len(self.out_rows()), 1)


class TestRfc3463Families(unittest.TestCase):
    """The RFC defines whole families this originally had holes in. A code the
    tool does not know falls through to prose, which is a worse guess."""

    def test_address_family(self):
        self.assertEqual(cls("550 5.1.4 address ambiguous")["reason"],
                         "ambiguous_address")
        for code in ("5.1.7", "5.1.8"):
            with self.subTest(code=code):
                r = cls(f"550 {code} bad sender address")
                self.assertEqual((r["reason"], r["category"]),
                                 ("sender_address_bad", bc.AUTH))

    def test_your_own_return_address_is_your_problem(self):
        """5.1.7/5.1.8 are about the SENDER, not the recipient. Suppressing
        the recipient over it would delete a good lead."""
        r = cls("550 5.1.8 Bad sender's system address")
        self.assertNotEqual(r["action"], bc.SUPPRESS)
        self.assertEqual(r["action"], bc.FIXAUTH)

    def test_mailbox_family(self):
        self.assertEqual(cls("552 5.2.3 message length exceeds limit")["reason"],
                         "email_too_large")
        self.assertEqual(cls("550 5.2.4 mailing list expansion problem")["reason"],
                         "list_expansion")

    def test_network_family(self):
        self.assertEqual(cls("550 5.4.6 routing loop detected")["reason"], "mail_loop")
        self.assertEqual(cls("550 5.4.4 unable to route")["reason"], "host_unknown")
        for code in ("4.4.0", "4.4.2", "4.4.5"):
            with self.subTest(code=code):
                self.assertEqual(cls(f"450 {code} network trouble")["category"],
                                 bc.TRANSIENT)

    def test_protocol_family(self):
        self.assertEqual(cls("550 5.5.3 too many recipients")["reason"],
                         "protocol_error")
        for code in ("5.5.0", "5.5.1", "5.5.2", "5.5.4"):
            with self.subTest(code=code):
                self.assertEqual(cls(f"550 {code} protocol trouble")["reason"],
                                 "protocol_error")

    def test_media_family(self):
        for code in ("5.6.0", "5.6.1", "5.6.3", "5.6.5"):
            with self.subTest(code=code):
                r = cls(f"550 {code} conversion problem")
                self.assertEqual((r["reason"], r["category"]),
                                 ("media_error", bc.CONTENT))

    def test_security_family(self):
        self.assertEqual(cls("550 5.7.0 security policy")["reason"], "policy_violation")
        self.assertEqual(cls("550 5.7.2 list expansion prohibited")["reason"],
                         "list_expansion")
        for code in ("5.7.4", "5.7.5", "5.7.6", "5.7.7"):
            with self.subTest(code=code):
                self.assertEqual(cls(f"550 {code} crypto failure")["reason"],
                                 "crypto_error")


class TestProviderCodes(unittest.TestCase):
    """Yahoo, AOL and Verizon put short codes in brackets that carry more than
    the 4xx/5xx class does."""

    def test_yahoo_policy_refusal(self):
        r = cls("554 5.7.9 Message not accepted for policy reasons")
        self.assertEqual((r["reason"], r["category"]),
                         ("policy_violation", bc.REPUTATION))

    def test_yahoo_throttle_is_temporary_not_a_domain_pause(self):
        """A TSS deferral means slow down. Pausing the domain over a 4xx would
        cost sending capacity for a problem that clears on its own."""
        r = cls("421 4.7.0 [TSS04] Messages temporarily deferred due to "
                "unexpected volume")
        self.assertEqual(r["reason"], "throttled")
        self.assertEqual(r["action"], bc.RETRY)
        self.assertNotEqual(r["action"], bc.PAUSE)

    def test_yahoo_ts_codes(self):
        for code in ("TS01", "TS03", "TSS01", "TSS04"):
            with self.subTest(code=code):
                self.assertEqual(cls(f"421 4.7.0 {code} deferred")["reason"],
                                 "throttled")

    def test_verizon_policy_code(self):
        self.assertEqual(cls("554 PH01 message rejected")["reason"], "blocked")

    def test_yahoo_blocklist_code(self):
        self.assertEqual(cls("553 5.7.1 DNSBL:ATTRBL 521 listed")["reason"],
                         "blocklisted")


class TestPathHandling(unittest.TestCase):
    """A path that does not exist is a typo. Classifying it as bounce text
    hides the mistake and sends you looking in the wrong place."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bouncesitrep-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_main(self, argv):
        import contextlib
        old = sys.argv
        sys.argv = ["bouncesitrep"] + argv
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                return bc.main(), err.getvalue()
        finally:
            sys.argv = old

    def test_missing_csv_is_an_error(self):
        code, err = self.run_main([os.path.join(self.tmp, "nope.csv")])
        self.assertEqual(code, 1)
        self.assertIn("no such file", err)

    def test_a_directory_named_csv_is_an_error(self):
        d = os.path.join(self.tmp, "adir.csv")
        os.makedirs(d)
        code, err = self.run_main([d])
        self.assertEqual(code, 1)
        self.assertIn("directory", err)

    def test_a_real_message_is_still_classified(self):
        code, err = self.run_main(["550 5.1.1 user unknown"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
