#!/usr/bin/env python3
# Copyright (C) 2026 miralemalic
# SPDX-License-Identifier: MIT

"""Tests for bouncesitrep.

    python3 -m unittest discover -s tests -v

Fixtures are real bounce text with the addresses and sending domains swapped
out.  No real address, domain or campaign name appears in this repo.
"""

import io
import os
import csv
import sys
import shutil
import argparse
import tempfile
import unittest
import contextlib

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bouncesitrep as bc  # noqa: E402

bc.QUIET = True

HEADER = ('email', 'mx', 'last_sent_at', 'bounce_msg')
SPAMHAUS = '554 5.7.1 blocked using dbl.spamhaus.org'
DEAD = '550 5.1.1 user unknown'


def read(path):
    with open(path, encoding='utf-8') as fp:
        return fp.read()


def read_lines(path):
    return [line.strip() for line in read(path).splitlines() if line.strip()]


def classify(text, host=''):
    return bc.classify(text, recipient_host=host)


def reason_of(text):
    return bc.classify(text)['reason']


def category_action(text):
    result = bc.classify(text)
    return result['category'], result['action']


def make_args(**kws):
    defaults = dict(
        column=None, host_column=None, outdir=None, report=None,
        suppress_list=None, pause_list=None, dump_unknown=None,
        force=False, quiet=True, all_rows=False, banner=False,
        no_banner=True, fail_over=None)
    defaults.update(kws)
    return argparse.Namespace(**defaults)


def blanks(count):
    # Leads that were mailed and never bounced.
    return [[f'a{i}@example.com', '', '2026-09-01', ''] for i in range(count)]


def bounces(count, text=DEAD):
    return [[f'b{i}@example.com', '', '2026-09-01', text]
            for i in range(count)]


class FileTestCase(unittest.TestCase):
    """Base class for tests that write an export and run it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='bouncesitrep-test-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, 'w', newline='', encoding='utf-8') as fp:
            fp.write(text)
        return path

    def write_csv(self, rows, header=HEADER):
        path = os.path.join(self.tmp, 'in.csv')
        with open(path, 'w', newline='', encoding='utf-8') as fp:
            writer = csv.writer(fp, lineterminator='\n')
            writer.writerow(header)
            writer.writerows(rows)
        return path

    def run_csv(self, path, **kws):
        kws.setdefault('outdir', self.tmp)
        return bc.run_csv(path, make_args(**kws))

    def report_for(self, rows):
        report = os.path.join(self.tmp, 'diag.md')
        self.run_csv(self.write_csv(rows), report=report, force=True)
        return read(report)

    def output_rows(self, name='in - classified.csv'):
        path = os.path.join(self.tmp, name)
        with open(path, newline='', encoding='utf-8') as fp:
            return list(csv.DictReader(fp))


class TestSafetyRails(unittest.TestCase):
    """Walk every reason in the table, since these mistakes cost the most."""

    def test_never_suppress_a_lead_over_your_own_problem(self):
        # A blocked sending domain says nothing about the recipient, who is
        # still a good lead.
        for reason, (meaning, category, action) in bc.REASONS.items():
            if category in bc.SENDING_SIDE:
                self.assertNotEqual(action, bc.SUPPRESS, reason)

    def test_transient_never_suppresses(self):
        for reason, (meaning, category, action) in bc.REASONS.items():
            if category == bc.TRANSIENT:
                self.assertNotEqual(action, bc.SUPPRESS, reason)

    def test_data_faults_never_pause_a_sending_domain(self):
        # A dead address says nothing about your domain's health.
        for reason, (meaning, category, action) in bc.REASONS.items():
            if category == bc.DATA:
                self.assertNotEqual(action, bc.PAUSE, reason)


class TestVocabulary(unittest.TestCase):

    def test_every_rule_points_at_a_known_reason(self):
        for rule in bc.RULES:
            self.assertIn(rule.reason, bc.REASONS, rule.cre.pattern[:40])

    def test_every_reason_has_a_plain_english_meaning(self):
        for reason, (meaning, category, action) in bc.REASONS.items():
            self.assertTrue(meaning and meaning[0].isupper(), reason)
            self.assertGreater(len(meaning), 15, reason)

    def test_categories_and_actions_are_from_the_fixed_set(self):
        categories = {'data', 'reputation', 'authentication', 'content',
                      'recipient', 'transient', 'unknown'}
        actions = {'suppress', 'retry_later', 'retry_once', 'pause_domain',
                   'fix_auth', 'rewrite_copy', 'review'}
        for reason, (meaning, category, action) in bc.REASONS.items():
            self.assertIn(category, categories, reason)
            self.assertIn(action, actions, reason)

    def test_rules_are_tier_sorted(self):
        tiers = [rule.tier for rule in bc.RULES]
        self.assertEqual(tiers, sorted(tiers))

    def test_no_duplicate_rule_patterns(self):
        seen = set()
        for rule in bc.RULES:
            key = (rule.tier, rule.cre.pattern)
            self.assertNotIn(key, seen)
            seen.add(key)


class TestVendorTokens(unittest.TestCase):
    """Exchange and the security gateways emit these from code, so they beat
    any English in the same message."""

    def test_recipient_not_found(self):
        self.assertEqual(
            category_action('RESOLVER.ADR.RecipientNotFound; Recipient '
                            'user@example.com not found'),
            (bc.DATA, bc.SUPPRESS))

    def test_quota_exception(self):
        self.assertEqual(
            reason_of('STOREDRV.Deliver.Exception:QuotaExceededException'),
            'mailbox_full')

    def test_transport_rule(self):
        self.assertEqual(reason_of('TRANSPORT.RULES.RejectMessage'),
                         'policy_violation')

    def test_mail_loop(self):
        self.assertEqual(
            reason_of('Hop count exceeded - possible mail loop ATTR34'),
            'mail_loop')

    def test_sophos_gateway_code(self):
        self.assertEqual(reason_of('XGEMAIL_0009 Command rejected'),
                         'blocked')

    def test_open_xchange_code(self):
        self.assertEqual(reason_of('Recipient rejected - OXSUS001_403'),
                         'blocked')

    def test_token_beats_conflicting_prose(self):
        result = classify(
            'user unknown STOREDRV.Deliver.Exception:QuotaExceededException')
        self.assertEqual(result['reason'], 'mailbox_full')
        self.assertEqual(result['_tier'], bc.T_TOKEN)


class TestRestrictedRecipient(unittest.TestCase):
    """The address exists and the domain is healthy, but it will never accept
    outside mail.  Not the sender's fault, and retrying is pointless."""

    def test_group_only_accepts_internal(self):
        self.assertEqual(
            category_action('5.7.133 RESOLVER.RST.'
                            'SenderNotAuthenticatedForGroup'),
            (bc.RECIPIENT, bc.SUPPRESS))

    def test_external_forwarding_blocked(self):
        self.assertEqual(
            reason_of('5.7.520 Access denied, Your organization does not '
                      'allow external forwarding'),
            'restricted_recipient')

    def test_partner_connector_only(self):
        self.assertEqual(
            reason_of('TenantInboundAttribution; Rejecting. Recipient has a '
                      'partner connector with RestrictDomainsToIPAddresses'),
            'restricted_recipient')

    def test_challenge_response_gate(self):
        self.assertEqual(
            reason_of('READ THIS: Delivery will ONLY occur if you click on '
                      'this link'),
            'restricted_recipient')

    def test_never_pauses_a_domain(self):
        for text in ('5.7.520 external forwarding',
                     '5.7.133 RESOLVER.RST.SenderNotAuthenticatedForGroup'):
            with self.subTest(text=text):
                self.assertNotEqual(classify(text)['action'], bc.PAUSE)


class TestMailboxFull(unittest.TestCase):
    """A full mailbox that the receiver also calls inactive is an abandoned
    account, not a mailbox that will drain."""

    def test_permanent_and_inactive_is_abandoned(self):
        result = classify(
            "552 5.2.2 The recipient's inbox is out of storage space and "
            'inactive. Please direct the recipient to OverQuotaPerm')
        self.assertEqual(
            (result['reason'], result['category'], result['action']),
            ('mailbox_full_abandoned', bc.DATA, bc.SUPPRESS))

    def test_temporary_full_is_retried_not_suppressed(self):
        result = classify(
            "452 4.2.2 The recipient's inbox is out of storage space")
        self.assertEqual(result['reason'], 'mailbox_full')
        self.assertNotEqual(result['action'], bc.SUPPRESS)

    def test_permanent_without_inactivity_is_not_abandoned(self):
        self.assertEqual(reason_of('552 5.2.2 Mailbox full'), 'mailbox_full')

    def test_plain_over_quota_is_not_abandoned(self):
        self.assertEqual(reason_of('user is over quota'), 'mailbox_full')


class TestBlocklists(unittest.TestCase):

    def test_spamhaus(self):
        result = classify(SPAMHAUS)
        self.assertEqual(
            (result['reason'], result['category'], result['action']),
            ('blocklisted', bc.REPUTATION, bc.PAUSE))
        self.assertEqual(result['blocklist'], 'Spamhaus')

    def test_hostnames_roll_up_to_the_operator(self):
        # uri.cal1 and uri.vir1 are one listing to fix, not two.
        result = classify('blocked using uri.cal1.sophosxl.com and '
                          'uri.vir1.sophosxl.com')
        self.assertEqual(result['blocklist'], 'Sophos XL')

    def test_several_operators_are_all_named(self):
        result = classify('listed on dbl.spamhaus.org and multi.surbl.org')
        self.assertIn('Spamhaus', result['blocklist'])
        self.assertIn('SURBL', result['blocklist'])

    def test_blocklist_beats_a_status_code(self):
        result = classify('550 5.1.1 rejected; blocked using dbl.spamhaus.org')
        self.assertEqual(result['reason'], 'blocklisted')
        self.assertEqual(result['_tier'], bc.T_BLOCKLIST)


class TestStatusCodes(unittest.TestCase):

    def test_microsoft_ip_reputation(self):
        self.assertEqual(
            category_action('550 5.7.708 Access denied, traffic not '
                            'accepted from this IP'),
            (bc.REPUTATION, bc.PAUSE))

    def test_gmail_unauthenticated_is_fixable_today(self):
        self.assertEqual(
            category_action('550 5.7.26 Unauthenticated email is not '
                            'accepted'),
            (bc.AUTH, bc.FIXAUTH))

    def test_gmail_rate_pattern(self):
        self.assertEqual(
            reason_of('421 4.7.28 unusual rate of unsolicited mail'),
            'rate_limited')

    def test_user_unknown_codes(self):
        for code in ('5.1.1', '5.1.2', '5.1.3', '5.1.10'):
            with self.subTest(code=code):
                self.assertEqual(reason_of(f'550 {code} bad destination'),
                                 'user_unknown')

    def test_codes_are_extracted(self):
        result = classify('550 5.7.708 denied')
        self.assertEqual((result['smtp_code'], result['status_code']),
                         ('550', '5.7.708'))


class TestLayerSplit(unittest.TestCase):

    def test_split(self):
        wrapper, remote = bc.split_layers(
            '5.7.350 detected as spam -> 554 5.7.1 rejected')
        self.assertTrue(wrapper.startswith('5.7.350'))
        self.assertTrue(remote.startswith('554'))

    def test_no_arrow_is_all_remote(self):
        self.assertEqual(bc.split_layers(DEAD), ('', DEAD))

    def test_remote_half_wins_over_the_relay_guess(self):
        result = classify(
            '5.1.351 Remote server returned unknown recipient or mailbox '
            'unavailable -> 550 Requested action not taken: mailbox '
            'unavailable;Reject due to policy restrictions.')
        self.assertEqual(result['reason'], 'policy_violation')

    def test_wrapper_used_when_the_remote_says_nothing(self):
        result = classify('5.7.350 Remote server returned message detected '
                          'as spam -> 550 delivery failed')
        self.assertEqual(result['reason'], 'spam_detected')

    def test_expiry_wrapper_keeps_the_underlying_cause(self):
        result = classify("5.4.300 Message expired -> 452 4.2.2 The "
                          "recipient's inbox is out of storage space")
        self.assertEqual(result['reason'], 'mailbox_full')


class TestPhrases(unittest.TestCase):

    def test_user_unknown_variants(self):
        for text in ('550 User unknown', 'no such user here',
                     'mailbox not found',
                     'Email address could not be found, or was misspelled',
                     'Email Address Invalid or Incorrect',
                     '1 Requested mail action aborted, mailbox not found'):
            with self.subTest(text=text):
                self.assertEqual(reason_of(text), 'user_unknown')

    def test_reputation_phrases(self):
        result = classify(
            '554 Your access to this mail system has been rejected due to '
            'poor reputation of a domain used in message transfer')
        self.assertEqual(result['reason'], 'bad_reputation')

    def test_gmail_low_reputation(self):
        result = classify(
            '550 5.7.1 Gmail has detected that this message is likely '
            'suspicious due to the very low reputation of the sending domain')
        self.assertEqual(result['category'], bc.REPUTATION)

    def test_spam_phrases(self):
        for text in ('550 "The mail server detected your message as spam"',
                     'Message content rejected as Spam',
                     'Message not accepted as it appears to be spam'):
            with self.subTest(text=text):
                self.assertEqual(reason_of(text), 'spam_detected')

    def test_relay_denied_is_a_data_problem(self):
        self.assertEqual(
            category_action('554 5.7.1 <a@example.com>: Relay access denied'),
            (bc.DATA, bc.SUPPRESS))

    def test_suspended_variants(self):
        for text in ("User's mailbox is disabled",
                     'Disabled recipient address',
                     'user disabled; cannot receive new mail'):
            with self.subTest(text=text):
                self.assertEqual(reason_of(text), 'suspended')


class TestPrecedence(unittest.TestCase):

    def test_generic_code_loses_to_an_explicit_phrase(self):
        self.assertEqual(reason_of('554 5.7.1 detected your message as spam'),
                         'spam_detected')

    def test_generic_code_still_catches_a_bare_message(self):
        result = classify('550 5.7.1 Service unavailable')
        self.assertEqual(result['reason'], 'blocked')
        self.assertEqual(result['_tier'], bc.T_GENERIC)

    def test_bare_access_denied_does_not_pause_a_domain(self):
        # Exchange returns this for a dead address and for a tenant block
        # alike.  It is 2% of a production corpus, so a wrong guess is
        # expensive.
        result = classify('Recipient address rejected: Access denied. For '
                          'more information see https://aka.ms/EXOSmtpErrors')
        self.assertEqual(result['action'], bc.REVIEW)
        self.assertNotEqual(result['action'], bc.PAUSE)

    def test_deterministic(self):
        text = ('5.7.350 detected as spam -> 554 5.7.1 blocked using '
                'dbl.spamhaus.org')
        self.assertEqual(classify(text), classify(text))


class TestConfidence(unittest.TestCase):

    def test_machine_signals_are_high_confidence(self):
        for text in ('RESOLVER.ADR.RecipientNotFound',
                     'blocked using dbl.spamhaus.org',
                     '550 5.7.708 denied'):
            with self.subTest(text=text):
                self.assertEqual(classify(text)['confidence'], 'high')

    def test_a_phrase_is_medium(self):
        self.assertEqual(classify('the mailbox is full')['confidence'],
                         'medium')

    def test_a_bare_code_is_low(self):
        self.assertEqual(classify('550 nope')['confidence'], 'low')

    def test_unreadable_has_no_confidence(self):
        self.assertEqual(classify('qqqq zzzz')['confidence'], 'none')


class TestExtraction(unittest.TestCase):

    def test_provider_fingerprints(self):
        self.assertEqual(
            classify('RESOLVER.ADR.RecipientNotFound')['rejected_by'],
            'microsoft')
        self.assertEqual(classify('550 rejected - gsmtp')['rejected_by'],
                         'google')

    def test_recipient_host_is_carried_through(self):
        result = classify(DEAD, host='GOOGLE_WORKSPACE')
        self.assertEqual(result['recipient_host'], 'GOOGLE_WORKSPACE')

    def test_rejecting_system_and_host_can_differ(self):
        # A Google-hosted domain behind a third-party filter.
        result = classify('550 rejected by proofpoint filter',
                          host='GOOGLE_WORKSPACE')
        self.assertEqual(result['rejected_by'], 'proofpoint')
        self.assertEqual(result['recipient_host'], 'GOOGLE_WORKSPACE')

    def test_empty_and_none(self):
        for value in ('', None, '   '):
            with self.subTest(value=value):
                self.assertEqual(reason_of(value), 'empty')

    def test_unreadable_is_admitted_not_guessed(self):
        result = classify('something entirely unparseable')
        self.assertEqual((result['reason'], result['action']),
                         ('unknown', bc.REVIEW))


class TestColumnDetection(unittest.TestCase):
    """Every sequencer invents its own schema, so the bounce column is found
    by what its values look like, not by hoping for a familiar name."""

    def detect(self, rows):
        return bc.detect_columns(list(rows[0]), rows)

    def test_finds_an_oddly_named_bounce_column(self):
        rows = [
            {'id': '1', 'who': 'a@example.com',
             'smtp_response_text': '550 5.1.1 user unknown, address rejected'},
            {'id': '2', 'who': 'b@example.com',
             'smtp_response_text': '552 5.2.2 mailbox full quota exceeded'},
            ]
        self.assertEqual(self.detect(rows)['bounce'], 'smtp_response_text')

    def test_prefers_bounce_text_over_a_long_unrelated_column(self):
        rows = [{'notes': 'Spoke to them at the conference last year about '
                          'renewing their annual maintenance contract',
                 'bounce_msg': DEAD}] * 5
        self.assertEqual(self.detect(rows)['bounce'], 'bounce_msg')

    def test_finds_host_column_by_its_values(self):
        rows = [{'x': 'GOOGLE_WORKSPACE', 'b': DEAD},
                {'x': 'MICROSOFT365', 'b': '550 mailbox full'}]
        self.assertEqual(self.detect(rows)['host'], 'x')

    def test_finds_email_and_date_columns(self):
        rows = [{'email': 'a@example.com', 'last_sent_at': '2026-09-01',
                 'bounce_msg': DEAD}] * 3
        found = self.detect(rows)
        self.assertEqual(found['email'], 'email')
        self.assertEqual(found['date'], 'last_sent_at')

    def test_well_named_column_survives_an_all_blank_sample(self):
        # Most rows in a whole-campaign export never bounced, so the sample
        # can be all blanks.  The column is still the right one.
        rows = [{'email': 'a@example.com', 'bounce_msg': ''}] * 200
        self.assertEqual(self.detect(rows)['bounce'], 'bounce_msg')

    def test_no_bounce_column_is_reported_not_guessed(self):
        rows = [{'name': 'Ada', 'city': 'London'}] * 3
        self.assertIsNone(self.detect(rows)['bounce'])


class TestCsv(FileTestCase):

    def test_columns_appended_originals_kept(self):
        path = self.write_csv(
            [['a@example.com', 'GOOGLE_WORKSPACE', '2026-09-01', DEAD]])
        self.assertEqual(self.run_csv(path), 0)
        row = self.output_rows()[0]
        self.assertEqual(row['bounce_reason'], 'user_unknown')
        self.assertEqual(row['bounce_category'], bc.DATA)
        self.assertEqual(row['recipient_host'], 'GOOGLE_WORKSPACE')
        self.assertTrue(row['bounce_meaning'])
        self.assertEqual(row['email'], 'a@example.com')

    def test_suppression_list_holds_only_dead_addresses(self):
        path = self.write_csv([
            ['dead@example.com', '', '2026-09-01', DEAD],
            # Our own fault, so this lead stays.
            ['good@example.com', '', '2026-09-01', SPAMHAUS],
            ['full@example.com', '', '2026-09-01', '452 4.2.2 mailbox full'],
            ])
        dead = os.path.join(self.tmp, 'sup.txt')
        self.run_csv(path, suppress_list=dead)
        self.assertEqual(read_lines(dead), ['dead@example.com'])

    def test_suppression_list_is_deduplicated(self):
        path = self.write_csv([['dup@example.com', '', '', DEAD],
                               ['DUP@example.com', '', '', DEAD]])
        dead = os.path.join(self.tmp, 'sup.txt')
        self.run_csv(path, suppress_list=dead)
        self.assertEqual(len(read_lines(dead)), 1)

    def test_report_is_written_and_names_the_problem(self):
        rows = [[f'a{i}@example.com', 'GOOGLE_WORKSPACE',
                 f'2026-09-0{i % 9 + 1}', SPAMHAUS] for i in range(30)]
        text = self.report_for(rows)
        self.assertIn('Bounce diagnosis', text)
        self.assertIn('Spamhaus', text)
        # A named blocklist outranks the generic sending-side verdict.
        self.assertIn('You are on a blocklist', text)

    def test_report_opens_with_the_banner_and_a_live_version(self):
        text = self.report_for(bounces(30))
        self.assertTrue(text.startswith('```'),
                        'banner must be fenced for markdown')
        self.assertIn('\u2588', text, 'reticle should render')
        self.assertIn('v' + bc.__version__, text)
        self.assertNotIn('{version}', text)

    def test_banner_fits_a_terminal(self):
        widest = max(len(line) for line in bc.BANNER.split('\n'))
        self.assertLessEqual(widest, 80)

    def test_report_says_list_problem_when_it_is_one(self):
        self.assertIn('Your list is stale', self.report_for(bounces(30)))

    def test_missing_bounce_column_is_an_error(self):
        path = self.write_csv([['a@example.com', '', '', '']],
                              header=('email', 'mx', 'last_sent_at', 'notes'))
        self.assertEqual(self.run_csv(path), 1)

    def test_existing_output_not_clobbered(self):
        path = self.write_csv([['a@example.com', '', '', DEAD]])
        self.assertEqual(self.run_csv(path), 0)
        self.assertEqual(self.run_csv(path), 1)
        self.assertEqual(self.run_csv(path, force=True), 0)

    def test_blank_bounce_text_is_not_dumped_as_unknown(self):
        path = self.write_csv([['a@example.com', '', '', ''],
                               ['b@example.com', '', '', 'qqq zzz']])
        dump = os.path.join(self.tmp, 'u.txt')
        self.run_csv(path, dump_unknown=dump)
        self.assertEqual(read_lines(dump), ['qqq zzz'])

    def test_newline_inside_bounce_text(self):
        path = self.write_csv(
            [['a@example.com', '', '', '550 5.1.1\nuser unknown']])
        self.run_csv(path)
        self.assertEqual(len(self.output_rows()), 1)


class TestDelimiters(FileTestCase):
    """A file called .csv is not always comma separated.  Excel writes
    semicolons across most of Europe, and reading one as commas gives a
    single column called "email;bounce_msg"."""

    def test_sniffs_each_separator(self):
        for name, sep in (('a.csv', ','), ('b.csv', ';'), ('c.csv', '\t'),
                          ('d.csv', '|')):
            with self.subTest(sep=repr(sep)):
                path = self.write(name,
                                  sep.join(['email', 'bounce_msg']) + '\n'
                                  + sep.join(['a@example.com', DEAD]) + '\n')
                self.assertEqual(bc.sniff_delimiter(path), sep)

    def test_tsv_is_tab_separated_by_name(self):
        path = self.write('x.tsv', 'email\tbounce_msg\n')
        self.assertEqual(bc.sniff_delimiter(path), '\t')

    def test_a_semicolon_file_is_parsed_into_real_columns(self):
        path = self.write('semi.csv',
                          f'email;bounce_msg\na@example.com;{DEAD}\n')
        self.assertEqual(self.run_csv(path), 0)
        row = self.output_rows('semi - classified.csv')[0]
        self.assertEqual(row['email'], 'a@example.com')
        self.assertEqual(row['bounce_reason'], 'user_unknown')

    def test_a_semicolon_file_can_still_write_a_suppression_list(self):
        # The old bug: no real email column meant no suppression list.
        path = self.write('semi.csv',
                          f'email;bounce_msg\na@example.com;{DEAD}\n')
        dead = os.path.join(self.tmp, 'dead.txt')
        self.run_csv(path, suppress_list=dead)
        self.assertEqual(read_lines(dead), ['a@example.com'])

    def test_an_empty_file_does_not_guess(self):
        path = self.write('empty.csv', '')
        self.assertEqual(bc.sniff_delimiter(path), ',')


class TestConsole(unittest.TestCase):
    """Decoration must never crash the program or break grep."""

    def setUp(self):
        self.addCleanup(setattr, bc, 'COLOUR', bc.COLOUR)
        self.addCleanup(setattr, bc, 'UNICODE', bc.UNICODE)

    def test_paint_is_a_no_op_without_colour(self):
        bc.COLOUR = False
        self.assertEqual(bc.paint('hello', 'red', 'bold'), 'hello')

    def test_paint_wraps_and_always_resets(self):
        bc.COLOUR = True
        painted = bc.paint('hello', 'red')
        self.assertIn('hello', painted)
        self.assertTrue(painted.endswith('\033[0m'), 'must reset or it bleeds')

    def test_colour_is_off_when_not_a_terminal(self):
        # unittest captures stdout, so this must be off already.
        self.assertFalse(bc._colour_ok())

    def test_banner_has_an_ascii_twin(self):
        ascii_banner = bc.BANNER_ASCII.format(version='9.9.9')
        # This raises if it is not pure ASCII.
        ascii_banner.encode('ascii')
        self.assertIn('9.9.9', ascii_banner)

    def test_banner_picks_a_set_this_console_can_print(self):
        bc.UNICODE = False
        bc.banner('1.0.0').encode('ascii')
        bc.UNICODE = True
        self.assertIn('\u2588', bc.banner('1.0.0'))

    def test_both_banners_fit_eighty_columns(self):
        for mark in (bc.BANNER, bc.BANNER_ASCII):
            lines = mark.format(version=bc.__version__).split('\n')
            self.assertLessEqual(max(len(line) for line in lines), 80)


class TestVerdicts(FileTestCase):
    """Sending side covers a Spamhaus listing, a broken SPF record and copy
    that trips filters.  Each needs a different fix, so the verdict names
    which one it is."""

    def verdict_for(self, message):
        return self.report_for(bounces(30, message))

    def test_blocklist_outranks_everything(self):
        self.assertIn('You are on a blocklist', self.verdict_for(SPAMHAUS))

    def test_broken_auth_is_called_the_cheap_problem(self):
        text = self.verdict_for(
            '550 5.7.26 Unauthenticated email is not accepted')
        self.assertIn('authentication is broken', text)
        self.assertIn('cheapest problem', text)

    def test_content_verdict_points_at_the_copy(self):
        text = self.verdict_for('550 "detected your message as spam"')
        self.assertIn('message is the problem, not the sender', text)

    def test_dead_addresses_read_as_a_stale_list(self):
        text = self.verdict_for('550 5.1.1 The email account does not exist')
        self.assertIn('list is stale', text)

    def test_abandoned_accounts_get_their_own_verdict(self):
        text = self.verdict_for('552 5.2.2 out of storage space and inactive')
        self.assertIn('abandoned accounts', text)

    def test_walled_mailboxes_get_their_own_verdict(self):
        text = self.verdict_for(
            '5.7.133 RESOLVER.RST.SenderNotAuthenticatedForGroup')
        self.assertIn('never reachable', text)

    def test_transient_says_there_may_be_nothing_wrong(self):
        text = self.verdict_for(
            '451 4.7.1 Greylisted, please try again later')
        self.assertIn('Mostly temporary', text)

    def test_unreadable_text_admits_it(self):
        self.assertIn('No clear signal',
                      self.verdict_for('qqq zzz nothing here'))

    def test_every_verdict_is_a_distinct_sentence(self):
        seen = set()
        for message in (SPAMHAUS,
                        '550 5.7.26 Unauthenticated email is not accepted',
                        '550 "detected your message as spam"',
                        '550 5.1.1 The email account does not exist',
                        '552 5.2.2 out of storage space and inactive',
                        '5.7.133 RESOLVER.RST.SenderNotAuthenticatedForGroup',
                        '451 4.7.1 Greylisted, please try again later',
                        'qqq zzz nothing here'):
            with self.subTest(message=message[:30]):
                body = self.verdict_for(message).split('## Verdict')[1]
                head = body.split('\n\n')[1]
                self.assertNotIn(head, seen, 'duplicate verdict wording')
                seen.add(head)


class TestEmptyRows(FileTestCase):
    """Most leads in an export never bounced.  Their rows have no bounce
    text, and counting them as unknown made a healthy run read as a 97%
    failure."""

    def test_empty_rows_are_not_counted_as_unknown(self):
        text = self.report_for(blanks(90) + bounces(10))
        # The 10 real bounces are counted against 100 leads, and the report
        # never claims 100 bounces.
        self.assertIn('10 of 100 leads bounced', text)
        self.assertNotIn('100 bounces', text)

    def test_percentages_use_the_bounces_not_the_row_count(self):
        # All ten real bounces are data faults, so this must read 100%.
        self.assertIn('100.0%', self.report_for(blanks(90) + bounces(10)))

    def test_a_whole_campaign_export_yields_a_bounce_rate(self):
        # The rows that never bounced are the denominator, not noise.
        text = self.report_for(blanks(950) + bounces(50))
        self.assertIn('50 of 1,000 leads bounced (5.0%)', text)
        self.assertIn('high enough to be doing damage', text)

    def test_a_healthy_rate_is_called_healthy(self):
        self.assertIn('healthy', self.report_for(blanks(995) + bounces(5)))

    def test_a_bounces_only_export_still_works(self):
        # No blank rows means no denominator, so it must not claim a rate.
        text = self.report_for(bounces(20))
        self.assertIn('20 bounces analysed', text)
        self.assertNotIn('leads bounced', text)

    def test_output_holds_only_the_bounces(self):
        # The output is for acting on, so the rows that never bounced stay
        # out of it.
        self.run_csv(self.write_csv(blanks(90) + bounces(10)))
        rows = self.output_rows()
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(row['bounce_reason'] != 'empty' for row in rows))

    def test_all_rows_keeps_everything(self):
        self.run_csv(self.write_csv(blanks(90) + bounces(10)), all_rows=True)
        self.assertEqual(len(self.output_rows()), 100)

    def test_the_rate_still_counts_every_lead(self):
        # Leaving blank rows out of the output must not change the
        # denominator.
        self.assertIn('50 of 1,000 leads bounced',
                      self.report_for(blanks(950) + bounces(50)))

    def test_a_file_of_only_blanks_does_not_crash(self):
        path = self.write_csv([['a@example.com', '', '', '']] * 5)
        self.assertEqual(self.run_csv(path), 0)


class TestRfc3463Families(unittest.TestCase):
    """RFC 3463 defines whole families of codes.  One the tool does not know
    falls through to prose, which is a worse guess."""

    def test_address_family(self):
        self.assertEqual(reason_of('550 5.1.4 address ambiguous'),
                         'ambiguous_address')
        for code in ('5.1.7', '5.1.8'):
            with self.subTest(code=code):
                result = classify(f'550 {code} bad sender address')
                self.assertEqual((result['reason'], result['category']),
                                 ('sender_address_bad', bc.AUTH))

    def test_your_own_return_address_is_your_problem(self):
        # 5.1.7 and 5.1.8 are about the sender, not the recipient.
        result = classify("550 5.1.8 Bad sender's system address")
        self.assertNotEqual(result['action'], bc.SUPPRESS)
        self.assertEqual(result['action'], bc.FIXAUTH)

    def test_mailbox_family(self):
        self.assertEqual(reason_of('552 5.2.3 message length exceeds limit'),
                         'email_too_large')
        self.assertEqual(
            reason_of('550 5.2.4 mailing list expansion problem'),
            'list_expansion')

    def test_network_family(self):
        self.assertEqual(reason_of('550 5.4.6 routing loop detected'),
                         'mail_loop')
        self.assertEqual(reason_of('550 5.4.4 unable to route'),
                         'host_unknown')
        for code in ('4.4.0', '4.4.2', '4.4.5'):
            with self.subTest(code=code):
                result = classify(f'450 {code} network trouble')
                self.assertEqual(result['category'], bc.TRANSIENT)

    def test_protocol_family(self):
        self.assertEqual(reason_of('550 5.5.3 too many recipients'),
                         'protocol_error')
        for code in ('5.5.0', '5.5.1', '5.5.2', '5.5.4'):
            with self.subTest(code=code):
                self.assertEqual(reason_of(f'550 {code} protocol trouble'),
                                 'protocol_error')

    def test_media_family(self):
        for code in ('5.6.0', '5.6.1', '5.6.3', '5.6.5'):
            with self.subTest(code=code):
                result = classify(f'550 {code} conversion problem')
                self.assertEqual((result['reason'], result['category']),
                                 ('media_error', bc.CONTENT))

    def test_security_family(self):
        self.assertEqual(reason_of('550 5.7.0 security policy'),
                         'policy_violation')
        self.assertEqual(reason_of('550 5.7.2 list expansion prohibited'),
                         'list_expansion')
        for code in ('5.7.4', '5.7.5', '5.7.6', '5.7.7'):
            with self.subTest(code=code):
                self.assertEqual(reason_of(f'550 {code} crypto failure'),
                                 'crypto_error')


class TestProviderCodes(unittest.TestCase):
    """Yahoo, AOL and Verizon put short codes in brackets that carry more
    than the 4xx/5xx class does."""

    def test_yahoo_policy_refusal(self):
        result = classify('554 5.7.9 Message not accepted for policy reasons')
        self.assertEqual((result['reason'], result['category']),
                         ('policy_violation', bc.REPUTATION))

    def test_yahoo_throttle_is_temporary_not_a_domain_pause(self):
        # TSS means slow down.  Pausing a domain over it would throw away
        # sending capacity for a problem that clears on its own.
        result = classify('421 4.7.0 [TSS04] Messages temporarily deferred '
                          'due to unexpected volume')
        self.assertEqual(result['reason'], 'throttled')
        self.assertEqual(result['action'], bc.RETRY)
        self.assertNotEqual(result['action'], bc.PAUSE)

    def test_yahoo_ts_codes(self):
        for code in ('TS01', 'TS03', 'TSS01', 'TSS04'):
            with self.subTest(code=code):
                self.assertEqual(reason_of(f'421 4.7.0 {code} deferred'),
                                 'throttled')

    def test_verizon_policy_code(self):
        self.assertEqual(reason_of('554 PH01 message rejected'), 'blocked')

    def test_yahoo_blocklist_code(self):
        self.assertEqual(reason_of('553 5.7.1 DNSBL:ATTRBL 521 listed'),
                         'blocklisted')



class TestMicrosoftCodes(unittest.TestCase):
    """Exchange Online's own codes, as its NDR reference defines them."""

    def test_outlook_mailbox_unavailable_is_a_dead_address(self):
        # This used to match a Barracuda pattern and say pause the domain.
        result = classify(
            'Requested action not taken: mailbox unavailable (S2017062302). '
            '[XX1PEPF0000AB88.namprd03.prod.outlook.com '
            '2026-08-19T13:57:11.876Z 08DEF98D3E158B5A]')
        self.assertEqual((result['reason'], result['action']),
                         ('user_unknown', bc.SUPPRESS))

    def test_hotmail_5_5_0_is_not_a_protocol_error(self):
        self.assertEqual(
            reason_of('550 5.5.0 Requested action not taken: mailbox '
                      'unavailable'),
            'user_unknown')

    def test_tenant_ban_says_it_is_the_tenant(self):
        result = classify('5.7.705 Service unavailable. Access denied, '
                          'tenant has exceeded threshold.')
        self.assertEqual(result['reason'], 'bad_reputation')
        self.assertIn('tenant', result['detail'])

    def test_bad_outbound_sender_is_your_own_mailbox(self):
        result = classify('Access denied, bad outbound sender AS(42004)')
        self.assertEqual(result['category'], bc.REPUTATION)
        self.assertNotEqual(result['action'], bc.SUPPRESS)

    def test_refused_connection_is_not_your_fault(self):
        result = classify(
            "Your message wasn't delivered. Despite repeated attempts to "
            "deliver your message, the recipient's email system refused to "
            'accept a connection from your email system. 5.4.317')
        self.assertEqual(result['reason'], 'network_error')
        self.assertNotEqual(result['action'], bc.PAUSE)

    def test_dns_failures_are_the_domain(self):
        self.assertEqual(
            reason_of('5.4.310 DNS domain example.com does not exist '
                      '[Message=InfoDomainNonexistent]'),
            'host_unknown')

    def test_directory_edge_blocking_means_no_such_recipient(self):
        self.assertEqual(
            reason_of('550 5.4.1 Recipient address rejected: Access denied. '
                      'AS(201806281)'),
            'user_unknown')

    def test_the_5_7_5xx_range_is_not_all_one_thing(self):
        for text, reason in (
                ('5.7.501 Access denied, spam abuse detected', 'blocked'),
                ('5.7.504 Recipient address rejected: Access denied',
                 'user_unknown'),
                ('5.7.509 Access denied, sending domain example.com does not '
                 'pass DMARC verification', 'auth_failure'),
                ('5.7.520 Access denied, Your organization does not allow '
                 'external forwarding', 'restricted_recipient')):
            with self.subTest(text=text[:20]):
                self.assertEqual(reason_of(text), reason)

    def test_a_relay_login_prompt_is_not_your_authentication(self):
        # The server wants you to log in, so it isn't this domain's mail
        # host.  Changing your SPF record would not help.
        result = classify(
            '5.7.368 Remote server returned authentication required to relay '
            '-> 550 Please turn on SMTP Authentication in your mail client')
        self.assertEqual(result['reason'], 'no_relaying')
        self.assertNotEqual(result['action'], bc.FIXAUTH)


class TestGmxCases(unittest.TestCase):
    """GMX, web.de, mail.com and 1&1 link each rejection to a case page whose
    code says what happened, while the text says only "policy"."""

    WRAPPER = ('5.1.351 Remote server returned unknown recipient or mailbox '
               'unavailable -> 550 Requested action not taken: mailbox '
               'unavailable;Reject due to policy restrictions.;For '
               'explanation visit https://postmaster.gmx.net/en/case?c={}'
               '&i=ip&v=192.0.2.1&r=abc')

    def test_r1102_is_a_spamhaus_listing(self):
        result = classify(self.WRAPPER.format('r1102'))
        self.assertEqual((result['reason'], result['action']),
                         ('blocklisted', bc.PAUSE))
        self.assertEqual(result['blocklist'], 'Spamhaus')
        self.assertEqual(result['rejected_by'], 'gmx')

    def test_r1103_is_a_spamhaus_listing_too(self):
        self.assertEqual(reason_of(self.WRAPPER.format('r1103')),
                         'blocklisted')

    def test_r1601_is_a_dead_address(self):
        self.assertEqual(reason_of(self.WRAPPER.format('r1601')),
                         'user_unknown')

    def test_r1503_is_a_full_mailbox(self):
        self.assertEqual(reason_of(self.WRAPPER.format('r1503')),
                         'mailbox_full')


class TestRfc7372(unittest.TestCase):
    """The authentication codes, numbered as IANA registers them."""

    def test_dkim_and_spf_codes(self):
        for code in ('5.7.20', '5.7.21', '5.7.22', '5.7.23', '5.7.24',
                     '5.7.26'):
            with self.subTest(code=code):
                self.assertEqual(
                    category_action(f'550 {code} authentication failure'),
                    (bc.AUTH, bc.FIXAUTH))

    def test_reverse_dns(self):
        self.assertEqual(reason_of('550 5.7.25 no PTR'), 'require_ptr')

    def test_null_mx_on_the_sending_domain(self):
        self.assertEqual(reason_of('550 5.7.27 sender address has null MX'),
                         'sender_address_bad')

    def test_arc_and_requiretls_are_not_rate_limits(self):
        self.assertEqual(reason_of('550 5.7.29 ARC validation failure'),
                         'auth_failure')
        self.assertEqual(reason_of('550 5.7.30 REQUIRETLS support required'),
                         'crypto_error')


class TestProviderTokens(unittest.TestCase):

    def test_retired_email_to_text_gateway(self):
        result = classify('Blocked. Decommission of Email to Text Vtext/'
                          'VZWPix. AUP#MXRT')
        self.assertEqual((result['reason'], result['category']),
                         ('host_unknown', bc.DATA))

    def test_aup_codes_are_not_called_comcast(self):
        result = classify('<a@example.com> sender rejected. Please see '
                          'https://www.spectrum.net/support/internet for more '
                          'information. AUP#In-1310')
        self.assertIn('Spectrum', result['detail'])
        self.assertEqual(result['rejected_by'], 'spectrum')

    def test_icloud_cs01_is_read_from_the_token(self):
        result = classify('[CS01] Message rejected due to local policy. '
                          'Please visit https://support.apple.com/HT204137')
        self.assertEqual(result['_tier'], bc.T_TOKEN)
        self.assertEqual(result['rejected_by'], 'apple')

    def test_icloud_hm08_is_a_throttle_not_a_dead_address(self):
        result = classify('[HM08] Message rejected due to local policy. '
                          'Please visit https://support.apple.com/HT204137')
        self.assertEqual((result['reason'], result['action']),
                         ('throttled', bc.RETRY))

    def test_mimecast_security_policies_without_the_wrapper(self):
        # The Exchange wrapper usually says "Mimecast detected message as
        # spam"; without it the remote text alone must still be read.
        self.assertEqual(
            reason_of('Email rejected due to security policies - '
                      'https://community.mimecast.com/docs/DOC-1369#554'),
            'spam_detected')

    def test_one_persons_block_list_is_not_a_domain_pause(self):
        result = classify('550 Envelope blocked - User Entry - '
                          'https://community.mimecast.com/docs/DOC-1369#550')
        self.assertEqual((result['category'], result['action']),
                         (bc.RECIPIENT, bc.SUPPRESS))

    def test_abusix_is_a_named_blocklist(self):
        result = classify('Invalid Sender. Your domain has been blacklisted '
                          'by Abusix (https://lookup.abusix.com/)')
        self.assertEqual(result['reason'], 'blocklisted')
        self.assertIn('Abusix', result['blocklist'])


class TestNewPhrases(unittest.TestCase):

    def test_examples(self):
        for text, reason in (
                ('530 Access denied due to the location screening policy.',
                 'geo_blocked'),
                ('Mail from 192.0.2.1 was refused due to the sender IP found '
                 'in ERS-Blocked-Country-Region-List', 'geo_blocked'),
                ('This message has been rejected due to content judged to be '
                 'spam by the internet community IB212', 'spam_detected'),
                ('554 Remote said: "Reputation too low"', 'bad_reputation'),
                ('Recipient address rejected: Too many complaints from domain '
                 'example.com', 'bad_reputation'),
                ('553 Relaying disallowed', 'no_relaying'),
                ('554 Failure : This message is being held. You are not on '
                 'the friends list', 'restricted_recipient'),
                ('550 No such person at this address', 'user_unknown'),
                ('550 recipient unrecognized', 'user_unknown'),
                ("550 Sender's policy prohibits this message: Quarantine",
                 'auth_failure'),
                ('example.com has no real MX records. Ask your email '
                 'administrator to fix this.', 'sender_address_bad'),
                ('550 We were unable to find the recipient domain.',
                 'host_unknown')):
            with self.subTest(text=text[:30]):
                self.assertEqual(reason_of(text), reason)


class TestEvidence(unittest.TestCase):

    def test_the_deciding_words_are_returned(self):
        result = classify('550 5.1.1 <a@example.com>: user unknown')
        self.assertEqual(result['evidence'], '5.1.1')

    def test_abandoned_shows_both_halves_of_the_call(self):
        result = classify('552 5.2.2 out of storage space and inactive')
        self.assertEqual(result['evidence'], '5.2.2 ... inactive')

    def test_unreadable_text_has_no_evidence(self):
        self.assertEqual(classify('qqq zzz')['evidence'], '')


class TestPauseList(FileTestCase):

    HEADER = ('email', 'email_acc_name', 'last_sent_at', 'bounce_msg')

    def export(self):
        rows = []
        # burnt.example: every bounce is a Spamhaus listing.
        rows += [[f'a{i}@example.net', 'jo@burnt.example', '2026-09-01',
                  SPAMHAUS] for i in range(5)]
        # stale.example: a bad list, plus two reputation refusals.
        rows += [[f'b{i}@example.net', 'jo@stale.example', '2026-09-01',
                  DEAD] for i in range(8)]
        rows += [[f'c{i}@example.net', 'jo@stale.example', '2026-09-01',
                  SPAMHAUS] for i in range(2)]
        return self.write_csv(rows, header=self.HEADER)

    def test_only_domains_mostly_refused_on_reputation(self):
        pause = os.path.join(self.tmp, 'pause.txt')
        self.run_csv(self.export(), pause_list=pause)
        self.assertEqual(read_lines(pause), ['burnt.example'])

    def test_no_sender_column_is_reported(self):
        path = self.write_csv(bounces(5, SPAMHAUS))
        pause = os.path.join(self.tmp, 'pause.txt')
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.run_csv(path, pause_list=pause)
        self.assertIn('no sending-mailbox column', err.getvalue())
        self.assertFalse(os.path.exists(pause))


class TestFailOver(FileTestCase):

    def test_over_the_threshold_exits_3(self):
        path = self.write_csv(blanks(95) + bounces(5))
        self.assertEqual(self.run_csv(path, fail_over=2.0), 3)

    def test_under_the_threshold_exits_0(self):
        path = self.write_csv(blanks(99) + bounces(1))
        self.assertEqual(self.run_csv(path, fail_over=2.0), 0)

    def test_no_denominator_is_an_error_not_a_pass(self):
        path = self.write_csv(bounces(5))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_csv(path, fail_over=2.0), 1)


class TestReasonsGlossary(unittest.TestCase):

    def test_every_reason_is_listed(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(bc.print_reasons(), 0)
        for reason in bc.REASONS:
            self.assertIn(reason, out.getvalue())

class TestOutputLocation(FileTestCase):
    """-o governs every output.  A bare filename lands there; a full path is
    still honoured."""

    def setUp(self):
        super().setUp()
        self.out = os.path.join(self.tmp, 'results')
        os.makedirs(self.out)

    def mixed_export(self):
        return self.write_csv([
            ['a@example.com', '', '2026-09-01', DEAD],
            ['b@example.com', '', '2026-09-01', 'qqq unreadable zzz'],
            ])

    def test_bare_filenames_land_in_the_output_directory(self):
        self.run_csv(self.mixed_export(), outdir=self.out, report='diag.md',
                     suppress_list='dead.txt', dump_unknown='miss.txt')
        for name in ('in - classified.csv', 'diag.md', 'dead.txt',
                     'miss.txt'):
            with self.subTest(name=name):
                path = os.path.join(self.out, name)
                self.assertTrue(os.path.isfile(path), name)

    def test_an_explicit_path_is_honoured(self):
        elsewhere = os.path.join(self.tmp, 'elsewhere.txt')
        self.run_csv(self.mixed_export(), outdir=self.out,
                     suppress_list=elsewhere)
        self.assertTrue(os.path.isfile(elsewhere))
        self.assertFalse(
            os.path.isfile(os.path.join(self.out, 'elsewhere.txt')))

    def test_out_path_helper(self):
        # Build the expected value the way the OS does, or this passes on
        # POSIX and fails on Windows over a separator.
        base = os.path.join(self.tmp, 'out')
        self.assertEqual(bc._out_path('x.txt', base),
                         os.path.join(base, 'x.txt'))
        absolute = os.path.join(self.tmp, 'elsewhere', 'x.txt')
        self.assertEqual(bc._out_path(absolute, base), absolute)


class TestPathHandling(FileTestCase):
    """A .csv path that does not exist is a typo, not bounce text."""

    def run_main(self, argv):
        # main() sets QUIET from its arguments, so put it back or every test
        # after this one starts printing.
        self.addCleanup(setattr, bc, 'QUIET', bc.QUIET)
        self.addCleanup(setattr, sys, 'argv', sys.argv)
        sys.argv = ['bouncesitrep'] + argv
        err = io.StringIO()
        with contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            return bc.main(), err.getvalue()

    def test_missing_csv_is_an_error(self):
        code, err = self.run_main([os.path.join(self.tmp, 'nope.csv')])
        self.assertEqual(code, 1)
        self.assertIn('no such file', err)

    def test_a_directory_named_csv_is_an_error(self):
        path = os.path.join(self.tmp, 'adir.csv')
        os.makedirs(path)
        code, err = self.run_main([path])
        self.assertEqual(code, 1)
        self.assertIn('directory', err)

    def test_a_real_message_is_still_classified(self):
        code, err = self.run_main([DEAD])
        self.assertEqual(code, 0)
        self.assertEqual(err, '')


if __name__ == '__main__':
    unittest.main()
