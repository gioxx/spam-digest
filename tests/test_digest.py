"""Digest side: state file, AI parsing, user rules, secret, digest HTML."""

import json
import os
import stat
import unittest

from support import EMAIL, FakeMail, mail, read_mailbox, reset_data, sd, shared, ss


def _run(status="success", emails=(), folder="Spam", uidvalidity=42):
    return {"email_address": EMAIL, "status": status, "count": len(emails), "spam_folder": folder,
            "uidvalidity": uidvalidity, "duration_seconds": 1, "emails": list(emails),
            "error_message": None if status == "success" else "boom"}


class StateTests(unittest.TestCase):
    def setUp(self):
        reset_data()

    def test_save_state_persists_lists_and_run_ts(self):
        sd.save_state([_run(emails=[mail("1", "spam"), mail("2", "uncertain"), mail("3", "safe")])],
                      "2026-11-08 08:00", 3)
        mb = read_mailbox()
        self.assertEqual(mb["confirmed_spam_uids"], ["1"])
        self.assertEqual([e["uid"] for e in mb["uncertain_emails"]], ["2"])
        self.assertEqual([e["uid"] for e in mb["safe_emails"]], ["3"])
        self.assertEqual(mb["spam_run_ts"], "2026-11-08 08:00")
        self.assertEqual(mb["uidvalidity"], 42)
        self.assertEqual(mb["spam_folder"], "Spam")

    def test_failed_fetch_clears_actionable_lists(self):
        sd.save_state([_run(emails=[mail("1", "spam"), mail("2", "uncertain")])], "2026-11-08 08:00", 2)
        sd.save_state([_run(status="error", folder="Junk", uidvalidity=None)], "2026-11-08 09:00", 0)
        mb = read_mailbox()
        self.assertEqual(mb["confirmed_spam_uids"], [])
        self.assertEqual(mb["uncertain_emails"], [])
        self.assertNotIn("spam_run_ts", mb)
        self.assertEqual(mb["status"], "error")

    def test_state_written_atomically(self):
        sd.save_state([_run()], "t", 0)
        self.assertFalse([f for f in os.listdir(shared.DATA_DIR) if f.startswith(".tmp-")])
        with open(shared.STATE_FILE) as f:
            json.load(f)


class SecretTests(unittest.TestCase):
    def setUp(self):
        reset_data()

    def test_secret_created_owner_only_and_stable(self):
        secret = shared.load_or_create_secret()
        self.assertEqual(stat.S_IMODE(os.stat(shared.SECRET_FILE).st_mode), 0o600)
        self.assertEqual(shared.load_or_create_secret(), secret)

    def test_corrupted_secret_is_regenerated(self):
        shared.load_or_create_secret()
        with open(shared.SECRET_FILE, "w") as f:
            f.write("not-hex")
        new = shared.load_or_create_secret()
        self.assertEqual(shared.load_secret(), new)

    def test_mgmt_token_roundtrip_and_purpose_separation(self):
        secret = shared.load_or_create_secret()
        token = shared.sign_mgmt_token(secret, shared.PURPOSE_REVIEW, EMAIL, "n1")
        self.assertTrue(shared.verify_mgmt_token(secret, shared.PURPOSE_REVIEW, EMAIL, "n1", token))
        self.assertFalse(shared.verify_mgmt_token(secret, shared.PURPOSE_FILTERS, EMAIL, "n1", token))
        self.assertFalse(shared.verify_mgmt_token(secret, shared.PURPOSE_REVIEW, EMAIL, "n2", token))


class AIParsingTests(unittest.TestCase):
    def test_fenced_json(self):
        out = sd._parse_ai_classifications('```json\n[{"index":0,"label":"SPAM","reason":"x"}]\n```')
        self.assertEqual(out, {0: ("spam", "x")})

    def test_prose_string_index_bad_label_and_junk_items(self):
        out = sd._parse_ai_classifications(
            'Here: [{"index":"1","label":"weird","reason":5},{"label":"spam"},3] done')
        self.assertEqual(out, {1: ("uncertain", "5")})

    def test_no_array_raises(self):
        with self.assertRaises(ValueError):
            sd._parse_ai_classifications("nothing here")


class UserRulesTests(unittest.TestCase):
    def setUp(self):
        reset_data()
        shared.add_filter_rule(EMAIL, "sender_domain", "spam.example.net", "t")
        self.mails = [{"uid": "7", "from": "x@spam.example.net", "subject": "hi"},
                      {"uid": "8", "from": "ok@good.example.com", "subject": "hello"}]

    def test_dry_run_sends_no_imap_commands(self):
        calls = []
        remaining, deleted, moved = sd._apply_user_rules(FakeMail(calls), self.mails, EMAIL, dry_run=True)
        self.assertEqual(calls, [])
        self.assertEqual([m["uid"] for m in deleted], ["7"])
        self.assertEqual([m["uid"] for m in remaining], ["8"])

    def test_live_run_deletes_and_expunges(self):
        calls = []
        sd._apply_user_rules(FakeMail(calls), self.mails, EMAIL, dry_run=False)
        self.assertEqual(calls, [("STORE", b"7"), ("EXPUNGE", None)])

    def test_allowlist_moves_to_inbox(self):
        shared.add_allowlist_sender(EMAIL, "ok@good.example.com")
        calls = []
        _, _, moved = sd._apply_user_rules(FakeMail(calls), self.mails, EMAIL)
        self.assertEqual([m["uid"] for m in moved], ["8"])
        self.assertIn(("COPY", b"8"), calls)


class DigestHtmlTests(unittest.TestCase):
    def setUp(self):
        self._env = {k: os.environ.get(k) for k in ("AI_PROVIDER", "AI_API_KEY")}
        os.environ["AI_PROVIDER"], os.environ["AI_API_KEY"] = "anthropic", "x"

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_review_buttons_only_with_web_base_url(self):
        r = _run(emails=[mail("1", "safe"), mail("2", "uncertain"), mail("3", "safe")])
        html = sd.build_html_digest([r], "2026-11-08 10:00", web_base_url="https://w.example.com",
                                    review_tokens={EMAIL: "T"})
        self.assertIn("Review 2 probably legitimate email(s)", html)
        self.assertIn("Review 1 uncertain email(s)", html)
        self.assertNotIn("Review 2", sd.build_html_digest([r], "2026-11-08 10:00"))

    def test_digest_escapes_subject(self):
        r = _run(emails=[mail("1", "spam", subject="<b>x</b>")])
        html = sd.build_html_digest([r], "t")
        self.assertNotIn("<b>x</b>", html)


class MailboxConfigTests(unittest.TestCase):
    KEYS = ("MAILBOX_CONFIGS", "IMAP_SERVER", "EMAIL_USER", "EMAIL_PASS", "IMAP_PORT",
            "IMAP_USE_SSL", "SPAM_FOLDER", "MAX_EMAILS", "EMAIL_ADDRESS", "DIGEST_TO")

    def setUp(self):
        self._env = {k: os.environ.pop(k, None) for k in self.KEYS}

    def tearDown(self):
        for k, v in self._env.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    def test_dashboard_and_digest_use_the_same_parser(self):
        os.environ["MAILBOX_CONFIGS"] = json.dumps([
            {"imap_server": "i.example.com", "email_user": "a@example.com", "email_pass": "x",
             "imap_use_ssl": False, "imap_port": "143"}])
        os.environ["SPAM_FOLDER"] = "Ignored"   # single-mailbox only
        cfg = shared.load_mailbox_configs()
        self.assertEqual(ss._get_mailbox_configs(), cfg)
        self.assertEqual(sd.load_mailbox_configs(), cfg)
        self.assertEqual((cfg[0]["imap_port"], cfg[0]["imap_use_ssl"], cfg[0]["spam_folder"],
                          cfg[0]["max_emails"], cfg[0]["email_address"]),
                         (143, False, "Junk", 100, "a@example.com"))

    def test_single_mailbox_and_invalid_json_fallback(self):
        os.environ.update({"IMAP_SERVER": "i.example.com", "EMAIL_USER": "u@example.com",
                           "EMAIL_PASS": "x", "SPAM_FOLDER": "Spam", "IMAP_USE_SSL": "false"})
        os.environ["MAILBOX_CONFIGS"] = "{not json"
        cfg = shared.load_mailbox_configs()
        self.assertEqual(len(cfg), 1)
        self.assertEqual((cfg[0]["spam_folder"], cfg[0]["imap_use_ssl"], cfg[0]["imap_port"]),
                         ("Spam", False, 993))


class ScheduleTests(unittest.TestCase):
    def test_schedule_description(self):
        old = os.environ.get("SCHEDULE_DAY")
        try:
            os.environ["SCHEDULE_DAY"] = "*"
            self.assertTrue(ss._get_schedule()[1].startswith("Every day at"))
            os.environ["SCHEDULE_DAY"] = "1"
            self.assertTrue(ss._get_schedule()[1].startswith("Every Monday at"))
        finally:
            if old is None:
                os.environ.pop("SCHEDULE_DAY", None)
            else:
                os.environ["SCHEDULE_DAY"] = old


if __name__ == "__main__":
    unittest.main()
