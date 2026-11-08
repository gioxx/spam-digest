"""IMAP against a minimal real server: UIDVALIDITY checks and races (#40, #46)."""

import imaplib
import json
import unittest

from support import EMAIL, FakeIMAPServer, read_mailbox, reset_data, sd, shared, ss, write_state


class ImapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.imap = FakeIMAPServer(uidvalidity=1234)

    @classmethod
    def tearDownClass(cls):
        cls.imap.close()

    def setUp(self):
        reset_data()
        self.imap.uidvalidity = 1234
        self.imap.commands.clear()
        self._orig_cfg = ss._get_mailbox_config
        ss._get_mailbox_config = lambda e: self.imap.config()

    def tearDown(self):
        ss._get_mailbox_config = self._orig_cfg

    def state(self, uidvalidity=1234, run="R1", uids=("1", "2")):
        mb = {"email_address": EMAIL, "spam_folder": "Junk", "last_run": run,
              "uncertain_emails": [{"uid": u} for u in uids], "safe_emails": []}
        if uidvalidity is not None:
            mb["uidvalidity"] = uidvalidity
        write_state([mb])

    def test_read_uidvalidity_parses_real_response(self):
        m = imaplib.IMAP4("127.0.0.1", self.imap.port)
        m.login("u", "p")
        m.select('"Junk"')
        self.assertEqual(shared.read_uidvalidity(m), 1234)
        m.logout()

    def test_matching_uidvalidity_allows_action(self):
        self.state()
        ok, msg = ss._do_bulk_review_action(EMAIL, "delete_all_uncertain")
        self.assertTrue(ok, msg)
        self.assertEqual(self.imap.writes(), [("UID", "STORE 1,2 +FLAGS (\\Deleted)"), ("EXPUNGE", "")])

    def test_changed_uidvalidity_refuses_and_keeps_list(self):
        self.state()
        self.imap.uidvalidity = 9999
        ok, msg = ss._do_bulk_review_action(EMAIL, "delete_all_uncertain")
        self.assertFalse(ok)
        self.assertIn("mailbox changed", msg)
        self.assertEqual(self.imap.writes(), [])
        self.assertEqual(len(ss._get_review_list(EMAIL, "uncertain")), 2)

    def test_legacy_state_without_uidvalidity_is_refused(self):
        self.state(uidvalidity=None)
        ok, _ = ss._do_review_action(EMAIL, "1", "delete")
        self.assertFalse(ok)
        self.assertEqual(self.imap.writes(), [])

    def test_race_new_digest_between_snapshot_and_check(self):
        """A digest after a folder recreation lands between the snapshot read and
        the IMAP check: the old UIDs must still be refused (Codex review on #44)."""
        self.state()
        real_open = ss._open_imap

        def racing_open(cfg, folder=None):
            self.imap.uidvalidity = 5555
            write_state([{"email_address": EMAIL, "spam_folder": "Junk", "uidvalidity": 5555,
                          "last_run": "R2", "uncertain_emails": [{"uid": "1"}, {"uid": "9"}]}])
            return real_open(cfg, folder)

        ss._open_imap = racing_open
        try:
            ok, _ = ss._do_bulk_review_action(EMAIL, "delete_all_uncertain")
        finally:
            ss._open_imap = real_open
        self.assertFalse(ok)
        self.assertEqual(self.imap.writes(), [])
        self.assertEqual([e["uid"] for e in ss._get_review_list(EMAIL, "uncertain")], ["1", "9"])

    def test_newer_run_list_not_edited_after_action(self):
        self.state()
        real = ss._imap_move_or_delete

        def then_new_run(*a, **k):
            result = real(*a, **k)
            write_state([{"email_address": EMAIL, "spam_folder": "Junk", "uidvalidity": 1234,
                          "last_run": "R2", "uncertain_emails": [{"uid": "1"}]}])
            return result

        ss._imap_move_or_delete = then_new_run
        try:
            ok, msg = ss._do_review_action(EMAIL, "1", "delete")
        finally:
            ss._imap_move_or_delete = real
        self.assertTrue(ok, msg)
        self.assertEqual([e["uid"] for e in ss._get_review_list(EMAIL, "uncertain")], ["1"])

    def test_digest_records_uidvalidity(self):
        self.imap.uidvalidity = 777
        cfg = {**self.imap.config(), "email_address": EMAIL, "max_emails": 10}
        result = sd.fetch_spam_emails(cfg, dry_run=True)
        self.assertEqual(result["status"], "success", result["error_message"])
        self.assertEqual(result["uidvalidity"], 777)
        sd.save_state([result], "2026-11-09 08:00", 0)
        self.assertEqual(read_mailbox()["uidvalidity"], 777)


if __name__ == "__main__":
    unittest.main()
