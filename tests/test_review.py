"""Review page (/review): rendering, per-row and bulk actions (#29, #30)."""

import unittest

from support import EMAIL, FakeMail, reset_data, review_entry, ss, write_state


def _state(uncertain=("1", "2"), safe=("10", "11"), uidvalidity=42):
    write_state([{
        "email_address": EMAIL, "spam_folder": "Junk", "uidvalidity": uidvalidity,
        "last_run": "2026-11-08 08:00",
        "uncertain_emails": [review_entry(u, subject="u" + u) for u in uncertain],
        "safe_emails": [review_entry(u, subject="s" + u) for u in safe],
    }])


class ReviewTests(unittest.TestCase):
    def setUp(self):
        reset_data()
        self.calls, self.fail, self.trusted = [], None, []
        self._orig = (ss._get_mailbox_config, ss._open_imap, ss._verify_mgmt_request,
                      ss.shared.add_allowlist_sender)
        ss._get_mailbox_config = lambda e: {"spam_folder": "Junk"}
        ss._open_imap = lambda cfg, folder=None: (FakeMail(self.calls, self.fail), None)
        ss._verify_mgmt_request = lambda e, p, t: (True, "ok")
        ss.shared.add_allowlist_sender = lambda e, s: self.trusted.append(s)

    def tearDown(self):
        (ss._get_mailbox_config, ss._open_imap, ss._verify_mgmt_request,
         ss.shared.add_allowlist_sender) = self._orig

    def post(self, **form):
        return ss._handle_review_request(EMAIL, "tok", form={k: [v] for k, v in form.items()})

    def lists(self):
        return {k: [e["uid"] for e in ss._get_review_list(EMAIL, k)] for k in ss._REVIEW_KINDS}

    def test_render_both_sections_with_bulk_buttons(self):
        _state()
        status, body, _ = ss._handle_review_request(EMAIL, "tok")
        html = body.decode()
        self.assertEqual(status, 200)
        self.assertIn("Delete all (2)", html)
        self.assertIn("Move all to INBOX (2)", html)
        # 2 uncertain "trust" + 2 safe "trust" + 2 safe plain "move"
        self.assertEqual(html.count("value='move_to_inbox'"), 6)

    def test_render_escapes_subjects(self):
        write_state([{"email_address": EMAIL, "uncertain_emails": [review_entry("1", subject="x<script>")]}])
        html = ss._handle_review_request(EMAIL, "tok")[1].decode()
        self.assertNotIn("x<script>", html)
        self.assertIn("x&lt;script&gt;", html)

    def test_single_item_and_legacy_state(self):
        write_state([{"email_address": EMAIL, "uidvalidity": 42, "uncertain_emails": [review_entry("5")]}])
        html = ss._handle_review_request(EMAIL, "tok")[1].decode()
        self.assertNotIn("Delete all", html)
        self.assertNotIn("Probably legitimate (", html)

    def test_empty_state(self):
        write_state([{"email_address": EMAIL}])
        html = ss._handle_review_request(EMAIL, "tok")[1].decode()
        self.assertIn("No emails pending review", html)

    def test_bulk_delete_uses_one_uid_set_and_one_expunge(self):
        _state()
        _, body, _ = self.post(action="delete_all_uncertain")
        self.assertEqual(self.calls, [("STORE", b"1,2"), ("EXPUNGE", None)])
        self.assertEqual(self.lists(), {"uncertain": [], "safe": ["10", "11"]})
        self.assertIn("Deleted 2 email(s).", body.decode())

    def test_bulk_ignores_client_uids(self):
        _state()
        self.post(action="delete_all_uncertain", uid="999")
        self.assertEqual(self.calls[0], ("STORE", b"1,2"))

    def test_bulk_move_failure_keeps_list(self):
        _state()
        self.fail = "COPY"
        _, body, _ = self.post(action="move_all_safe")
        self.assertEqual(self.lists()["safe"], ["10", "11"])
        self.assertIn("No emails were removed", body.decode())

    def test_row_move_without_and_with_trust(self):
        _state()
        self.post(action="move_to_inbox", uid="10")
        self.assertEqual(self.calls, [("COPY", b"10"), ("STORE", b"10"), ("EXPUNGE", None)])
        self.assertEqual(self.trusted, [])
        self.post(action="move_to_inbox", uid="11", sender="x11@a.example.com", add_allowlist="1")
        self.assertEqual(self.trusted, ["x11@a.example.com"])
        self.assertEqual(self.lists()["safe"], [])

    def test_unknown_uid_rejected_without_imap(self):
        _state()
        _, body, _ = self.post(action="delete", uid="999")
        self.assertEqual(self.calls, [])
        self.assertIn("not in the current review list", body.decode())

    def test_access_denied_without_valid_token(self):
        ss._verify_mgmt_request = lambda e, p, t: (False, "invalid or revoked link")
        status, body, _ = ss._handle_review_request(EMAIL, "bad")
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
