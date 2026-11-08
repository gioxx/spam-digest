"""HTTP layer: delete-spam flow, dashboard actions, headers, optional login."""

import base64
import http.client
import os
import threading
import time
import unittest
import urllib.parse

from support import EMAIL, FakeMail, WebServer, read_mailbox, reset_data, shared, ss, write_state

RUN_TS = "2026-11-08 08:00"


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web = WebServer()

    @classmethod
    def tearDownClass(cls):
        cls.web.close()

    def setUp(self):
        reset_data()
        os.environ.pop("DASHBOARD_PASS", None)
        os.environ.pop("DASHBOARD_USER", None)
        self.calls, self.opened, self.ran = [], [], []
        self._orig = (ss._get_mailbox_config, ss._open_imap, ss._run_digest)
        ss._get_mailbox_config = lambda e: {"spam_folder": "Junk"}

        def fake_open(cfg, folder=None):
            self.opened.append(folder)
            return FakeMail(self.calls), None
        ss._open_imap = fake_open
        ss._run_digest = lambda action, email=None, allowed_emails=None: (self.ran.append(action) or True, "out")
        self.secret = shared.load_or_create_secret()
        write_state([{"email_address": EMAIL, "spam_folder": "Spam", "uidvalidity": 42,
                      "last_run": RUN_TS, "spam_run_ts": RUN_TS, "confirmed_spam_uids": ["1", "2"]}])

    def tearDown(self):
        ss._get_mailbox_config, ss._open_imap, ss._run_digest = self._orig
        os.environ.pop("DASHBOARD_PASS", None)
        os.environ.pop("DASHBOARD_USER", None)

    def req(self, *a, **k):
        return self.web.request(*a, **k)

    # --- delete confirmed spam -------------------------------------------
    def test_delete_link_from_older_digest_is_refused(self):
        token = shared.sign_delete_token(self.secret, EMAIL, "2026-11-07 08:00")
        ok, msg, _, _ = ss._check_delete_link(EMAIL, "2026-11-07 08:00", token)
        self.assertFalse(ok)
        self.assertIn("older digest", msg)

    def test_delete_get_confirms_then_post_deletes(self):
        token = shared.sign_delete_token(self.secret, EMAIL, RUN_TS)
        q = urllib.parse.urlencode({"email": EMAIL, "ts": RUN_TS, "token": token})
        status, _, body = self.req("GET", "/action/delete-spam?" + q)
        self.assertEqual(status, 200)
        self.assertEqual(self.calls, [], "GET must never delete")
        self.assertIn("Delete 2 email(s)", body)
        status, _, body = self.req("POST", "/action/delete-spam",
                                   form={"email": EMAIL, "ts": RUN_TS, "token": token})
        self.assertIn("Deleted 2 confirmed spam", body)
        self.assertEqual(self.calls, [("STORE", b"1,2"), ("EXPUNGE", None)])
        self.assertEqual(self.opened[-1], "Spam", "uses the folder the digest actually read")
        self.assertEqual(read_mailbox()["confirmed_spam_uids"], [])
        self.assertIn("Nothing to do", self.req("GET", "/action/delete-spam?" + q)[2])

    # --- dashboard actions -----------------------------------------------
    def test_dashboard_actions_are_post_only(self):
        self.assertEqual(self.req("GET", "/action/run-now")[0], 405)
        self.assertEqual(self.req("GET", "/action/run-mailbox?email=" + EMAIL)[0], 405)
        self.assertEqual(self.ran, [])

    def test_cross_site_post_rejected(self):
        status = self.req("POST", "/action/run-now", form={}, headers={"Sec-Fetch-Site": "cross-site"})[0]
        self.assertEqual(status, 403)
        status = self.req("POST", "/action/regenerate-link", form={"email": EMAIL, "purpose": "filters"},
                          headers={"Sec-Fetch-Site": "cross-site"})[0]
        self.assertEqual(status, 403)
        self.assertEqual(self.ran, [])

    def test_same_origin_post_runs(self):
        status, headers, _ = self.req("POST", "/action/run-now", form={}, headers={"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 303)
        self.assertIn("run_all_started", headers["Location"])
        self.assertEqual(self.req("POST", "/action/dry-run", form={})[0], 303)
        self.assertEqual(self.ran, ["force_send", "dry_run"])

    def test_security_headers_and_forms(self):
        status, headers, body = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("action='/action/run-now'", body)
        self.assertNotIn("href='/action/run-now'", body)

    def test_unknown_and_lookalike_paths_are_404(self):
        self.assertEqual(self.req("GET", "/nope")[0], 404)
        self.assertEqual(self.req("GET", "/reviewxyz?email=x%40example.com&token=t")[0], 404)
        self.assertEqual(self.req("POST", "/filtersfoo", form={})[0], 404)

    def test_bad_or_oversized_content_length(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.web.port, timeout=10)
        conn.putrequest("POST", "/action/delete-spam")
        conn.putheader("Content-Length", "abc")
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 400)
        status = self.req("POST", "/action/delete-spam", form={"x": "y" * 5000})[0]
        self.assertEqual(status, 413)

    # --- optional dashboard login (#42, #48) -----------------------------
    def test_login_disabled_by_default(self):
        self.assertEqual(self.req("GET", "/")[0], 200)

    def test_login_required_when_password_set(self):
        os.environ["DASHBOARD_PASS"] = "s3cret"
        status, headers, _ = self.req("GET", "/")
        self.assertEqual(status, 401)
        self.assertTrue(headers["WWW-Authenticate"].startswith('Basic realm="Spam-Digest"'))
        self.assertEqual(self.req("GET", "/", auth="admin:wrong")[0], 401)
        self.assertEqual(self.req("GET", "/", auth="admin:s3cret")[0], 200)
        self.assertEqual(self.req("POST", "/action/run-now", form={})[0], 401)
        self.assertEqual(self.ran, [])
        self.assertEqual(self.req("POST", "/action/run-now", form={}, auth="admin:s3cret")[0], 303)

    def test_custom_user_and_colon_in_password(self):
        os.environ["DASHBOARD_USER"], os.environ["DASHBOARD_PASS"] = "gio", "a:b"
        self.assertEqual(self.req("GET", "/", auth="gio:a:b")[0], 200)
        self.assertEqual(self.req("GET", "/", auth="admin:a:b")[0], 401)
        self.assertEqual(self.req("GET", "/", headers={"Authorization": "Basic !!!"})[0], 401)

    def test_tokenised_routes_not_behind_login(self):
        os.environ["DASHBOARD_PASS"] = "s3cret"
        self.assertEqual(self.req("GET", "/review?email=x%40example.com&token=bad")[0], 403)

    def test_lockout_hides_correct_password(self):
        os.environ["DASHBOARD_PASS"] = "s3cret"
        for _ in range(ss._AUTH_FAIL_MAX):
            self.assertEqual(self.req("GET", "/", auth="admin:nope")[0], 401)
        self.assertEqual(self.req("GET", "/", auth="admin:nope")[0], 429)
        self.assertEqual(self.req("GET", "/", auth="admin:s3cret")[0], 429)
        self.assertEqual(self.req("POST", "/action/run-now", form={}, auth="admin:s3cret")[0], 429)
        # expires after the window
        for dq in ss._auth_fail_state.values():
            for i in range(len(dq)):
                dq[i] -= ss._AUTH_FAIL_WINDOW_SECS + 1
        self.assertEqual(self.req("GET", "/", auth="admin:s3cret")[0], 200)

    def test_concurrent_burst_checks_at_most_the_limit(self):
        """Lockout check and attempt reservation are atomic (Codex review on #48)."""
        os.environ["DASHBOARD_PASS"] = "s3cret"
        checks, lock, real = [], threading.Lock(), ss._check_basic_auth

        def slow_check(header, creds):
            with lock:
                checks.append(1)
            time.sleep(0.05)            # widen the race window
            return real(header, creds)

        statuses = []

        def hit():
            conn = http.client.HTTPConnection("127.0.0.1", self.web.port, timeout=20)
            conn.request("GET", "/", headers={"Authorization": "Basic " + base64.b64encode(b"admin:nope").decode()})
            resp = conn.getresponse()
            resp.read()
            statuses.append(resp.status)

        ss._check_basic_auth = slow_check
        try:
            threads = [threading.Thread(target=hit) for _ in range(30)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            ss._check_basic_auth = real
        self.assertEqual(len(checks), ss._AUTH_FAIL_MAX)
        self.assertEqual(statuses.count(401), ss._AUTH_FAIL_MAX)
        self.assertEqual(self.req("GET", "/", auth="admin:s3cret")[0], 429)

    def test_requests_without_credentials_do_not_lock_out(self):
        os.environ["DASHBOARD_PASS"] = "s3cret"
        for _ in range(ss._AUTH_FAIL_MAX + 3):
            self.assertEqual(self.req("GET", "/")[0], 401)
        self.assertEqual(self.req("GET", "/", auth="admin:s3cret")[0], 200)


if __name__ == "__main__":
    unittest.main()
