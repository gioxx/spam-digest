"""Shared test helpers: an isolated /data directory, IMAP fakes, HTTP client.

Standard library only. Import this module before the app modules are used:
it redirects every data file to a temporary directory so tests never touch
/data.
"""

import base64
import http.client
import http.server
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import shared  # noqa: E402

DATA_DIR = tempfile.mkdtemp(prefix="spam-digest-tests-")
shared.DATA_DIR = DATA_DIR
for _name in ("STATE_FILE", "SECRET_FILE", "NONCES_FILE", "FILTERS_FILE", "ALLOWLIST_FILE"):
    setattr(shared, _name, os.path.join(DATA_DIR, os.path.basename(getattr(shared, _name))))
shared._LOCK_FILE = os.path.join(DATA_DIR, ".lock")

import spam_digest as sd  # noqa: E402
import status_server as ss  # noqa: E402

sd.STATE_FILE = ss.STATE_FILE = shared.STATE_FILE
ss._ACTIONS_LOG_FILE = os.path.join(DATA_DIR, "actions.log")

EMAIL = "me@example.com"


def reset_data():
    """Empty the data directory and in-memory limiters between tests."""
    for name in os.listdir(DATA_DIR):
        path = os.path.join(DATA_DIR, name)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    ss._rate_state.clear()
    ss._auth_fail_state.clear()


def write_state(mailboxes):
    with open(shared.STATE_FILE, "w") as f:
        json.dump({"mailboxes": mailboxes}, f)


def read_mailbox(email=EMAIL):
    with open(shared.STATE_FILE) as f:
        return next(m for m in json.load(f)["mailboxes"] if m["email_address"] == email)


def review_entry(uid, subject="s", sender="X <x@a.example.com>"):
    return {"uid": uid, "subject": subject, "from": sender,
            "date": "2026-11-01 10:00", "ai_reason": "r"}


def mail(uid, label, sender="a@b.example.com", subject=None):
    return {"uid": uid, "subject": subject or f"s{uid}", "from": sender, "date": "d",
            "ai_label": label, "ai_reason": "r"}


class FakeMail:
    """In-process stand-in for an imaplib connection; records commands."""

    def __init__(self, calls, fail=None, uidvalidity=42):
        self.calls, self.fail, self.uidvalidity = calls, fail, uidvalidity

    def uid(self, cmd, *args):
        self.calls.append((cmd, args[0]))
        return ("NO" if cmd == self.fail else "OK"), None

    def expunge(self):
        self.calls.append(("EXPUNGE", None))

    def response(self, code):
        return "OK", [str(self.uidvalidity).encode()] if self.uidvalidity is not None else [None]

    def logout(self):
        pass


class FakeIMAPServer:
    """Minimal IMAP4rev1 server over plain TCP.

    Speaks just enough of the protocol for imaplib (LOGIN, SELECT with an
    UIDVALIDITY response code, UID SEARCH/STORE/COPY/FETCH-less, EXPUNGE,
    LOGOUT), so imaplib's real response parsing is exercised.
    """

    def __init__(self, uidvalidity=1234):
        self.uidvalidity = uidvalidity
        self.commands = []
        server = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(b"* OK fake IMAP ready\r\n")
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    tag, cmd, *rest = line.decode().rstrip("\r\n").split(" ", 2)
                    cmd, arg = cmd.upper(), (rest[0] if rest else "")
                    server.commands.append((cmd, arg))
                    if cmd == "CAPABILITY":
                        out = "* CAPABILITY IMAP4rev1\r\n"
                    elif cmd == "SELECT":
                        out = (f"* 3 EXISTS\r\n* 0 RECENT\r\n"
                               f"* OK [UIDVALIDITY {server.uidvalidity}] UIDs valid\r\n")
                        self.wfile.write(out.encode() + f"{tag} OK [READ-WRITE] done\r\n".encode())
                        continue
                    elif cmd == "UID" and arg.upper().startswith("SEARCH"):
                        out = "* SEARCH\r\n"
                    elif cmd == "LOGOUT":
                        self.wfile.write(f"* BYE\r\n{tag} OK bye\r\n".encode())
                        return
                    elif cmd in ("LOGIN", "UID", "EXPUNGE"):
                        out = ""
                    else:
                        self.wfile.write(f"{tag} BAD unknown\r\n".encode())
                        continue
                    self.wfile.write(out.encode() + f"{tag} OK done\r\n".encode())

        self._srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def writes(self):
        """STORE/COPY/EXPUNGE commands received (no SEARCH)."""
        return [c for c in self.commands
                if c[0] == "EXPUNGE" or (c[0] == "UID" and not c[1].upper().startswith("SEARCH"))]

    def config(self):
        return {"imap_server": "127.0.0.1", "imap_port": self.port, "imap_use_ssl": False,
                "email_user": "u", "email_pass": "p", "spam_folder": "Junk"}

    def close(self):
        self._srv.shutdown()
        self._srv.server_close()


class WebServer:
    """status_server's handler on a real ThreadingHTTPServer, on localhost."""

    def __init__(self):
        class _Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = 64  # same as status_server's __main__

        self._srv = _Server(("127.0.0.1", 0), ss._Handler)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def request(self, method, path, form=None, headers=None, auth=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = dict(headers or {})
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if auth is not None:
            hdrs["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def close(self):
        self._srv.shutdown()
        self._srv.server_close()
