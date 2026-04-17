"""Shared helpers for spam-digest: paths, HMAC token signing, nonce rotation.

Imported by both spam_digest.py and status_server.py to keep token signing
and nonce handling identical across the two processes.
"""

import hashlib
import hmac
import json
import os
import secrets

DATA_DIR = "/data"
STATE_FILE = os.path.join(DATA_DIR, "spam_digest_last_run.json")
SECRET_FILE = os.path.join(DATA_DIR, "spam_digest_secret.key")
NONCES_FILE = os.path.join(DATA_DIR, "spam_digest_nonces.json")

# Purposes for management tokens. Keep these short and stable — they are
# part of the signed payload, so changing a value invalidates all outstanding
# links for that purpose.
PURPOSE_FILTERS = "filters"
PURPOSE_REVIEW = "review"
_VALID_PURPOSES = (PURPOSE_FILTERS, PURPOSE_REVIEW)


def load_or_create_secret():
    """Return the 32-byte HMAC signing secret, creating it on first use."""
    try:
        with open(SECRET_FILE) as f:
            return bytes.fromhex(f.read().strip())
    except FileNotFoundError:
        secret = os.urandom(32)
        try:
            with open(SECRET_FILE, "w") as f:
                f.write(secret.hex())
        except OSError:
            pass
        return secret
    except Exception:
        return os.urandom(32)


def load_secret():
    """Return the signing secret or None if the file is missing/unreadable."""
    try:
        with open(SECRET_FILE) as f:
            return bytes.fromhex(f.read().strip())
    except Exception:
        return None


def sign_delete_token(secret, email, ts):
    """Legacy signature for confirm-delete-spam links (email + run timestamp)."""
    msg = f"{email}|{ts}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def sign_mgmt_token(secret, purpose, email, nonce):
    """Sign a management token bound to (purpose, email, rotating nonce).

    Rotating the nonce revokes all previously issued links for that purpose.
    """
    if purpose not in _VALID_PURPOSES:
        raise ValueError(f"unknown token purpose: {purpose!r}")
    msg = f"mgmt|{purpose}|{email}|{nonce}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_mgmt_token(secret, purpose, email, nonce, token):
    """Constant-time compare of a management token against the expected value."""
    try:
        expected = sign_mgmt_token(secret, purpose, email, nonce)
    except ValueError:
        return False
    return hmac.compare_digest(expected, token)


def _load_nonces():
    try:
        with open(NONCES_FILE) as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    except Exception:
        pass
    return {}


def _save_nonces(nonces):
    try:
        with open(NONCES_FILE, "w") as f:
            json.dump(nonces, f)
    except OSError:
        pass


def get_nonce(email, purpose):
    """Return the current nonce for (email, purpose), or None if unset."""
    if purpose not in _VALID_PURPOSES:
        raise ValueError(f"unknown token purpose: {purpose!r}")
    return _load_nonces().get(email, {}).get(purpose)


def get_or_create_nonce(email, purpose):
    """Return the current nonce for (email, purpose), creating one if absent."""
    if purpose not in _VALID_PURPOSES:
        raise ValueError(f"unknown token purpose: {purpose!r}")
    nonces = _load_nonces()
    mb = nonces.setdefault(email, {})
    if not mb.get(purpose):
        mb[purpose] = secrets.token_hex(16)
        _save_nonces(nonces)
    return mb[purpose]


def rotate_nonce(email, purpose):
    """Force a new nonce for (email, purpose), revoking existing links."""
    if purpose not in _VALID_PURPOSES:
        raise ValueError(f"unknown token purpose: {purpose!r}")
    nonces = _load_nonces()
    mb = nonces.setdefault(email, {})
    mb[purpose] = secrets.token_hex(16)
    _save_nonces(nonces)
    return mb[purpose]
