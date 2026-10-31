"""Megolm session export file format.

Implements the encrypted key export format from the Matrix spec
(https://spec.matrix.org/latest/client-server-api/#key-exports), which is what
Element and other clients read with "Import E2E room keys".
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
from typing import Any, Dict, List

from Crypto.Cipher import AES

HEADER = "-----BEGIN MEGOLM SESSION DATA-----"
FOOTER = "-----END MEGOLM SESSION DATA-----"
VERSION = 1
LINE_LENGTH = 96

# Unambiguous characters only (no 0/O, 1/l/I), so passwords are easy to copy by hand.
PASSPHRASE_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_passphrase(groups: int = 6, group_len: int = 5) -> str:
    """Generate a random passphrase like ``abcde-fghij-...`` (~170 bits for the defaults)."""
    return "-".join(
        "".join(secrets.choice(PASSPHRASE_ALPHABET) for _ in range(group_len))
        for _ in range(groups)
    )


def _derive_keys(passphrase: str, salt: bytes, rounds: int) -> tuple[bytes, bytes]:
    key = hashlib.pbkdf2_hmac("sha512", passphrase.encode("utf-8"), salt, rounds, dklen=64)
    return key[:32], key[32:]


def _aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    # The spec uses the whole 16-byte IV as a 128-bit big-endian counter block.
    return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv).encrypt(data)


def encrypt_key_export(
    sessions: List[Dict[str, Any]], passphrase: str, rounds: int = 500_000
) -> bytes:
    """Serialize and encrypt a list of exported megolm sessions."""
    if not 1 <= rounds <= 0xFFFFFFFF:
        raise ValueError("rounds must fit in an unsigned 32-bit integer")
    plaintext = json.dumps(sessions).encode("utf-8")

    salt = os.urandom(16)
    iv = bytearray(os.urandom(16))
    # Clear bit 63 so the counter can't overflow into the nonce half (matches Element).
    iv[8] &= 0x7F
    iv = bytes(iv)

    aes_key, hmac_key = _derive_keys(passphrase, salt, rounds)
    ciphertext = _aes_ctr(aes_key, iv, plaintext)

    body = bytes([VERSION]) + salt + iv + struct.pack(">I", rounds) + ciphertext
    body += hmac.new(hmac_key, body, hashlib.sha256).digest()

    encoded = base64.b64encode(body).decode("ascii")
    lines = [encoded[i : i + LINE_LENGTH] for i in range(0, len(encoded), LINE_LENGTH)]
    return "\n".join([HEADER, *lines, FOOTER, ""]).encode("ascii")


def decrypt_key_export(data: bytes, passphrase: str) -> List[Dict[str, Any]]:
    """Inverse of :func:`encrypt_key_export`. Used for testing and verification."""
    text = data.decode("ascii").strip()
    if not text.startswith(HEADER) or not text.endswith(FOOTER):
        raise ValueError("Missing megolm session data header/footer")
    body = base64.b64decode("".join(text[len(HEADER) : -len(FOOTER)].split()))
    if len(body) < 1 + 16 + 16 + 4 + 32 or body[0] != VERSION:
        raise ValueError("Unsupported or truncated key export")

    salt, iv = body[1:17], body[17:33]
    (rounds,) = struct.unpack(">I", body[33:37])
    ciphertext, mac = body[37:-32], body[-32:]

    aes_key, hmac_key = _derive_keys(passphrase, salt, rounds)
    expected = hmac.new(hmac_key, body[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Authentication check failed: incorrect password?")
    return json.loads(_aes_ctr(aes_key, iv, ciphertext))
