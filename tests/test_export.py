import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "getkeys"))

from export import (  # noqa: E402
    FOOTER,
    HEADER,
    decrypt_key_export,
    encrypt_key_export,
    generate_passphrase,
)

SESSIONS = [
    {
        "algorithm": "m.megolm.v1.aes-sha2",
        "forwarding_curve25519_key_chain": [],
        "room_id": "!room:example.com",
        "sender_key": "sender",
        "sender_claimed_keys": {"ed25519": "signing"},
        "session_id": "sessionid",
        "session_key": "sessionkey",
    }
]


class ExportTest(unittest.TestCase):
    def test_round_trip(self):
        data = encrypt_key_export(SESSIONS, "hunter2", rounds=1000)
        text = data.decode()
        self.assertTrue(text.startswith(HEADER + "\n"))
        self.assertTrue(text.endswith(FOOTER + "\n"))
        self.assertEqual(decrypt_key_export(data, "hunter2"), SESSIONS)

    def test_wrong_password(self):
        data = encrypt_key_export(SESSIONS, "hunter2", rounds=1000)
        with self.assertRaises(ValueError):
            decrypt_key_export(data, "hunter3")

    def test_iv_bit_63_cleared(self):
        import base64

        for _ in range(20):
            text = encrypt_key_export(SESSIONS, "pw", rounds=1).decode()
            body = base64.b64decode("".join(text.splitlines()[1:-1]))
            self.assertEqual(body[17 + 8] & 0x80, 0)

    def test_passphrase(self):
        pw = generate_passphrase()
        self.assertEqual(len(pw), 6 * 5 + 5)
        self.assertNotEqual(pw, generate_passphrase())

    def test_real_olm_session(self):
        try:
            import olm
        except ImportError:
            self.skipTest("python-olm not installed")
        outbound = olm.OutboundGroupSession()
        inbound = olm.InboundGroupSession(outbound.session_key)
        ciphertext = outbound.encrypt("hello")
        sessions = [dict(SESSIONS[0], session_id=inbound.id,
                         session_key=inbound.export_session(inbound.first_known_index))]
        restored = decrypt_key_export(encrypt_key_export(sessions, "pw", rounds=1000), "pw")
        imported = olm.InboundGroupSession.import_session(restored[0]["session_key"])
        self.assertEqual(imported.id, inbound.id)
        self.assertEqual(imported.decrypt(ciphertext)[0], "hello")


if __name__ == "__main__":
    unittest.main()
