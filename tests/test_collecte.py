import unittest
from src.collecte import masquer_ip, masquer_parametres, normaliser_acces, normaliser_scan

LIGNE = "2026-10-05 10:01:10 192.168.1.15 POST /login 401"


class TestCollecte(unittest.TestCase):
    def test_masquer_ip(self):
        self.assertEqual(masquer_ip("192.168.1.15"), "192.168.1.x")
        with self.assertRaises(ValueError):
            masquer_ip("192.168.1")

    def test_masquer_parametres(self):
        res = masquer_parametres("/api?id=3&token=abc123&password=secret")
        self.assertEqual(res, "/api?id=3&token=[MASQUE]&password=[MASQUE]")

    def test_normaliser_acces(self):
        sig = normaliser_acces(LIGNE, 42)
        self.assertEqual(sig.id, "SIG-00042")
        self.assertEqual(sig.timestamp, "2026-10-05T10:01:10Z")
        self.assertEqual(sig.type, "LOGIN_ECHEC")
        self.assertEqual(sig.gravite, "MOYENNE")

    def test_normaliser_scan(self):
        rapport = {
            "rule": "S3649",
            "component": "backend",
            "severity": "blocker",
            "message": "injection SQL possible",
            "date": "2026-10-05T10:05:00Z"
        }
        sig = normaliser_scan(rapport, 1)
        self.assertEqual(sig.id, "SIG-00001")
        self.assertEqual(sig.source, "SCAN")
        self.assertEqual(sig.type, "FAILLE")
        self.assertEqual(sig.gravite, "CRITIQUE")


if __name__ == "__main__":
    unittest.main()
