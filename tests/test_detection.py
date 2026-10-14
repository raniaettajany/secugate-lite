import unittest
from src.contrat import PROCEDURES, Signal
from src.detection import analyser, compter_echecs, est_deja_vu, evaluer

def sig(type_="ACCES", gravite="FAIBLE", message="GET /home -> 200", ip="10.0.0.5"):
    return Signal("SIG-00001", "2026-10-05T10:00:00Z", "ACCES", ip, "web-app", type_, gravite, message)

class TestDetection(unittest.TestCase):
    def test_doublon(self):
        vus = set()
        self.assertFalse(est_deja_vu(sig(), vus))
        self.assertTrue(est_deja_vu(sig(), vus))

    def test_evaluer_echecs_login(self):
        e = sig("LOGIN_ECHEC", "MOYENNE")
        self.assertEqual(evaluer(e, 5), "CRITIQUE")
        self.assertEqual(evaluer(e, 4), "MOYENNE")

if __name__ == "__main__":
    unittest.main()