import unittest
from exposure_core.engine import assess
from exposure_core.fixtures import cases


class EngineTests(unittest.TestCase):
    def test_cases(self):
        for name,case,expected in cases():
            with self.subTest(name=name):
                self.assertEqual(assess(case)["verdict"],expected)

    def test_interfaces(self):
        _,case,_ = next(cases())
        for addr,expect in [("::1","loopback_only"),("127.0.0.1","loopback_only"),
                            ("0.0.0.0","possible_unverified"),("::","possible_unverified"),
                            ("invalid","unknown")]:
            case["observation"]["bind"]=addr
            self.assertEqual(assess(case)["listener"],expect)

    def test_minimization(self):
        _,case,_ = next(cases())
        case["observation"]["command_line"]="mock-secret"
        self.assertNotIn("mock-secret",str(assess(case)))
