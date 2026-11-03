import unittest
from exposure_core.fixtures import cases
from exposure_core.triggers import triage


class TriggerTests(unittest.TestCase):
    def test_network_transitions(self):
        for kind, before, after, expected in [
            ("network_changed","private","public","recheck_interfaces_listeners_and_firewall"),
            ("network_changed","public","public","ignore_duplicate"),
            ("vpn_changed","connected","disconnected","recheck_interfaces_listeners_and_firewall"),
            ("vpn_changed","unknown","disconnected","record_context"),
        ]:
            self.assertEqual(triage(dict(kind=kind,before=before,after=after)),expected)

    def test_build_and_launch(self):
        _, case, _ = next(cases())
        self.assertEqual(triage(dict(kind="playwright_build",case=case)),"potentially_affected")
        self.assertEqual(triage(dict(kind="browser_launched",case=case)),"affected")
