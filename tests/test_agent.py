import unittest
from exposure_core.agent import investigate
from exposure_core.fixtures import cases


class AgentTests(unittest.TestCase):
    def setUp(self):
        _, self.case, _ = next(cases())

    def test_runtime_resolves_without_inventory(self):
        run = investigate(self.case["rule"], lambda _: self.case["observation"])
        self.assertEqual([s["tool"] for s in run["trace"]], ["runtime"])
        self.assertEqual(run["assessment"]["verdict"], "affected")

    def test_denied_runtime_changes_plan(self):
        run = investigate(self.case["rule"], lambda t: {} if t == "runtime" else self.case["observation"])
        self.assertEqual([s["tool"] for s in run["trace"]], ["runtime", "inventory"])
        self.assertEqual(run["assessment"]["verdict"], "potentially_affected")

    def test_planner_cannot_invent_actions(self):
        with self.assertRaises(ValueError):
            investigate(self.case["rule"], lambda _: self.fail(), lambda *_: "shell")

    def test_budget(self):
        run = investigate(self.case["rule"], lambda _: {}, budget=1)
        self.assertEqual(len(run["trace"]), 1)
        self.assertEqual(run["assessment"]["verdict"], "unknown")
