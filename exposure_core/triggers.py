"""One-shot dispatcher for normalized local events. No polling or inference."""
import argparse
import json
from pathlib import Path

from .engine import assess


def triage(event):
    kind = event["kind"]
    if kind == "manual":
        return "investigate_on_request"
    if kind in {"network_changed", "vpn_changed"}:
        previous, current = event.get("before"), event.get("after")
        if previous == current:
            return "ignore_duplicate"
        if ((kind == "network_changed" and current == "public")
                or (kind == "vpn_changed" and previous == "connected" and current == "disconnected")):
            return "recheck_interfaces_listeners_and_firewall"
        return "record_context"
    if kind in {"playwright_build", "browser_launched", "advisory_changed"}:
        case = event.get("case")
        if case is None:
            return "collect_matching_product_and_runtime_evidence"
        if kind == "playwright_build":
            # Build evidence alone cannot establish which browser a later run will use.
            case = dict(case, observation=dict(case["observation"], runtime=None))
        return assess(case)["verdict"]
    raise ValueError("Unsupported event kind")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", type=Path)
    event = json.loads(parser.parse_args().event.read_text(encoding="utf8"))
    print(json.dumps({"action": triage(event), "model_calls": 0}))
