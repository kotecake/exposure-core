"""Bounded evidence collection for the browser exposure research scenario."""
import argparse
import json
from urllib.request import Request, build_opener, ProxyHandler
from .__main__ import NoRedirect
from .engine import assess
from .fixtures import cases


def investigate(rule, observe, choose=None, budget=3):
    """Tool results must come from the same subject and snapshot as the rule's case."""
    facts, trace, tried = {}, [], set()
    fields = {"runtime": ("runtime", "channel", "platform", "at"),
              "inventory": ("installed", "channel", "platform", "at")}
    for _ in range(budget):
        result = assess({"rule": rule, "observation": facts})
        if result["verdict"] in {"affected", "outside_affected_range", "not_applicable"}:
            break
        if rule.get("stale", True):
            break
        available = [name for name in fields if name not in tried]
        if not available:
            break
        action = choose(available, result["verdict"], trace) if choose else available[0]
        if action not in available:
            raise ValueError("Planner returned an unavailable tool")
        tried.add(action)
        observed = observe(action)
        evidence = {key: observed[key] for key in fields[action] if observed.get(key) is not None}
        facts.update(evidence)
        trace.append({"tool": action, "returned_fields": sorted(evidence)})
    result = assess({"rule": rule, "observation": facts})
    return {"goal": "Determine browser exposure", "trace": trace, "assessment": result}


def local_planner(model):
    """Send only tool names, field names and a verdict to a loopback Ollama server."""
    def choose(available, verdict, trace):
        payload = {"model": model, "stream": False, "format": "json",
                   "prompt": "Investigate browser exposure. Pick one available evidence tool. "
                             "Prefer runtime evidence. Return JSON with key tool. State: "
                             + json.dumps(dict(available=available, verdict=verdict, trace=trace))}
        request = Request("http://127.0.0.1:11434/api/generate",
                          data=json.dumps(payload).encode(), headers={"Content-Type":"application/json"})
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=60) as response:
            return json.loads(json.load(response)["response"])["tool"]
    return choose


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", default="managed-patched", choices=[n for n, _, _ in cases()])
    parser.add_argument("--model", help="Optional installed Ollama model on localhost")
    args = parser.parse_args()
    case = next(c for n, c, _ in cases() if n == args.case)
    def replay(tool):
        if tool == "runtime" and case["observation"].get("runtime") is None:
            return {}
        return case["observation"]
    output = investigate(case["rule"], replay, local_planner(args.model) if args.model else None)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
