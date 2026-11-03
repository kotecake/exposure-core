# Exposure Core

Does knowing which executable actually ran improve workstation security triage? This offline-first research prototype compares package inventory with observed runtime evidence. In the included paired example, the installed browser is susceptible and the observed launch is patched. The two methods give different answers on the same evidence.

## Run from the repository root

Requires Python 3.11 or later. No dependencies or credentials for replay.

    python -m exposure_core demo
    python -m exposure_core benchmark
    python -m exposure_core assess examples/patched-launch.json
    python -m exposure_core report examples/patched-launch.json > report.html
    python -m unittest discover -s tests -v

## Results and scope

The evidence matcher matches 11 of 11 author-labelled synthetic cases. The inventory baseline substitutes installed version for runtime and matches 7 of 11. Both use the same advisory conditions. These small development fixtures exercise branches of the implementation. They provide no estimate of real-world accuracy. No independent labels, temporal holdout, or model-only arm have been measured. Full case-level outcomes are in examples/benchmark.json.

## Architecture and threat model

A normalized rule records channel, platform, affected interval, source date and lifecycle. A local observation records runtime and installed versions. The pure matcher joins those fields and keeps interface binding separate from reachability. Unsupported version syntax and missing evidence produce uncertainty. The escaped HTML and JSON renderers consume the same assessment. Fixture bulletins are fictional. The research harness trusts the supplied freshness and runtime labels, so independently validate those fields before using real inputs.

The inspect command requests Windows network profiles and listening addresses without elevation. The live collector does not identify which browser a particular agent launched or evaluate effective firewall rules. It has not been validated on a managed Windows endpoint. Network commands never run during the offline demo. The optional feeds refresh command retrieves public CISA KEV and GitHub advisory data from fixed HTTPS endpoints into a local SQLite cache and rejects redirects. Feed records are informational and currently require manual normalization for assessment. The purge command removes that cache. Retest reruns assessment against a supplied new snapshot.

## Research roadmap

Next milestones are live runtime attribution, Firefox/ESR and Chrome vendor adapters, dated evidence edges, independent labelling, held-out advisory families and a budget-matched model-only evaluation. Record unsupported confident claims, misses, false alerts, citation accuracy, latency, tokens and cost before making public performance claims. The initial offline result uses zero inference tokens.

## Provenance

All code and fixtures in this initial history were generated for this project. No employer code, workstation observations or client records are included. Public feed sources: https://github.com/cisagov/kev-data and https://docs.github.com/en/rest/security-advisories/global-advisories . No third-party feed payloads are redistributed.

## Agent investigation demo

    python -m exposure_core.agent --case managed-patched
    python -m exposure_core.agent --case unobserved-launch

The agent starts without observation fields and chooses among read-only evidence tools. In the first replay it obtains runtime evidence and stops. In the second it cannot observe the runtime, requests inventory and returns a qualified verdict. Both commands use synthetic tool results and a deterministic default planner. To delegate tool selection to an installed local Ollama model, append `--model MODEL_NAME`. The controller enforces an action allowlist and budget. The model cannot set the verdict or run commands. This experiment has no measured live-model results yet. The Windows collector and public feeds are separate CLI features pending integration into this loop.

## Event-driven triage

Run `python -m exposure_core.triggers event.json` for a single normalized event, for example
`{"kind":"vpn_changed","before":"connected","after":"disconnected"}`.
The dispatcher returns a recommended local check or an evidence-based verdict and exits. It makes zero model calls. A manual investigation is available with `python -m exposure_core.agent`. Native network/VPN subscriptions, build hooks and alert delivery are future adapters. A production adapter should debounce transitions, coalesce by device/project plus advisory revision and evidence fingerprint, refresh affected facts, and notify only on changed exposure. A VPN provider must supply trusted status. A public network or VPN loss alone cannot establish exploitability. Keep automatic LLM invocation off by default. Any future opt-in escalation should require a specific unresolved decision, eligible evidence, a per-run and daily token limit, and a stop condition.
