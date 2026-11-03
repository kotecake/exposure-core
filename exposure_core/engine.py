"""Pure assessment functions. Inputs are normalized evidence, never executable text."""
import ipaddress
import re


def version(value):
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,8}(\.[0-9]{1,8}){0,3}", value):
        parts = tuple(map(int, value.split(".")))
        return parts + (0,) * (4 - len(parts))
    return None


def assess(case):
    rule, obs = case["rule"], case["observation"]
    channel = obs.get("channel")
    bounds = rule.get("ranges", {}).get(channel, {})
    low, fixed = version(bounds.get("from")), version(bounds.get("fixed"))
    running, installed = version(obs.get("runtime")), version(obs.get("installed"))
    status, reason = "unknown", "Missing or unsupported runtime, platform or channel evidence."
    if rule.get("retracted"):
        status, reason = "not_applicable", "Advisory withdrawn."
    elif rule.get("stale", True):
        reason = "Refresh advisory evidence before making a current decision."
    elif low and fixed and low < fixed and obs.get("platform") == rule.get("platform"):
        if running:
            status = "affected" if low <= running < fixed else "outside_affected_range"
            reason = "Compared the observed executable against its channel-specific range."
        elif obs.get("runtime") is None and installed and low <= installed < fixed:
            status, reason = "potentially_affected", "Affected component installed. Launch is unverified."
    bind = obs.get("bind")
    reach = "unknown"
    if bind:
        try:
            address = ipaddress.ip_address(bind)
            reach = "loopback_only" if address.is_loopback else "possible_unverified"
        except ValueError:
            pass
    return dict(verdict=status, reason=reason, listener=reach,
                sandbox_disabled=obs.get("sandbox_disabled") is True,
                advisory=rule["id"], observed_at=obs.get("at"),
                source_as_of=rule.get("as_of"), next_action={
                    "affected":"Verify vendor fix, update and relaunch, then retest.",
                    "outside_affected_range":"Reassess when runtime or advisory changes.",
                    "potentially_affected":"Identify the executable used in the actual launch.",
                    "unknown":"Gather missing evidence or refresh the advisory.",
                    "not_applicable":"Retain the withdrawal for audit."
                }[status])
