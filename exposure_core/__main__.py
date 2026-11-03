"""Offline replay and read-only collection interfaces."""
import argparse
import html
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from urllib.request import build_opener, HTTPRedirectHandler, Request
from .engine import assess
from .fixtures import cases


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


FEEDS = {"kev":"https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
         "github":"https://api.github.com/advisories?per_page=10"}


def collect():
    if sys.platform != "win32":
        return {"status":"unsupported_platform"}
    script = """
    $ErrorActionPreference='Stop'
    $p=@(Get-NetConnectionProfile | Select-Object InterfaceIndex,NetworkCategory)
    $l=@(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort)
    @{profiles=$p;listeners=$l;reachability='unknown'} | ConvertTo-Json -Depth 4 -Compress
    """
    try:
        output = subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",script],
                                capture_output=True,text=True,check=True,timeout=20)
        return json.loads(output.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"status":"collection_unavailable"}


def benchmark():
    rows = []
    for name, case, expected in cases():
        result = assess(case)
        obs = dict(case["observation"], runtime=case["observation"]["installed"])
        baseline = assess(dict(case, observation=obs))["verdict"]
        rows.append(dict(case=name, expected=expected, evidence=result["verdict"], inventory=baseline))
    return {"cases":rows, "matches":{k:sum(r[k]==r["expected"] for r in rows)
                                      for k in ("evidence","inventory")},
            "model_only":"not_run"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=["demo","benchmark","assess","retest","report","inspect","feeds","purge"])
    parser.add_argument("input",nargs="?")
    args = parser.parse_args()
    if args.command == "demo":
        out = {name:assess(case) for name,case,_ in cases()}
    elif args.command == "benchmark":
        out = benchmark()
    elif args.command == "inspect":
        out = collect()
    elif args.command in ("assess","retest","report"):
        if not args.input:
            parser.error("provide a normalized JSON case")
        out = assess(json.loads(Path(args.input).read_text(encoding="utf8")))
        if args.command == "report":
            print("<!doctype html><meta charset=utf-8><title>Exposure assessment</title><pre>"
                  +html.escape(json.dumps(out,indent=2))+"</pre>")
            return
    else:
        directory = Path(os.environ.get("LOCALAPPDATA",Path.home())) / ".exposure-core"
        directory.mkdir(mode=0o700,exist_ok=True)
        db = directory / "public-feeds.sqlite3"
        if args.command == "purge":
            db.unlink(missing_ok=True)
            out = {"purged":True}
        else:
            if args.input != "refresh":
                parser.error("use feeds refresh")
            out = {}
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS feed(name PRIMARY KEY, refreshed, body)")
                for name,url in FEEDS.items():
                    try:
                        with build_opener(NoRedirect()).open(Request(url,headers={"User-Agent":"exposure-core"}),timeout=12) as response:
                            data = response.read(16_000_001)
                        if len(data)>16_000_000:
                            raise ValueError("size")
                        parsed = json.loads(data)
                        if not isinstance(parsed if name=="github" else parsed["vulnerabilities"],list):
                            raise ValueError("shape")
                        conn.execute("INSERT OR REPLACE INTO feed VALUES(?,?,?)",
                                     (name,datetime.now(timezone.utc).isoformat(),data))
                        out[name]="refreshed"
                    except (OSError,ValueError,KeyError,TypeError):
                        out[name]="refresh_failed"
    print(json.dumps(out,indent=2))


if __name__ == "__main__":
    main()
