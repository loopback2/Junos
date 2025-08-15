#!/usr/bin/env python3
"""
Audit Junos devices for presence of the substring:
  'set firewall family inet filter controlplane-filter term snmp_allow_in'
anywhere within:
  show configuration firewall family inet | display set | no-more

- Netmiko + getpass
- Concurrent SSH with clean teardown
- CSV summary: host, reachable, found, matches, error
"""

from __future__ import annotations
import argparse
import csv
import getpass
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Tuple, List

from netmiko import ConnectHandler

TARGET_SUBSTR = "set firewall family inet filter controlplane-filter term snmp_allow_in"

def load_devices(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    hosts: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        hosts.append(line.split(",")[0].strip())
    if not hosts:
        raise ValueError(f"No hosts found in {path}")
    return hosts

def canonicalize(s: str) -> str:
    return " ".join(s.split())

def check_host(host: str, username: str, password: str, timeouts: Dict[str, int]) -> Tuple[str, bool, bool, int, str]:
    """
    Returns: (host, reachable, found, matches, error)
    """
    conn = None
    try:
        conn = ConnectHandler(
            device_type="juniper",
            host=host,
            username=username,
            password=password,
            fast_cli=False,
            global_delay_factor=1,
            timeout=timeouts["timeout"],
            auth_timeout=timeouts["auth_timeout"],
            banner_timeout=timeouts["banner_timeout"],
            conn_timeout=timeouts["conn_timeout"],
        )

        # Ensure pager is off; harmless if already unset
        try:
            conn.send_command("set cli screen-length 0")
        except Exception:
            pass

        cmd = "show configuration firewall family inet | display set | no-more"
        out = conn.send_command(cmd)

        target = canonicalize(TARGET_SUBSTR)
        matches = 0
        for line in out.splitlines():
            if target in canonicalize(line):
                matches += 1

        found = matches > 0
        return (host, True, found, matches, "")

    except Exception as e:
        return (host, False, False, 0, str(e))
    finally:
        try:
            if conn:
                conn.disconnect()
        except Exception:
            pass

def write_csv(rows: List[Tuple[str, bool, bool, int, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "reachable", "found", "matches", "error"])
        for r in rows:
            w.writerow(r)

def main() -> None:
    ap = argparse.ArgumentParser(description="Audit for presence of controlplane SNMP term substring.")
    ap.add_argument("--devices", required=True, type=Path, help="Path to devices.txt (one host/IP per line)")
    ap.add_argument("--out", required=True, type=Path, help="CSV report output path (e.g., report.csv)")
    ap.add_argument("--workers", type=int, default=30, help="Concurrent SSH sessions (default 30)")
    ap.add_argument("--timeout", type=int, default=90, help="SSH overall timeout seconds (default 90)")
    ap.add_argument("--auth-timeout", type=int, default=60, help="Auth timeout seconds (default 60)")
    ap.add_argument("--banner-timeout", type=int, default=60, help="Banner timeout seconds (default 60)")
    ap.add_argument("--conn-timeout", type=int, default=60, help="Connect timeout seconds (default 60)")
    args = ap.parse_args()

    hosts = load_devices(args.devices)
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    timeouts = {
        "timeout": int(args.timeout),
        "auth_timeout": int(args.auth_timeout),
        "banner_timeout": int(args.banner_timeout),
        "conn_timeout": int(args.conn_timeout),
    }

    print(f"Auditing {len(hosts)} devices for substring:\n  '{TARGET_SUBSTR}'")

    results: List[Tuple[str, bool, bool, int, str]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = [ex.submit(check_host, h, username, password, timeouts) for h in hosts]
        for fut in as_completed(futs):
            results.append(fut.result())

    write_csv(results, args.out)

    # Console summary
    total = len(results)
    reachable = [r for r in results if r[1]]
    unreachable = [r for r in results if not r[1]]
    found = [r for r in reachable if r[2]]
    missing = [r for r in reachable if not r[2]]

    print("\n=== Audit Summary ===")
    print(f"Total devices:  {total}")
    print(f"Reachable:      {len(reachable)}")
    print(f"Unreachable:    {len(unreachable)}")
    print(f"Found:          {len(found)}")
    print(f"Missing:        {len(missing)}")

    if missing:
        print("\nDevices missing substring:")
        for host, *_ in sorted([(r[0],) for r in missing]):
            print(f"  - {host}")

    if unreachable:
        print("\nUnreachable devices:")
        for host, *_ in sorted([(r[0],) for r in unreachable]):
            print(f"  - {host}")

    print(f"\nCSV saved to: {args.out}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(1)
