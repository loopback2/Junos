#!/usr/bin/env python3
"""
Audit Junos devices for presence of the substring:
  'set firewall family inet filter controlplane-filter term snmp_allow_in'
anywhere within:
  show configuration firewall family inet | display set | no-more

Outputs:
- CSV summary (--out): host, reachable, found, matches, error
- TXT file listing devices that matched (default: <csvbase>_have.txt)
- TXT file listing devices that did not match (default: <csvbase>_missing.txt)

Run:
  python3 audit_cp_snmp_term.py --devices devices.txt --out report.csv --workers 30
  # optional:
  # --have-file matched.txt --missing-file missing.txt
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

        # Disable pager (harmless if already off)
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

def write_list(lines: List[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

def default_txt_paths(csv_path: Path, have_file: Path | None, missing_file: Path | None) -> tuple[Path, Path]:
    if have_file and missing_file:
        return have_file, missing_file
    base = csv_path.stem  # e.g., "report" from "report.csv"
    parent = csv_path.parent
    have = have_file if have_file else parent / f"{base}_have.txt"
    missing = missing_file if missing_file else parent / f"{base}_missing.txt"
    return have, missing

def main() -> None:
    ap = argparse.ArgumentParser(description="Audit for presence of controlplane SNMP term substring.")
    ap.add_argument("--devices", required=True, type=Path, help="Path to devices.txt (one host/IP per line)")
    ap.add_argument("--out", required=True, type=Path, help="CSV report output path (e.g., report.csv)")
    ap.add_argument("--workers", type=int, default=30, help="Concurrent SSH sessions (default 30)")
    ap.add_argument("--timeout", type=int, default=90, help="SSH overall timeout seconds (default 90)")
    ap.add_argument("--auth-timeout", type=int, default=60, help="Auth timeout seconds (default 60)")
    ap.add_argument("--banner-timeout", type=int, default=60, help="Banner timeout seconds (default 60)")
    ap.add_argument("--conn-timeout", type=int, default=60, help="Connect timeout seconds (default 60)")
    ap.add_argument("--have-file", type=Path, help="TXT path for devices WITH the substring")
    ap.add_argument("--missing-file", type=Path, help="TXT path for devices WITHOUT the substring")
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

    # CSV
    write_csv(results, args.out)

    # Build lists
    reachable = [r for r in results if r[1]]
    found = sorted([r[0] for r in reachable if r[2]])
    missing = sorted([r[0] for r in reachable if not r[2]])

    # TXT paths (defaults derived from CSV path)
    have_path, missing_path = default_txt_paths(args.out, args.have_file, args.missing_file)
    write_list(found, have_path)
    write_list(missing, missing_path)

    # Console summary
    total = len(results)
    unreachable = [r for r in results if not r[1]]

    print("\n=== Audit Summary ===")
    print(f"Total devices:  {total}")
    print(f"Reachable:      {len(reachable)}")
    print(f"Unreachable:    {len(unreachable)}")
    print(f"Found:          {len(found)}  (listed in: {have_path})")
    print(f"Missing:        {len(missing)} (listed in: {missing_path})")

    if missing:
        print("\nDevices missing substring:")
        for h in missing:
            print(f"  - {h}")

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
