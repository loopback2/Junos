#!/usr/bin/env python3
import getpass
from netmiko import ConnectHandler

DEVICES_FILE = "devices.txt"

CMD1 = "set firewall family inet filter controlplane-filter term snmp_allow_in from source-address 10.0.0.0/24"
CMD2 = "set firewall family inet filter controlplane-filter term snmp_allow_in from source-address 10.1.0.0/24"

def load_hosts(path):
    hosts = []
    with open(path, "r") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            hosts.append(s.split(",")[0].strip())
    return hosts

def main():
    hosts = load_hosts(DEVICES_FILE)
    user = input("Username: ").strip()
    pw = getpass.getpass("Password: ")

    for host in hosts:
        print(f"-> {host} ... ", end="", flush=True)
        try:
            conn = ConnectHandler(device_type="juniper", host=host, username=user, password=pw, fast_cli=False)
            try:
                conn.send_command("set cli screen-length 0")
            except Exception:
                pass
            conn.config_mode()
            conn.send_config_set([CMD1, CMD2], exit_config_mode=False)
            conn.send_command_timing("commit")
            try:
                conn.exit_config_mode()
            except Exception:
                pass
            conn.disconnect()
            print("OK")
        except Exception as e:
            print(f"FAIL ({e})")

if __name__ == "__main__":
    main()
