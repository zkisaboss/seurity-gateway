#!/usr/bin/env python3
# Owner: Matthew Liao (Security)
import os, sys, argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.gateway_core import SecurityGateway

def main():
    p = argparse.ArgumentParser(description="IoT Security Gateway Attack & Traffic Generator")
    p.add_argument("--attack", choices=["all", "telnet", "c2", "portscan", "flood", "command"], default="all")
    atk = p.parse_args().attack

    gw = SecurityGateway()
    if atk in ("telnet", "all"):
        print("Telnet:", "ALLOWED" if gw.run_scenario_telnet()["result"]["allowed"] else "BLOCKED")
    if atk in ("c2", "all"):
        print("C2:", "ALLOWED" if gw.run_scenario_c2_outbound()["result"]["allowed"] else "BLOCKED")
    if atk in ("portscan", "all"):
        print(f"PortScan: Evaluated {len(gw.run_scenario_port_scan()['results'])} ports")
    if atk in ("flood", "all"):
        print(f"Flood: Sent {len(gw.run_scenario_flood()['results'])} packets")
    if atk in ("command", "all"):
        print("Command:", "ALLOWED" if gw.run_scenario_command("TOGGLE_LED")["gateway_result"]["allowed"] else "BLOCKED")

if __name__ == "__main__":
    main()
