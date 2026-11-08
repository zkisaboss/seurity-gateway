#!/usr/bin/env python3
# Owner: Brandon Lyubarsky (Application / Dashboard), Support: Matthew Liao
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.gateway_core import SecurityGateway
from backend.database import get_events, clear_events

def run_tests():
    gw = SecurityGateway()
    clear_events()
    time.sleep(1)
    passed = 0

    t1 = gw.run_scenario_telemetry()
    if t1["result"]["allowed"] and "Allow-Outbound-Telemetry" in t1["result"]["rule"]:
        print("PASS: Normal sensor traffic")
        passed += 1
    else:
        print("FAIL: Normal sensor traffic")

    t2 = gw.run_scenario_command("TOGGLE_LED")
    if t2["gateway_result"]["allowed"] and t2["device_result"].get("success"):
        print("PASS: Legitimate application command")
        passed += 1
    else:
        print("FAIL: Legitimate application command")

    t3 = gw.run_scenario_telnet()
    if not t3["result"]["allowed"] and any(a.get("alert_type") == "ALERT_FORBIDDEN_PORT" for a in t3["result"]["alerts"]):
        print("PASS: Unauthorized connection to ESP32")
        passed += 1
    else:
        print("FAIL: Unauthorized connection to ESP32")

    t4 = gw.run_scenario_c2_outbound()
    if not t4["result"]["allowed"] and any(a.get("alert_type") == "ALERT_FORBIDDEN_DESTINATION" for a in t4["result"]["alerts"]):
        print("PASS: Forbidden outbound connection from ESP32")
        passed += 1
    else:
        print("FAIL: Forbidden outbound connection from ESP32")

    gw.run_scenario_port_scan()
    if any("Horizontal Port Scan Detected" in (e.get("rule_triggered") or "") for e in get_events(limit=50)):
        print("PASS: Port scan detection")
        passed += 1
    else:
        print("FAIL: Port scan detection")

    t6 = gw.reboot()
    if t6["persisted_event_counts"]["total"] > 0 and t6["status"] == "ONLINE":
        print("PASS: Gateway reboot persistence")
        passed += 1
    else:
        print("FAIL: Gateway reboot persistence")

    print(f"{passed}/6 tests passed")

if __name__ == "__main__":
    run_tests()
