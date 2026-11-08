# Owner: Zach Kosove (Gateway / Networking)
import ipaddress
from .database import get_rules

IOT_NET = ipaddress.ip_network("10.0.0.0/24")
ESP32_IP = ipaddress.ip_address("10.0.0.50")

def evaluate_packet(source_ip, dest_ip, source_port, dest_port, protocol):
    src, dst = ipaddress.ip_address(source_ip), ipaddress.ip_address(dest_ip)
    proto = protocol.upper()
    direction = "INBOUND" if (dst in IOT_NET or dst == ESP32_IP) else ("OUTBOUND" if (src in IOT_NET or src == ESP32_IP) else "TRANSIT")

    for r in get_rules():
        if not r["enabled"]: continue
        if r["direction"] not in ("ANY", direction): continue
        if r["protocol"] not in ("ANY", proto): continue
        if r["dest_port"] is not None and r["dest_port"] != dest_port: continue
        try:
            if src in ipaddress.ip_network(r["source_cidr"], strict=False) and dst in ipaddress.ip_network(r["dest_cidr"], strict=False):
                return r["action"] == "ALLOW", r["name"], direction
        except ValueError:
            continue

    return False, f"DEFAULT_DENY_{direction}", direction

class FirewallRuleEngine:
    evaluate_packet = staticmethod(evaluate_packet)
