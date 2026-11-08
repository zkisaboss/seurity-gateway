# Owner: Matthew Liao (Security)
import time, ipaddress, threading
from collections import defaultdict, deque

FORBIDDEN_PORTS = {
    21: "FTP (Plaintext credentials)", 22: "SSH (Unauthorized shell probe)",
    23: "Telnet (Mirai botnet vector / weak default credentials)", 25: "SMTP (Spam relay)",
    445: "SMB (EternalBlue / Worm propagation)", 3389: "RDP (Remote Desktop probe)",
    4444: "Metasploit / Reverse Shell payload", 6667: "IRC (Botnet C2 channel)"
}
LAN_NET = ipaddress.ip_network("192.168.1.0/24")
IOT_NET = ipaddress.ip_network("10.0.0.0/24")

class ThreatDetector:
    def __init__(self):
        self.lock = threading.Lock()
        self.port_history = defaultdict(deque)
        self.rate_history = defaultdict(deque)

    def inspect_traffic(self, source_ip, dest_ip, source_port, dest_port, protocol, is_allowed):
        with self.lock:
            now = time.time()
            alerts = []
            try:
                src, dst = ipaddress.ip_address(source_ip), ipaddress.ip_address(dest_ip)
            except ValueError:
                return alerts

            if dest_port in FORBIDDEN_PORTS:
                alerts.append({
                    "alert_type": "ALERT_FORBIDDEN_PORT",
                    "rule": "SIG-001: Forbidden Port Connection Attempt",
                    "severity": "HIGH",
                    "details": f"Attempted connection to restricted port {dest_port} ({FORBIDDEN_PORTS[dest_port]})."
                })

            if src in IOT_NET and dst not in LAN_NET and dst not in IOT_NET:
                alerts.append({
                    "alert_type": "ALERT_FORBIDDEN_DESTINATION",
                    "rule": "SIG-002: Rogue Outbound C2 Beaconing",
                    "severity": "CRITICAL",
                    "details": f"IoT device {source_ip} attempted unauthorized outbound connection to external host {dest_ip}:{dest_port}."
                })

            ports = self.port_history[source_ip]
            ports.append((now, dest_port))
            while ports and ports[0][0] < now - 8.0:
                ports.popleft()
            unique_ports = {p[1] for p in ports}
            if len(unique_ports) >= 4:
                alerts.append({
                    "alert_type": "ALERT_PORT_SCAN",
                    "rule": "SIG-003: Horizontal Port Scan Detected",
                    "severity": "HIGH",
                    "details": f"Source {source_ip} probed {len(unique_ports)} distinct ports ({sorted(list(unique_ports))[-6:]}) within 8s."
                })
                ports.clear()

            rates = self.rate_history[source_ip]
            rates.append(now)
            while rates and rates[0] < now - 3.0:
                rates.popleft()
            if len(rates) >= 8:
                alerts.append({
                    "alert_type": "ALERT_EXCESSIVE_TRAFFIC",
                    "rule": "SIG-004: Excessive Connection Burst",
                    "severity": "MEDIUM",
                    "details": f"Source {source_ip} exceeded threshold: {len(rates)} requests in 3s."
                })

            return alerts
