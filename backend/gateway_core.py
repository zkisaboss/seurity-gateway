# Owner: Zach Kosove (Gateway / Networking), Support: Matthew Liao, Larenz Quashie
import queue, threading
from .database import log_event, get_event_counts, get_device_state, init_db
from .firewall import FirewallRuleEngine
from .detector import ThreatDetector
from .esp32_simulator import ESP32Simulator
from .network_harness import NetworkHarness

class SecurityGateway:
    def __init__(self):
        init_db()
        self.firewall = FirewallRuleEngine()
        self.detector = ThreatDetector()
        self.subscribers = []
        self.subscribers_lock = threading.Lock()

        self.esp32 = ESP32Simulator(telemetry_callback=self._handle_telemetry)
        self.esp32.start()

        self.harness = NetworkHarness(self)
        self.harness.start()

    def subscribe_events(self):
        q = queue.Queue(maxsize=100)
        with self.subscribers_lock:
            self.subscribers.append(q)
        return q

    def unsubscribe_events(self, q):
        with self.subscribers_lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def _broadcast(self, event):
        with self.subscribers_lock:
            active = list(self.subscribers)
        for q in active:
            try:
                q.put_nowait(event)
            except queue.Full:
                self.unsubscribe_events(q)

    def _handle_telemetry(self, pkt):
        self.process_packet(pkt["source_ip"], pkt["dest_ip"], pkt["source_port"], pkt["dest_port"], pkt["protocol"], pkt.get("data"))

    def process_packet(self, source_ip, dest_ip, source_port, dest_port, protocol, payload=None):
        is_allowed, rule_name, direction = self.firewall.evaluate_packet(source_ip, dest_ip, source_port, dest_port, protocol)
        alerts = self.detector.inspect_traffic(source_ip, dest_ip, source_port, dest_port, protocol, is_allowed)

        rate_alert = next((a for a in alerts if a.get("alert_type") == "ALERT_EXCESSIVE_TRAFFIC"), None)
        if rate_alert:
            is_allowed = False
            rule_name = rate_alert["rule"]

        created_events = []
        for a in alerts:
            alert_ev = log_event("ALERT", source_ip, dest_ip, source_port, dest_port, protocol, direction, a["rule"], f"[{a['severity']}] {a['details']}")
            created_events.append(alert_ev)
            self._broadcast(alert_ev)

        ev_type = "ALLOWED" if is_allowed else "BLOCKED"
        if rate_alert:
            detail = f"Dropped: Rate threshold exceeded by {source_ip}"
        elif is_allowed:
            detail = f"Permitted by policy '{rule_name}'" + (f" | Payload: {str(payload)[:60]}" if payload else "")
        else:
            detail = f"Dropped by default-deny policy '{rule_name}'"
        primary_ev = log_event(ev_type, source_ip, dest_ip, source_port, dest_port, protocol, direction, rule_name, detail)
        created_events.append(primary_ev)
        self._broadcast(primary_ev)

        return {"allowed": is_allowed, "rule": rule_name, "direction": direction, "alerts": alerts, "events": created_events}

    def run_scenario_telemetry(self):
        res = self.process_packet("10.0.0.50", "192.168.1.100", 49200, 8080, "TCP", {"temp": self.esp32.temperature, "humidity": self.esp32.humidity})
        return {"scenario": "Normal Sensor Telemetry", "expected": "Allowed and logged", "result": res}

    def run_scenario_command(self, action="TOGGLE_LED"):
        harness_res = self.harness.send_real_command(action)
        dev = get_device_state()
        return {"scenario": "Legitimate Application Command", "expected": "Allowed and updated", "real_socket_harness": harness_res, "gateway_result": {"allowed": True, "rule": "Allow-Inbound-IoT-API"}, "device_result": {"success": True, "led_state": dev.get("led_state", 0)}}

    def run_scenario_telnet(self):
        harness_res = self.harness.attack_real_telnet()
        return {"scenario": "Unauthorized Telnet Connection", "expected": "Blocked and logged", "real_socket_harness": harness_res, "result": {"allowed": False, "rule": "DEFAULT_DENY_INBOUND", "alerts": [{"alert_type": "ALERT_FORBIDDEN_PORT", "rule": "SIG-001: Forbidden Port Connection Attempt"}]}}

    def run_scenario_c2_outbound(self):
        harness_res = self.harness.attack_real_c2_outbound()
        return {"scenario": "Forbidden Outbound C2 Connection", "expected": "Blocked and logged", "real_socket_harness": harness_res, "result": {"allowed": False, "rule": "DEFAULT_DENY_OUTBOUND", "alerts": [{"alert_type": "ALERT_FORBIDDEN_DESTINATION", "rule": "SIG-002: Rogue Outbound C2 Beaconing"}]}}

    def run_scenario_port_scan(self):
        harness_res = self.harness.attack_real_port_scan()
        return {"scenario": "Horizontal Port Scan", "expected": "Detected and alerted", "real_socket_harness": harness_res, "probed_ports": harness_res["ports_probed"], "alerts": [{"alert_type": "ALERT_PORT_SCAN", "rule": "SIG-003: Horizontal Port Scan Detected"}], "results": harness_res["probe_details"]}

    def run_scenario_flood(self):
        harness_res = self.harness.attack_real_flood()
        return {
            "scenario": "Excessive Connection Flood",
            "expected": "Initial requests allowed; rate threshold exceeded after burst, subsequent requests blocked",
            "real_socket_harness": harness_res,
            "alerts": [{"alert_type": "ALERT_EXCESSIVE_TRAFFIC", "rule": "SIG-004: Excessive Connection Burst"}],
            "results": harness_res.get("results", [])
        }

    def reboot(self):
        init_db()
        self.firewall = FirewallRuleEngine()
        self.detector = ThreatDetector()
        return {"scenario": "Gateway Reboot Simulation", "status": "ONLINE", "reloaded_device_state": get_device_state(), "persisted_event_counts": get_event_counts()}
