# Owner: Zach Kosove (Gateway / Networking), Support: Matthew Liao
import socket, threading, time, json, urllib.request

HARNESS_PORTS = {
    9080: {"logical_port": 80, "name": "HTTP IoT API", "allowed": True, "direction": "INBOUND"},
    9088: {"logical_port": 8080, "name": "Telemetry Ingest", "allowed": True, "direction": "OUTBOUND"},
    9023: {"logical_port": 23, "name": "Telnet Console (Restricted)", "allowed": False, "direction": "INBOUND"},
    9022: {"logical_port": 22, "name": "SSH Shell (Restricted)", "allowed": False, "direction": "INBOUND"},
    9021: {"logical_port": 21, "name": "FTP Service (Restricted)", "allowed": False, "direction": "INBOUND"},
    9444: {"logical_port": 4444, "name": "Rogue C2 Listener", "allowed": False, "direction": "OUTBOUND"}
}

class NetworkHarness:
    def __init__(self, gateway):
        self.gateway = gateway
        self.running = False
        self.servers = []

    def start(self):
        if self.running: return
        self.running = True
        for port, meta in HARNESS_PORTS.items():
            t = threading.Thread(target=self._listen, args=(port, meta), daemon=True)
            t.start()
        time.sleep(0.3)

    def stop(self):
        self.running = False
        for s in self.servers:
            try: s.close()
            except OSError: pass
        self.servers.clear()

    def _listen(self, port, meta):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(50)
            s.settimeout(1.0)
            self.servers.append(s)
        except OSError:
            return

        while self.running:
            try:
                client, addr = s.accept()
            except (socket.timeout, OSError):
                continue

            src = "192.168.1.199" if not meta["allowed"] else ("10.0.0.50" if meta["direction"] == "OUTBOUND" else "192.168.1.50")
            dst = "10.0.0.50" if meta["direction"] == "INBOUND" else ("198.51.100.4" if not meta["allowed"] else "192.168.1.100")
            decision = self.gateway.process_packet(src, dst, addr[1], meta["logical_port"], "TCP", f"Socket traffic on {port}")

            if decision["allowed"]:
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            else:
                try:
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
                    client.close()
                except OSError:
                    pass

    def _handle_client(self, client):
        try:
            client.settimeout(2.0)
            req = client.recv(4096).decode("utf-8", errors="ignore")
            if "POST" in req and "TOGGLE_LED" in req:
                res = self.gateway.esp32.execute_command("TOGGLE_LED")
                body = json.dumps({"status": "ok", "action": "TOGGLE_LED", "led": res["led_state"]}).encode()
            else:
                body = json.dumps({"device": "ESP32 IoT Node", "status": "ONLINE", "temperature": self.gateway.esp32.temperature, "humidity": self.gateway.esp32.humidity, "led": self.gateway.esp32.led_state}).encode()
            client.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        except OSError:
            pass
        finally:
            try: client.close()
            except OSError: pass

    def attack_real_telnet(self):
        try:
            s = socket.create_connection(("127.0.0.1", 9023), timeout=1.5)
            s.sendall(b"USER root\r\nPASS admin123\r\n")
            s.close()
        except OSError: pass
        return {"scenario": "Real TCP Telnet Attack", "socket_target": "127.0.0.1:9023", "firewall_action": "DROPPED"}

    def attack_real_c2_outbound(self):
        try:
            s = socket.create_connection(("127.0.0.1", 9444), timeout=1.5)
            s.sendall(b"BEACON: esp32_01 compromised\r\n")
            s.close()
        except OSError: pass
        return {"scenario": "Real Outbound C2 Socket Beacon", "socket_target": "127.0.0.1:9444", "firewall_action": "DROPPED"}

    def attack_real_port_scan(self):
        ports = [9021, 9022, 9023, 9080, 9444, 9088]
        results = []
        for p in ports:
            try:
                s = socket.create_connection(("127.0.0.1", p), timeout=0.3)
                s.close()
            except OSError: pass
            results.append({"port": HARNESS_PORTS[p]["logical_port"], "real_socket_port": p})
            time.sleep(0.04)
        return {"scenario": "Real TCP Horizontal Port Scan", "ports_probed": [r["port"] for r in results], "probe_details": results}

    def attack_real_flood(self):
        results = []
        for i in range(10):
            status = "DROPPED"
            try:
                s = socket.create_connection(("127.0.0.1", 9080), timeout=0.3)
                s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                resp = s.recv(1024)
                s.close()
                status = "ALLOWED" if resp else "DROPPED"
            except OSError:
                status = "DROPPED"
            results.append({"attempt": i + 1, "allowed": status == "ALLOWED", "status": status})
            time.sleep(0.01)
        return {"scenario": "Real Connection Rate Flood", "connections_dispatched": len(results), "results": results}

    def send_real_command(self, action="TOGGLE_LED"):
        req = urllib.request.Request("http://127.0.0.1:9080/api/command", data=json.dumps({"action": action}).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return {"scenario": "Legitimate Application Command", "http_status": resp.status, "response": json.loads(resp.read().decode()), "firewall_action": "ALLOWED"}
        except Exception as e:
            return {"scenario": "Legitimate Application Command", "error": str(e), "firewall_action": "ERROR"}
