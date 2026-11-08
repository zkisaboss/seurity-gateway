# Owner: Brandon Lyubarsky (Application / Dashboard)
import os, sys, json, urllib.parse, queue, time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from .gateway_core import SecurityGateway
from .database import get_events, get_event_counts, get_device_state, get_rules, clear_events

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")

class GatewayRequestHandler(SimpleHTTPRequestHandler):
    gateway_instance = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def log_message(self, format, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)

        if path == "/favicon.ico":
            self.send_response(204); self.end_headers(); return
        if path == "/api/status":
            return self._send_json({"gateway": {"status": "ONLINE", "mode": "ENFORCING", "policy": "DEFAULT_DENY", "counts": get_event_counts()}, "device": get_device_state()})
        if path == "/api/events":
            limit = int(query.get("limit", [100])[0])
            ev_type = query.get("type", ["ALL"])[0]
            evs = get_events(limit=limit, event_type=ev_type)
            return self._send_json({"events": evs, "count": len(evs)})
        if path == "/api/rules":
            return self._send_json({"rules": get_rules()})
        if path == "/api/stream":
            return self._handle_sse()
        super().do_GET()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        clen = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(clen).decode("utf-8")) if clen > 0 else {}

        if path == "/api/command":
            return self._send_json(self.gateway_instance.run_scenario_command(body.get("action", "TOGGLE_LED")))
        if path == "/api/attack":
            sc = body.get("scenario", "")
            actions = {
                "telnet": self.gateway_instance.run_scenario_telnet,
                "c2_outbound": self.gateway_instance.run_scenario_c2_outbound,
                "port_scan": self.gateway_instance.run_scenario_port_scan,
                "flood": self.gateway_instance.run_scenario_flood,
                "telemetry": self.gateway_instance.run_scenario_telemetry
            }
            if sc in actions:
                return self._send_json(actions[sc]())
            return self._send_json({"error": f"Unknown attack '{sc}'"}, status=400)
        if path == "/api/reset":
            clear_events()
            return self._send_json({"success": True})
        if path == "/api/reboot":
            return self._send_json(self.gateway_instance.reboot())
        self._send_json({"error": "Not found"}, status=404)

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = self.gateway_instance.subscribe_events()
        try:
            self.wfile.write(f"data: {json.dumps({'type': 'CONNECTED'})}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    ev = q.get(timeout=1.0)
                    self.wfile.write(f"data: {json.dumps({'type': 'EVENT', 'data': ev})}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except OSError:
            pass
        finally:
            self.gateway_instance.unsubscribe_events(q)

class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        if not issubclass(sys.exc_info()[0] or Exception, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            super().handle_error(request, client_address)

def start_server(host="0.0.0.0", port=8080, max_port_attempts=10):
    gateway = SecurityGateway()
    GatewayRequestHandler.gateway_instance = gateway
    for attempt in range(max_port_attempts):
        candidate = port + attempt
        try:
            return ReusableThreadingHTTPServer((host, candidate), GatewayRequestHandler), candidate
        except OSError:
            if attempt == max_port_attempts - 1: raise
