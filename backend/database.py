# Owner: Brandon Lyubarsky (Application / Dashboard), Support: Zach Kosove, Larenz Quashie
import os, sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gateway.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
            source_ip TEXT NOT NULL, dest_ip TEXT NOT NULL, source_port INTEGER NOT NULL, dest_port INTEGER NOT NULL,
            protocol TEXT NOT NULL, direction TEXT NOT NULL, rule_triggered TEXT NOT NULL, details TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS device_state (
            device_id TEXT PRIMARY KEY, device_name TEXT NOT NULL, ip_address TEXT NOT NULL, mac_address TEXT NOT NULL,
            status TEXT NOT NULL, led_state INTEGER NOT NULL DEFAULT 0, temperature REAL NOT NULL DEFAULT 24.5,
            humidity REAL NOT NULL DEFAULT 48.0, firmware_version TEXT NOT NULL, last_seen TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, direction TEXT NOT NULL,
            source_cidr TEXT NOT NULL, dest_cidr TEXT NOT NULL, dest_port INTEGER, protocol TEXT NOT NULL,
            action TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, description TEXT)""")

        if c.execute("SELECT COUNT(*) FROM device_state").fetchone()[0] == 0:
            c.execute("INSERT INTO device_state VALUES ('esp32-node-01', 'ESP32 Insecure IoT Node', '10.0.0.50', '24:6F:28:AB:CD:EF', 'ONLINE', 0, 24.2, 51.5, 'v1.0.0-insecure', datetime('now'))")

        if c.execute("SELECT COUNT(*) FROM firewall_rules").fetchone()[0] == 0:
            c.executemany("INSERT INTO firewall_rules (name, direction, source_cidr, dest_cidr, dest_port, protocol, action, enabled, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [
                ("Allow-Inbound-IoT-API", "INBOUND", "192.168.1.0/24", "10.0.0.50/32", 80, "TCP", "ALLOW", 1, "Allows legitimate LAN controller to send HTTP commands to ESP32 API"),
                ("Allow-Outbound-Telemetry", "OUTBOUND", "10.0.0.50/32", "192.168.1.100/32", 8080, "TCP", "ALLOW", 1, "Allows ESP32 to publish sensor telemetry to Pi Gateway / Middleware"),
                ("Allow-Inbound-DNS-Relay", "INBOUND", "10.0.0.50/32", "10.0.0.1/32", 53, "UDP", "ALLOW", 1, "Allows DNS resolution queries to Gateway local resolver")
            ])

def log_event(event_type, source_ip, dest_ip, source_port, dest_port, protocol, direction, rule_triggered, details=""):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO events (timestamp, event_type, source_ip, dest_ip, source_port, dest_port, protocol, direction, rule_triggered, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (ts, event_type, source_ip, dest_ip, source_port, dest_port, protocol, direction, rule_triggered, details))
        eid = cur.lastrowid
    return {"id": eid, "timestamp": ts, "event_type": event_type, "source_ip": source_ip, "dest_ip": dest_ip, "source_port": source_port, "dest_port": dest_port, "protocol": protocol, "direction": direction, "rule_triggered": rule_triggered, "details": details}

def get_events(limit=100, event_type=None):
    with get_db_connection() as conn:
        c = conn.cursor()
        if event_type and event_type.upper() != "ALL":
            return [dict(r) for r in c.execute("SELECT * FROM events WHERE event_type = ? ORDER BY id DESC LIMIT ?", (event_type.upper(), limit)).fetchall()]
        return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

def get_event_counts():
    with get_db_connection() as conn:
        r = conn.cursor().execute("SELECT COUNT(*), SUM(CASE WHEN event_type = 'ALLOWED' THEN 1 ELSE 0 END), SUM(CASE WHEN event_type = 'BLOCKED' THEN 1 ELSE 0 END), SUM(CASE WHEN event_type = 'ALERT' THEN 1 ELSE 0 END) FROM events").fetchone()
        return {"total": r[0] or 0, "allowed": r[1] or 0, "blocked": r[2] or 0, "alerts": r[3] or 0}

def get_device_state():
    with get_db_connection() as conn:
        r = conn.cursor().execute("SELECT * FROM device_state WHERE device_id = 'esp32-node-01'").fetchone()
        return dict(r) if r else {}

def update_device_state(led_state=None, temperature=None, humidity=None, status=None):
    updates, params = ["last_seen = datetime('now')"], []
    if led_state is not None: updates.append("led_state = ?"); params.append(led_state)
    if temperature is not None: updates.append("temperature = ?"); params.append(temperature)
    if humidity is not None: updates.append("humidity = ?"); params.append(humidity)
    if status is not None: updates.append("status = ?"); params.append(status)
    with get_db_connection() as conn:
        conn.cursor().execute(f"UPDATE device_state SET {', '.join(updates)} WHERE device_id = 'esp32-node-01'", params)

def get_rules():
    with get_db_connection() as conn:
        return [dict(r) for r in conn.cursor().execute("SELECT * FROM firewall_rules ORDER BY id ASC").fetchall()]

def clear_events():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM events")
        try: c.execute("DELETE FROM sqlite_sequence WHERE name='events'")
        except sqlite3.OperationalError: pass
