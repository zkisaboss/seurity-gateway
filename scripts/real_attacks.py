#!/usr/bin/env python3
# Owner: Matthew Liao (Security)
import socket, argparse, time, json, urllib.request

def run_telnet_attack(host="127.0.0.1", port=9023):
    try:
        s = socket.create_connection((host, port), timeout=2.0)
        s.sendall(b"USER root\r\nPASS admin123\r\n")
        s.recv(1024)
        s.close()
        print("Telnet: ALLOWED")
    except OSError:
        print("Telnet: BLOCKED")

def run_c2_beacon(host="127.0.0.1", port=9444):
    try:
        s = socket.create_connection((host, port), timeout=2.0)
        s.sendall(b"BEACON: esp32_01 compromised\r\n")
        s.close()
        print("C2 Beacon: BLOCKED")
    except OSError:
        print("C2 Beacon: BLOCKED")

def run_port_scan(host="127.0.0.1", ports=None):
    ports = ports or [9021, 9022, 9023, 9080, 9444, 9088]
    for p in ports:
        status = "OPEN"
        try:
            s = socket.create_connection((host, p), timeout=0.4)
            s.close()
        except OSError:
            status = "FILTERED"
        print(f"Port {p}: {status}")

def run_flood(host="127.0.0.1", port=9080, count=10):
    for _ in range(count):
        try:
            s = socket.create_connection((host, port), timeout=0.3)
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            s.close()
        except OSError:
            pass
        time.sleep(0.01)
    print(f"Rate Flood: Dispatched {count} packets")

def send_command(host="127.0.0.1", port=9080, action="TOGGLE_LED"):
    req = urllib.request.Request(f"http://{host}:{port}/api/command", data=json.dumps({"action": action}).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode())
            print(f"Command: {data.get('status', 'OK')}")
    except Exception as e:
        print(f"Command: FAILED ({e})")

def main():
    p = argparse.ArgumentParser(description="Real Network Attack Harness CLI")
    p.add_argument("--telnet", action="store_true")
    p.add_argument("--c2", action="store_true")
    p.add_argument("--portscan", action="store_true")
    p.add_argument("--flood", action="store_true")
    p.add_argument("--command", action="store_true")
    p.add_argument("--all", action="store_true")
    args = p.parse_args()

    if not (args.telnet or args.c2 or args.portscan or args.flood or args.command or args.all):
        return
    if args.telnet or args.all: run_telnet_attack()
    if args.c2 or args.all: run_c2_beacon()
    if args.portscan or args.all: run_port_scan()
    if args.flood or args.all: run_flood()
    if args.command or args.all: send_command()

if __name__ == "__main__":
    main()
