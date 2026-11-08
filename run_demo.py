#!/usr/bin/env python3
# Owner: Brandon Lyubarsky (Application / Dashboard), Support: Zach Kosove
import os, sys, argparse, webbrowser, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from backend.server import start_server, GatewayRequestHandler

def main():
    p = argparse.ArgumentParser(description="IoT Security Gateway Demo Launcher")
    p.add_argument("--port", "-p", type=int, default=int(os.environ.get("PORT", 8080)))
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--no-browser", action="store_true")
    args = p.parse_args()

    server, port = start_server(host=args.host, port=args.port)
    print(f"Gateway running on http://localhost:{port}")

    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{port}")).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        if getattr(GatewayRequestHandler, "gateway_instance", None):
            GatewayRequestHandler.gateway_instance.esp32.stop()

if __name__ == "__main__":
    main()
