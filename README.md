# IoT Security Gateway

A self-contained prototype of a Raspberry Pi Security Gateway protecting an ESP32 IoT node with default-deny firewall policies, sliding-window threat detection, and a live web dashboard.

## Team & Component Ownership

- **Larenz Quashie** — **IoT Device**: ESP32 microcontroller firmware simulation (`backend/esp32_simulator.py`), DHT22 digital temperature & humidity telemetry, onboard GPIO2 LED actuation, and device state schema.
- **Zach Kosove** — **Gateway / Networking**: Network routing, CIDR subnet isolation, default-deny packet filtering engine (`backend/firewall.py`), and socket harness (`backend/network_harness.py`).
- **Matthew Liao** — **Security**: Sliding-window heuristic threat detection (`backend/detector.py`), security signature definitions (SIG-001 through SIG-004), and attack scripts (`scripts/real_attacks.py`, `scripts/simulate_attacks.py`).
- **Brandon Lyubarsky** — **Application / Dashboard**: Unified SQLite event logging (`backend/database.py`), HTTP REST & SSE streaming server (`backend/server.py`), web dashboard frontend (`frontend/`), and verification test suite (`scripts/test_scenarios.py`).

## Dependencies

- Python 3.8+
- Zero external packages (uses pure Python standard library only).

## Quick Start

### 1. Run Web Dashboard
```bash
python3 run_demo.py
```
Opens the web dashboard at `http://localhost:8080`.

### 2. Run Verification Test Suite
```bash
python3 scripts/test_scenarios.py
```
Executes and validates all 6 test scenarios (telemetry, API command, unauthorized Telnet, rogue C2 outbound beacon, port scan, and reboot persistence).

### 3. Run Attack Generators
```bash
# Simulated attack dispatch:
python3 scripts/simulate_attacks.py

# Raw TCP socket attacks (requires running gateway):
python3 scripts/real_attacks.py --all
```
