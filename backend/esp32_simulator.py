# Owner: Larenz Quashie (IoT Device)
import time, random, threading
from .database import update_device_state, get_device_state

class ESP32Simulator:
    def __init__(self, telemetry_callback=None):
        self.device_id = "esp32-node-01"
        self.ip_address = "10.0.0.50"
        self.led_state = 0
        self.temperature = 23.8
        self.humidity = 48.5
        self.is_running = False
        self.telemetry_callback = telemetry_callback
        self.lock = threading.Lock()

        saved = get_device_state()
        if saved:
            self.led_state = saved.get("led_state", 0)
            self.temperature = saved.get("temperature", 23.8)
            self.humidity = saved.get("humidity", 48.5)

    def start(self):
        if not self.is_running:
            self.is_running = True
            threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.is_running = False

    def _loop(self):
        while self.is_running:
            time.sleep(4.0)
            with self.lock:
                self.temperature = round(23.0 + random.uniform(0.5, 2.5), 1)
                self.humidity = round(47.0 + random.uniform(1.0, 5.0), 1)
                update_device_state(temperature=self.temperature, humidity=self.humidity, led_state=self.led_state, status="ONLINE")

            if self.telemetry_callback:
                self.telemetry_callback({
                    "source_ip": self.ip_address,
                    "dest_ip": "192.168.1.100",
                    "source_port": 49152 + random.randint(100, 999),
                    "dest_port": 8080,
                    "protocol": "TCP",
                    "data": {"temperature_c": self.temperature, "humidity_pct": self.humidity, "led": self.led_state}
                })

    def execute_command(self, action, params=None):
        with self.lock:
            if action in ("TOGGLE_LED", "SET_LED"):
                self.led_state = (1 if self.led_state == 0 else 0) if action == "TOGGLE_LED" else (1 if params and params.get("state") in (1, True, "1", "on") else 0)
                update_device_state(led_state=self.led_state)
                return {"success": True, "action": action, "led_state": self.led_state, "message": f"LED set to {'ON' if self.led_state == 1 else 'OFF'}"}
            if action == "GET_SENSORS":
                return {"success": True, "temperature": self.temperature, "humidity": self.humidity, "led_state": self.led_state}
            return {"success": False, "error": f"Unknown command action '{action}'"}
