#!/usr/bin/env python3
"""Core WiFi scanning module with safe fallback simulation mode."""

import logging
import random
import re
import subprocess
import time
from datetime import datetime
from typing import List

logger = logging.getLogger(__name__)


class WiFiSecurityAnalyzer:
    def __init__(self, interface: str = "wlan0") -> None:
        self.interface = interface
        self.monitor_mode = False
        self.scanning = False
        self.networks: List[dict] = []

    def scan_networks(self, duration: int = 20) -> List[dict]:
        self.scanning = True
        self.networks = []

        try:
            result = subprocess.run(
                ["iwlist", self.interface, "scan"],
                capture_output=True,
                text=True,
                timeout=max(duration, 5),
                check=False,
            )
            if result.returncode == 0 and result.stdout:
                self._parse_scan_output(result.stdout)
            else:
                logger.warning("iwlist scan failed, switching to simulation mode: %s", result.stderr.strip())
                self._simulate_scan(duration)
        except FileNotFoundError:
            logger.warning("iwlist not found; using simulation mode")
            self._simulate_scan(duration)
        except Exception as exc:
            logger.warning("Scan failed; using simulation mode: %s", exc)
            self._simulate_scan(duration)

        self.scanning = False
        return self.networks

    def _parse_scan_output(self, output: str) -> None:
        cells = output.split("Cell ")
        parsed = []

        for cell in cells:
            if "Address:" not in cell:
                continue

            bssid_match = re.search(r"Address: ([0-9A-Fa-f:]{17})", cell)
            if not bssid_match:
                continue

            ssid_match = re.search(r'ESSID:"([^"]*)"', cell)
            channel_match = re.search(r"Channel:(\d+)", cell)
            quality_match = re.search(r"Quality=(\d+)/(\d+)", cell)
            beacon_match = re.search(r"Beacon Interval: (\d+)", cell)

            encryption = "Open"
            if "Encryption key:on" in cell:
                if "WPA3" in cell:
                    encryption = "WPA3"
                elif "WPA2" in cell:
                    encryption = "WPA2"
                elif "WPA" in cell:
                    encryption = "WPA"
                elif "WEP" in cell:
                    encryption = "WEP"
                else:
                    encryption = "Unknown"

            signal = 0
            if quality_match:
                q = int(quality_match.group(1))
                max_q = int(quality_match.group(2)) or 100
                signal = int((q / max_q) * 100)

            parsed.append(
                {
                    "ssid": ssid_match.group(1) if ssid_match else "Hidden Network",
                    "bssid": bssid_match.group(1).upper(),
                    "channel": int(channel_match.group(1)) if channel_match else 0,
                    "signal": signal,
                    "encryption": encryption,
                    "security_score": self.calculate_security_score(encryption, signal),
                    "first_seen": datetime.now().isoformat(),
                    "last_seen": datetime.now().isoformat(),
                    "beacon_interval": int(beacon_match.group(1)) if beacon_match else 100,
                    "manufacturer": "Unknown",
                }
            )

        unique = {}
        for net in parsed:
            unique[net["bssid"]] = net

        self.networks = list(unique.values())
        for index, net in enumerate(self.networks, start=1):
            net["id"] = index

    @staticmethod
    def calculate_security_score(encryption: str, signal: int) -> int:
        score = 100
        if encryption == "Open":
            score -= 50
        elif encryption == "WEP":
            score -= 40
        elif encryption == "WPA":
            score -= 20
        elif encryption == "WPA2":
            score -= 10

        if signal < 30:
            score += 10
        elif signal > 80:
            score -= 10

        return max(0, min(100, score))

    def _simulate_scan(self, duration: int) -> None:
        encryptions = ["WPA3", "WPA2", "WPA", "WEP", "Open"]
        vendors = ["Cisco", "TP-Link", "Netgear", "D-Link", "Asus", "Ubiquiti"]
        generated = []

        for _ in range(max(2, duration // 2)):
            if not self.scanning:
                break
            for _ in range(random.randint(1, 3)):
                enc = random.choice(encryptions)
                signal = random.randint(15, 98)
                generated.append(
                    {
                        "ssid": f"Network_{len(generated) + 1}",
                        "bssid": ":".join(f"{random.randint(0, 255):02X}" for _ in range(6)),
                        "channel": random.randint(1, 13),
                        "signal": signal,
                        "encryption": enc,
                        "security_score": self.calculate_security_score(enc, signal),
                        "first_seen": datetime.now().isoformat(),
                        "last_seen": datetime.now().isoformat(),
                        "beacon_interval": random.randint(90, 200),
                        "manufacturer": random.choice(vendors),
                    }
                )
            time.sleep(0.2)

        unique = {}
        for net in generated:
            unique[net["bssid"]] = net

        self.networks = list(unique.values())
        for index, net in enumerate(self.networks, start=1):
            net["id"] = index

    def enable_monitor_mode(self) -> bool:
        return False

    def disable_monitor_mode(self) -> bool:
        return True
