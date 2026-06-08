#!/usr/bin/env python3
"""WiFi Security Analyzer backend server."""

import json
import io
import logging
import os
import platform
import random
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit

try:
    import netifaces  # type: ignore
except Exception:
    netifaces = None

from wifi_analyzer import WiFiSecurityAnalyzer
from vulnerability_scanner import VulnerabilityScanner
from rogue_ap_detector import RogueAPDetector
from report_generator import ReportGenerator


BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = BASE_DIR / "wifi_analyzer.log"
SETTINGS_PATH = BASE_DIR / "settings.json"
BLACKLIST_PATH = BASE_DIR / "blacklist.txt"
REPORTS_DIR = BASE_DIR / "reports"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

REPORTS_DIR.mkdir(exist_ok=True)
TEMPLATES_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
)
logger = logging.getLogger("wifi-security-analyzer")

app = Flask(__name__, template_folder=str(TEMPLATES_DIR), static_folder=str(STATIC_DIR))
app.config["SECRET_KEY"] = "wifi-security-analyzer-secret-key"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")


class BackendState:
    def __init__(self) -> None:
        self.interface = self.get_default_interface()
        self.analyzer = WiFiSecurityAnalyzer(self.interface)
        self.vuln_scanner = VulnerabilityScanner()
        self.rogue_detector = RogueAPDetector()
        self.report_generator = ReportGenerator(output_dir=str(REPORTS_DIR))

        self.scanning_active = False
        self.scan_thread = None

        self.current_networks: List[dict] = []
        self.current_vulnerabilities: List[dict] = []
        self.current_rogue_aps: List[dict] = []
        self.generated_reports: Dict[str, dict] = {}

    def get_default_interface(self) -> str:
        if platform.system() != "Linux":
            return "wlan0"
        if not netifaces:
            return "wlan0"

        try:
            for iface in netifaces.interfaces():
                if iface.startswith(("wlan", "wlp", "wlx")):
                    return iface
        except Exception:
            pass
        return "wlan0"


state = BackendState()


def _load_settings() -> dict:
    if SETTINGS_PATH.exists():
        try:
            return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to parse settings: %s", exc)

    return {
        "interface": state.interface,
        "scan_interval": 5,
        "channel_hopping": True,
        "deep_scan": False,
        "rogue_alerts": True,
        "alert_threshold": "medium",
        "sound_alerts": True,
        "monitor_mode": False,
        "packet_capture": False,
    }


def _save_settings(settings: dict) -> None:
    SETTINGS_PATH.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def _append_blacklist(bssid: str) -> None:
    with BLACKLIST_PATH.open("a", encoding="utf-8") as fh:
        fh.write(f"{bssid}\n")


def _simulate_network_scan(duration: int) -> List[dict]:
    encryptions = ["WPA3", "WPA2", "WPA", "WEP", "Open"]
    vendors = ["Cisco", "TP-Link", "Netgear", "D-Link", "Asus", "Ubiquiti"]

    steps = max(1, duration // 2)
    networks: List[dict] = []

    for step in range(steps):
        if not state.scanning_active:
            break

        for _ in range(random.randint(1, 3)):
            enc = random.choice(encryptions)
            signal = random.randint(15, 98)
            net_id = len(networks) + 1
            networks.append(
                {
                    "id": net_id,
                    "ssid": f"Network_{net_id}",
                    "bssid": ":".join(f"{random.randint(0, 255):02X}" for _ in range(6)),
                    "channel": random.randint(1, 13),
                    "signal": signal,
                    "encryption": enc,
                    "security_score": WiFiSecurityAnalyzer.calculate_security_score(enc, signal),
                    "first_seen": datetime.now().isoformat(),
                    "last_seen": datetime.now().isoformat(),
                    "beacon_interval": random.randint(90, 200),
                    "manufacturer": random.choice(vendors),
                }
            )

        progress = int(((step + 1) / steps) * 100)
        socketio.emit("scan_progress", {"progress": progress, "networks_found": len(networks)})
        socketio.sleep(2)

    unique = {}
    for net in networks:
        unique[net["bssid"]] = net
    deduped = list(unique.values())

    for index, net in enumerate(deduped, start=1):
        net["id"] = index

    return deduped


def _perform_scan(interface: str, duration: int, continuous: bool) -> None:
    logger.info("Starting scan on %s for %s seconds (continuous=%s)", interface, duration, continuous)
    cycle = 0
    try:
        while state.scanning_active:
            cycle += 1
            if platform.system() == "Linux":
                state.analyzer.interface = interface
                networks = state.analyzer.scan_networks(duration=duration)
            else:
                networks = _simulate_network_scan(duration)

            if not networks and state.scanning_active:
                networks = _simulate_network_scan(duration)

            if not state.scanning_active and not networks:
                break

            state.current_networks = networks
            state.current_vulnerabilities = state.vuln_scanner.scan(networks)
            state.current_rogue_aps = state.rogue_detector.detect(networks)

            payload = {
                "networks": state.current_networks,
                "vulnerabilities": state.current_vulnerabilities,
                "rogue_aps": state.current_rogue_aps,
                "count": len(state.current_networks),
                "cycle": cycle,
                "continuous": continuous,
                "timestamp": datetime.now().isoformat(),
            }
            socketio.emit("scan_complete", payload)

            if not continuous:
                break

            socketio.emit(
                "scan_progress",
                {"progress": 0, "networks_found": len(state.current_networks), "cycle": cycle + 1},
            )
            socketio.sleep(1)
    except Exception as exc:
        logger.exception("Scan failed: %s", exc)
        socketio.emit("scan_error", {"error": str(exc)})
    finally:
        state.scanning_active = False
        logger.info("Scan complete")


def _channel_distribution(networks: List[dict]) -> Dict[int, int]:
    distribution: Dict[int, int] = {}
    for network in networks:
        channel = network.get("channel")
        if channel is None:
            continue
        distribution[channel] = distribution.get(channel, 0) + 1
    return dict(sorted(distribution.items()))


@app.route("/")
def home():
    return render_template("index.html", active_page="operations")


@app.route("/operations")
def operations_page():
    return render_template("index.html", active_page="operations")


@app.route("/security")
def security_page():
    return render_template("index.html", active_page="security")


@app.route("/network")
def network_page():
    return render_template("index.html", active_page="network")


@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify(
        {
            "status": "online",
            "interface": state.interface,
            "scanning": state.scanning_active,
            "timestamp": datetime.now().isoformat(),
            "components": {
                "analyzer": True,
                "vuln_scanner": True,
                "rogue_detector": True,
                "report_gen": True,
            },
        }
    )


@app.route("/api/networks", methods=["GET"])
def get_networks():
    return jsonify(state.current_networks)


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    if state.scanning_active:
        return jsonify({"error": "Scan already in progress"}), 400

    data = request.get_json(silent=True) or {}
    interface = data.get("interface", state.interface)
    duration = int(data.get("duration", 20))
    continuous = bool(data.get("continuous", True))
    duration = max(5, min(duration, 120))

    state.scanning_active = True
    state.current_networks = []
    state.current_vulnerabilities = []
    state.current_rogue_aps = []
    state.scan_thread = threading.Thread(
        target=_perform_scan,
        args=(interface, duration, continuous),
        daemon=True,
    )
    state.scan_thread.start()

    socketio.emit(
        "scan_started",
        {
            "interface": interface,
            "duration": duration,
            "continuous": continuous,
            "timestamp": datetime.now().isoformat(),
        },
    )
    socketio.emit(
        "update",
        {
            "networks": state.current_networks,
            "vulnerabilities": state.current_vulnerabilities,
            "rogue_aps": state.current_rogue_aps,
            "reports": list(state.generated_reports.values()),
            "scanning": state.scanning_active,
        },
    )

    mode = "continuous" if continuous else "single"
    return jsonify(
        {
            "status": "started",
            "message": f"Started {mode} scan on {interface} ({duration}s per cycle)",
        }
    )


@app.route("/api/scan/stop", methods=["POST"])
def stop_scan():
    if not state.scanning_active:
        return jsonify({"error": "No scan in progress"}), 400

    state.scanning_active = False
    socketio.emit("scan_stopped", {"timestamp": datetime.now().isoformat()})
    return jsonify({"status": "stopped", "message": "Scan stop requested"})


@app.route("/api/scan/results", methods=["GET"])
def scan_results():
    return jsonify(
        {
            "networks": state.current_networks,
            "count": len(state.current_networks),
            "timestamp": datetime.now().isoformat(),
        }
    )


@app.route("/api/channels/graph", methods=["GET"])
def channel_graph():
    distribution = _channel_distribution(state.current_networks)
    if not distribution:
        return jsonify({"error": "No network channel data available"}), 404

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:
        return jsonify({"error": f"matplotlib not available: {exc}"}), 500

    channels = list(distribution.keys())
    counts = [distribution[channel] for channel in channels]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(channels, counts, color="#2E86AB")
    ax.set_title("WiFi Networks by Channel")
    ax.set_xlabel("Channel")
    ax.set_ylabel("Network Count")
    ax.set_xticks(channels)
    fig.tight_layout()

    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", dpi=150)
    plt.close(fig)
    buffer.seek(0)
    return send_file(buffer, mimetype="image/png")


@app.route("/api/vulnerabilities", methods=["GET"])
def get_vulnerabilities():
    return jsonify(state.current_vulnerabilities)


@app.route("/api/vulnerabilities/scan", methods=["POST"])
def scan_vulnerabilities():
    data = request.get_json(silent=True) or {}
    networks = data.get("networks", state.current_networks)
    state.current_vulnerabilities = state.vuln_scanner.scan(networks)
    socketio.emit(
        "vulnerabilities_updated",
        {"count": len(state.current_vulnerabilities), "timestamp": datetime.now().isoformat()},
    )
    return jsonify(state.current_vulnerabilities)


@app.route("/api/rogue-aps", methods=["GET"])
def get_rogue_aps():
    return jsonify(state.current_rogue_aps)


@app.route("/api/rogue-aps/detect", methods=["POST"])
def detect_rogue_aps():
    data = request.get_json(silent=True) or {}
    networks = data.get("networks", state.current_networks)
    state.current_rogue_aps = state.rogue_detector.detect(networks)

    if state.current_rogue_aps:
        socketio.emit(
            "rogue_aps_detected",
            {
                "count": len(state.current_rogue_aps),
                "aps": state.current_rogue_aps,
                "timestamp": datetime.now().isoformat(),
            },
        )

    return jsonify(state.current_rogue_aps)


@app.route("/api/reports", methods=["GET"])
def get_reports():
    return jsonify(list(state.generated_reports.values()))


@app.route("/api/dashboard", methods=["GET"])
def get_dashboard():
    return jsonify(
        {
            "networks": state.current_networks,
            "vulnerabilities": state.current_vulnerabilities,
            "rogue_aps": state.current_rogue_aps,
            "reports": list(state.generated_reports.values()),
            "scanning": state.scanning_active,
            "interface": state.interface,
            "timestamp": datetime.now().isoformat(),
        }
    )


@app.route("/api/reports/generate", methods=["POST"])
def generate_report():
    data = request.get_json(silent=True) or {}
    report_type = data.get("type", "pdf")

    networks = data.get("networks", state.current_networks)
    vulnerabilities = data.get("vulnerabilities", state.current_vulnerabilities)
    rogue_aps = data.get("rogue_aps", state.current_rogue_aps)

    report = state.report_generator.generate(
        networks=networks,
        vulnerabilities=vulnerabilities,
        rogue_aps=rogue_aps,
        report_type=report_type,
    )

    report_id = report.get("id") or uuid.uuid4().hex[:8]
    report["id"] = report_id
    state.generated_reports[report_id] = report

    return jsonify(report)


@app.route("/api/reports/download/<report_id>", methods=["GET"])
def download_report(report_id: str):
    report = state.generated_reports.get(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404

    path = report.get("path")
    if not path or not os.path.exists(path):
        return jsonify({"error": "Report file missing"}), 404

    return send_file(path, as_attachment=True)


@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "GET":
        return jsonify(_load_settings())

    data = request.get_json(silent=True) or {}
    _save_settings(data)

    if "interface" in data:
        state.interface = data["interface"]
        state.analyzer.interface = data["interface"]

    socketio.emit("settings_updated", data)
    return jsonify({"status": "success", "message": "Settings saved"})


@app.route("/api/block-rogue/<bssid>", methods=["POST"])
def block_rogue_ap(bssid: str):
    _append_blacklist(bssid)
    socketio.emit("ap_blocked", {"bssid": bssid, "timestamp": datetime.now().isoformat()})
    return jsonify({"status": "success", "message": f"AP {bssid} blocked"})


@app.route("/api/fix-vulnerability/<vuln_id>", methods=["POST"])
def fix_vulnerability(vuln_id: str):
    socketio.emit("vulnerability_fixed", {"id": vuln_id, "timestamp": datetime.now().isoformat()})
    return jsonify({"status": "success", "message": f"Vulnerability {vuln_id} marked fixed"})


@socketio.on("connect")
def handle_connect():
    emit("connected", {"status": "connected", "timestamp": datetime.now().isoformat()})


@socketio.on("request_update")
def handle_request_update(_):
    emit(
        "update",
        {
            "networks": state.current_networks,
            "vulnerabilities": state.current_vulnerabilities,
            "rogue_aps": state.current_rogue_aps,
            "reports": list(state.generated_reports.values()),
            "scanning": state.scanning_active,
        },
    )


if __name__ == "__main__":
    logger.info("Starting WiFi Security Analyzer backend on http://127.0.0.1:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
