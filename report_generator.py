#!/usr/bin/env python3
"""Security report generator with JSON/CSV/PDF outputs."""

import csv
import json
import logging
import os
import tempfile
from datetime import datetime
from typing import List

logger = logging.getLogger(__name__)


class ReportGenerator:
    def __init__(self, output_dir: str = "reports") -> None:
        self.report_dir = output_dir
        os.makedirs(self.report_dir, exist_ok=True)

    def generate(self, networks: List[dict], vulnerabilities: List[dict], rogue_aps: List[dict], report_type: str = "pdf") -> dict:
        report_type = (report_type or "pdf").lower()
        if report_type == "csv":
            return self._generate_csv(networks, vulnerabilities, rogue_aps)
        if report_type == "json":
            return self._generate_json(networks, vulnerabilities, rogue_aps)
        return self._generate_pdf(networks, vulnerabilities, rogue_aps)

    def _generate_pdf(self, networks: List[dict], vulnerabilities: List[dict], rogue_aps: List[dict]) -> dict:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table
        except Exception as exc:
            logger.warning("reportlab unavailable (%s); falling back to JSON report", exc)
            return self._generate_json(networks, vulnerabilities, rogue_aps)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{ts}.pdf"
        path = os.path.join(self.report_dir, filename)

        doc = SimpleDocTemplate(path, pagesize=A4)
        styles = getSampleStyleSheet()
        content = [
            Paragraph("WiFi Security Analysis Report", styles["Title"]),
            Spacer(1, 12),
            Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]),
            Spacer(1, 16),
        ]

        stats = self._stats(networks, vulnerabilities, rogue_aps)
        content.append(Paragraph("Summary", styles["Heading2"]))
        content.append(Spacer(1, 8))
        content.append(
            Table(
                [["Metric", "Value"]]
                + [["Total Networks", stats["total_networks"]], ["Total Vulnerabilities", stats["total_vulnerabilities"]], ["Total Rogue APs", stats["total_rogue_aps"]], ["Average Security Score", f"{stats['average_security_score']:.2f}"]]
            )
        )
        content.append(Spacer(1, 16))

        channel_graph = self._generate_channel_graph(networks)
        if channel_graph:
            content.append(Paragraph("Channel Distribution", styles["Heading2"]))
            content.append(Spacer(1, 8))
            content.append(Image(channel_graph, width=480, height=260))
            content.append(Spacer(1, 16))

        if vulnerabilities:
            content.append(Paragraph("Top Vulnerabilities", styles["Heading2"]))
            content.append(Spacer(1, 8))
            rows = [["SSID", "Type", "Severity", "CVE"]]
            for item in vulnerabilities[:12]:
                rows.append([
                    item.get("network_ssid", "Unknown"),
                    item.get("type", "Unknown"),
                    str(item.get("severity", "")).upper(),
                    item.get("cve") or "N/A",
                ])
            content.append(Table(rows))
            content.append(Spacer(1, 16))

        if rogue_aps:
            content.append(Paragraph("Rogue Access Points", styles["Heading2"]))
            content.append(Spacer(1, 8))
            rows = [["SSID", "BSSID", "Threat", "Confidence"]]
            for item in rogue_aps[:12]:
                rows.append([
                    item.get("ssid", "Unknown"),
                    item.get("bssid", "Unknown"),
                    item.get("threat_type", "Unknown"),
                    f"{item.get('confidence', 0)}%",
                ])
            content.append(Table(rows))

        doc.build(content)
        if channel_graph and os.path.exists(channel_graph):
            try:
                os.remove(channel_graph)
            except OSError:
                logger.warning("Failed to remove temporary channel graph: %s", channel_graph)
        return self._result("pdf", filename, path)

    def _generate_csv(self, networks: List[dict], vulnerabilities: List[dict], rogue_aps: List[dict]) -> dict:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{ts}.csv"
        path = os.path.join(self.report_dir, filename)

        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["WiFi Security Analysis Report"])
            writer.writerow([f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
            writer.writerow([])

            writer.writerow(["Networks"])
            writer.writerow(["SSID", "BSSID", "Channel", "Signal", "Encryption", "Security Score"])
            for net in networks:
                writer.writerow([
                    net.get("ssid", ""),
                    net.get("bssid", ""),
                    net.get("channel", ""),
                    f"{net.get('signal', 0)}%",
                    net.get("encryption", ""),
                    net.get("security_score", ""),
                ])

            writer.writerow([])
            writer.writerow(["Vulnerabilities"])
            writer.writerow(["SSID", "Type", "Severity", "Description", "CVE"])
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get("network_ssid", ""),
                    vuln.get("type", ""),
                    vuln.get("severity", ""),
                    vuln.get("description", ""),
                    vuln.get("cve") or "N/A",
                ])

            writer.writerow([])
            writer.writerow(["Rogue APs"])
            writer.writerow(["SSID", "BSSID", "Threat Type", "Confidence", "Risk Level"])
            for rogue in rogue_aps:
                writer.writerow([
                    rogue.get("ssid", ""),
                    rogue.get("bssid", ""),
                    rogue.get("threat_type", ""),
                    f"{rogue.get('confidence', 0)}%",
                    rogue.get("risk_level", ""),
                ])

        return self._result("csv", filename, path)

    def _generate_json(self, networks: List[dict], vulnerabilities: List[dict], rogue_aps: List[dict]) -> dict:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{ts}.json"
        path = os.path.join(self.report_dir, filename)

        payload = {
            "generated": datetime.now().isoformat(),
            "summary": self._stats(networks, vulnerabilities, rogue_aps),
            "networks": networks,
            "vulnerabilities": vulnerabilities,
            "rogue_aps": rogue_aps,
            "recommendations": self._recommendations(networks, vulnerabilities, rogue_aps),
        }

        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

        return self._result("json", filename, path)

    def _stats(self, networks: List[dict], vulnerabilities: List[dict], rogue_aps: List[dict]) -> dict:
        avg = sum(n.get("security_score", 0) for n in networks) / len(networks) if networks else 0.0
        return {
            "total_networks": len(networks),
            "total_vulnerabilities": len(vulnerabilities),
            "total_rogue_aps": len(rogue_aps),
            "secure_networks": sum(1 for n in networks if n.get("security_score", 0) >= 80),
            "average_security_score": avg,
        }

    def _recommendations(self, networks: List[dict], vulnerabilities: List[dict], rogue_aps: List[dict]) -> List[str]:
        recs = set()
        for network in networks:
            enc = network.get("encryption", "")
            if enc == "Open":
                recs.add("Enable WPA3/WPA2 on open networks.")
            elif enc == "WEP":
                recs.add("Migrate WEP networks to WPA3 immediately.")
            elif enc == "WPA":
                recs.add("Upgrade WPA to WPA2/WPA3.")

        for vuln in vulnerabilities:
            if vuln.get("remediation"):
                recs.add(vuln["remediation"])

        if rogue_aps:
            recs.add("Investigate and isolate detected rogue APs.")

        recs.add("Update router firmware regularly.")
        recs.add("Disable WPS where not required.")
        return sorted(recs)

    def _result(self, report_type: str, filename: str, path: str) -> dict:
        return {
            "id": datetime.now().strftime("%Y%m%d%H%M%S%f")[-10:],
            "type": report_type,
            "filename": filename,
            "path": path,
            "generated": datetime.now().isoformat(),
            "size": os.path.getsize(path),
        }

    def _generate_channel_graph(self, networks: List[dict]) -> str | None:
        if not networks:
            return None

        channel_counts = {}
        for network in networks:
            channel = network.get("channel")
            if channel is None:
                continue
            channel_counts[channel] = channel_counts.get(channel, 0) + 1

        if not channel_counts:
            return None

        try:
            import matplotlib

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except Exception as exc:
            logger.warning("matplotlib unavailable (%s); skipping channel graph", exc)
            return None

        channels = sorted(channel_counts.keys())
        counts = [channel_counts[ch] for ch in channels]

        temp_file = tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".png",
            delete=False,
            dir=self.report_dir,
        )
        temp_path = temp_file.name
        temp_file.close()

        plt.figure(figsize=(8, 4))
        plt.bar(channels, counts, color="#2E86AB")
        plt.title("WiFi Networks by Channel")
        plt.xlabel("Channel")
        plt.ylabel("Network Count")
        plt.xticks(channels)
        plt.tight_layout()
        plt.savefig(temp_path, dpi=150)
        plt.close()

        return temp_path
