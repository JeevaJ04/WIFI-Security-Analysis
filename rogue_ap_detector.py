#!/usr/bin/env python3
"""Rogue AP detection module."""

import hashlib
import logging
from collections import defaultdict
from datetime import datetime
from typing import List

logger = logging.getLogger(__name__)


class RogueAPDetector:
    def __init__(self) -> None:
        self.trusted_bssids = set()

    def detect(self, networks: List[dict]) -> List[dict]:
        findings: List[dict] = []

        grouped = defaultdict(list)
        for network in networks:
            grouped[network.get("ssid", "")].append(network)

        for ssid, aps in grouped.items():
            if ssid and len(aps) > 1:
                findings.extend(self._detect_evil_twin(aps))

        for network in networks:
            if self._is_suspicious(network):
                findings.append(self._create(network, threat_type="Suspicious Activity", confidence=78))

            if self._check_mac_spoofing(network):
                findings.append(self._create(network, threat_type="MAC Spoofing", confidence=88))

        unique = {}
        for finding in findings:
            unique[(finding.get("bssid"), finding.get("threat_type"))] = finding

        result = list(unique.values())
        logger.info("Rogue AP detection complete: %d findings", len(result))
        return result

    def _detect_evil_twin(self, aps: List[dict]) -> List[dict]:
        out = []
        sorted_aps = sorted(aps, key=lambda x: x.get("signal", 0), reverse=True)
        baseline = sorted_aps[0]

        for ap in sorted_aps[1:]:
            confidence = 55
            if baseline.get("channel") != ap.get("channel"):
                confidence += 20
            if baseline.get("manufacturer") != ap.get("manufacturer"):
                confidence += 15
            if abs(baseline.get("beacon_interval", 100) - ap.get("beacon_interval", 100)) > 20:
                confidence += 10

            if confidence >= 70:
                out.append(
                    self._create(
                        ap,
                        threat_type="Evil Twin",
                        confidence=min(confidence, 99),
                        legitimate_ap=baseline.get("bssid"),
                    )
                )

        return out

    def _check_mac_spoofing(self, network: dict) -> bool:
        bssid = (network.get("bssid") or "").upper()
        suspicious_prefixes = ("00:11:22", "AA:BB:CC", "DE:AD:BE")
        return bssid.startswith(suspicious_prefixes)

    def _is_suspicious(self, network: dict) -> bool:
        ssid = (network.get("ssid") or "").strip()
        signal = int(network.get("signal", 0))
        channel = int(network.get("channel", 0))

        if not ssid:
            return True

        suspicious_names = {"Free WiFi", "Public WiFi", "Starbucks", "ATT", "xfinity"}
        if ssid in suspicious_names:
            return True

        if signal >= 95:
            return True

        return 12 <= channel <= 35

    def _create(self, network: dict, threat_type: str, confidence: int, legitimate_ap: str = None) -> dict:
        rid = hashlib.md5(f"{network.get('bssid','')}-{threat_type}-{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        reason_map = {
            "Evil Twin": "Multiple APs share the same SSID with conflicting radio characteristics.",
            "MAC Spoofing": "MAC prefix pattern resembles spoofing signatures.",
            "Suspicious Activity": "Network properties match suspicious heuristics.",
        }
        return {
            "id": rid,
            "ssid": network.get("ssid", "Unknown"),
            "bssid": network.get("bssid", ""),
            "channel": network.get("channel", 0),
            "signal": network.get("signal", 0),
            "encryption": network.get("encryption", "Unknown"),
            "threat_type": threat_type,
            "confidence": confidence,
            "detected": datetime.now().isoformat(),
            "legitimate_ap": legitimate_ap,
            "reason": reason_map.get(threat_type, "Potential rogue access point detected."),
            "risk_level": "high" if confidence >= 85 else "medium",
        }
