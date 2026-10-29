"""
feature_extractor.py
====================
Per-MAC BUM (Broadcast, Unknown Unicast, Multicast) traffic statistics and
15-feature extraction for the BCAST IDS anomaly detection pipeline.

Features are extracted over a 10-second sliding window per MAC address and
normalized by that MAC's total packet count for the window.  The 15 features
mirror those described in the BCAST IDS paper:

    UCAST, MCAST, BCAST, ARP, GARP, ARP_PROBE, ARP_ANNOUNCE,
    TCP, UDP, ICMP, ICMPv6, IPv6, SSDP, IPF, ARP_noIP, IP_RESTO

Usage
-----
    extractor = FeatureExtractor()
    extractor.update(pkt_info)          # call for every captured packet
    snapshot = extractor.get_snapshot() # call every 10 s
    extractor.reset_counters()          # call after snapshot
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature name ordering (must be consistent across all modules)
# ---------------------------------------------------------------------------
FEATURE_NAMES: List[str] = [
    "UCAST",
    "MCAST",
    "BCAST",
    "ARP",
    "GARP",
    "ARP_PROBE",
    "ARP_ANNOUNCE",
    "TCP",
    "UDP",
    "ICMP",
    "ICMPv6",
    "IPv6",
    "SSDP",
    "IPF",
    "ARP_noIP",
    "IP_RESTO",
]


# ---------------------------------------------------------------------------
# MACTrafficStats
# ---------------------------------------------------------------------------

@dataclass
class MACTrafficStats:
    """Raw per-MAC packet counters for one 10-second window.

    Attributes
    ----------
    mac : str
        The MAC address string this record belongs to.
    ucast : int
        Unknown unicast packets received.
    mcast : int
        Multicast packets received.
    bcast : int
        Broadcast packets received.
    arp : int
        Total ARP packets.
    garp : int
        Gratuitous ARP packets (src_ip == dst_ip in ARP).
    arp_probe : int
        ARP probes (sender IP == 0.0.0.0).
    arp_announce : int
        ARP announcements.
    tcp : int
        TCP packets.
    udp : int
        UDP packets (non-SSDP).
    icmp : int
        ICMP echo request packets.
    icmpv6 : int
        ICMPv6 packets.
    ipv6 : int
        IPv6 packets.
    ssdp : int
        SSDP packets (UDP to 239.255.255.250:1900).
    ipf : int
        Count of distinct destination IPs this MAC has ARPed for that exist
        in the network (i.e., found in ``seen_ips``).
    arp_no_ip : int
        ARP requests to nonexistent IPs (not in ``seen_ips``).
    ip_resto : int
        Other IP protocol packets (not TCP/UDP/ICMP).
    total_packets : int
        Sum of all packet types; used as the normalization denominator.
    """

    mac: str = ""
    ucast: int = 0
    mcast: int = 0
    bcast: int = 0
    arp: int = 0
    garp: int = 0
    arp_probe: int = 0
    arp_announce: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    icmpv6: int = 0
    ipv6: int = 0
    ssdp: int = 0
    ipf: int = 0
    arp_no_ip: int = 0
    ip_resto: int = 0
    total_packets: int = 0

    def reset(self) -> None:
        """Zero out all counters while preserving the MAC identifier."""
        self.ucast = 0
        self.mcast = 0
        self.bcast = 0
        self.arp = 0
        self.garp = 0
        self.arp_probe = 0
        self.arp_announce = 0
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.icmpv6 = 0
        self.ipv6 = 0
        self.ssdp = 0
        self.ipf = 0
        self.arp_no_ip = 0
        self.ip_resto = 0
        self.total_packets = 0

    def to_normalized_feature_vector(self) -> Dict[str, float]:
        """Return a normalized feature dict keyed by feature name.

        Each raw counter is divided by ``total_packets``.  If the total is
        zero (no traffic observed in this window), all features are 0.0.

        Returns
        -------
        dict
            Mapping from feature name (str) to normalized value (float).
        """
        total = self.total_packets
        if total == 0:
            return {name: 0.0 for name in FEATURE_NAMES}

        return {
            "UCAST":        self.ucast       / total,
            "MCAST":        self.mcast       / total,
            "BCAST":        self.bcast       / total,
            "ARP":          self.arp         / total,
            "GARP":         self.garp        / total,
            "ARP_PROBE":    self.arp_probe   / total,
            "ARP_ANNOUNCE": self.arp_announce / total,
            "TCP":          self.tcp         / total,
            "UDP":          self.udp         / total,
            "ICMP":         self.icmp        / total,
            "ICMPv6":       self.icmpv6      / total,
            "IPv6":         self.ipv6        / total,
            "SSDP":         self.ssdp        / total,
            "IPF":          self.ipf         / total,
            "ARP_noIP":     self.arp_no_ip   / total,
            "IP_RESTO":     self.ip_resto    / total,
        }

    def to_feature_list(self) -> List[float]:
        """Return normalized features as an ordered list (FEATURE_NAMES order).

        Returns
        -------
        list of float
            16-element list in the canonical FEATURE_NAMES order.
        """
        fv = self.to_normalized_feature_vector()
        return [fv[name] for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# FeatureExtractor
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """Extracts and manages 16-feature BUM-traffic vectors per MAC address.

    The extractor is designed to be called from a packet-capture loop.
    ``update()`` should be called for every packet; ``get_snapshot()`` +
    ``reset_counters()`` should be called every 10 seconds to harvest a
    window of features.

    Thread Safety
    -------------
    All public methods acquire ``self._lock`` before accessing shared state,
    making the extractor safe for use in multi-threaded capture pipelines.

    Parameters
    ----------
    arp_associations_file : str, optional
        Path to the JSON file used to persist ARP association snapshots.
        Defaults to ``"database/arp_associations.json"``.
    """

    def __init__(
        self,
        arp_associations_file: str = "database/arp_associations.json",
        arp_snapshot_path: Optional[str] = None,
    ) -> None:
        if arp_snapshot_path is not None:
            arp_associations_file = arp_snapshot_path
        self.arp_associations_file: str = arp_associations_file

        # Per-MAC statistics
        self.mac_stats: Dict[str, MACTrafficStats] = {}

        # Association maps
        self.mac_ip_map: Dict[str, Set[str]] = {}   # MAC -> IPs seen
        self.ip_mac_map: Dict[str, Set[str]] = {}   # IP  -> MACs seen
        self.seen_ips: Set[str] = set()             # All IPs ever seen

        self.last_snapshot_time: float = time.monotonic()

        self._lock = threading.Lock()
        logger.info("FeatureExtractor initialised (window file: %s)", arp_associations_file)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_mac(self, mac: str) -> MACTrafficStats:
        """Return the ``MACTrafficStats`` for *mac*, creating it if needed.

        .. note:: Must be called with ``self._lock`` held.
        """
        if mac not in self.mac_stats:
            self.mac_stats[mac] = MACTrafficStats(mac=mac)
            logger.debug("New MAC registered: %s", mac)
        return self.mac_stats[mac]

    def _record_ip_association(self, mac: str, ip: str) -> None:
        """Update bidirectional MAC↔IP maps and ``seen_ips``.

        .. note:: Must be called with ``self._lock`` held.
        """
        if not mac or not ip or ip in ("0.0.0.0", "::", ""):
            return
        self.seen_ips.add(ip)
        self.mac_ip_map.setdefault(mac, set()).add(ip)
        self.ip_mac_map.setdefault(ip, set()).add(mac)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(self, pkt_info: dict) -> None:
        """Update per-MAC counters from a parsed packet descriptor.

        Parameters
        ----------
        pkt_info : dict
            Expected keys:

            * ``mac_src`` (str) – source MAC address.
            * ``mac_dst`` (str) – destination MAC address.
            * ``pkt_type`` (str) – one of ``'BCAST'``, ``'MCAST'``,
              ``'UCAST'``, ``'ARP'``, ``'GARP'``, ``'ARP_PROBE'``,
              ``'ARP_ANNOUNCE'``, ``'TCP'``, ``'UDP'``, ``'ICMP'``,
              ``'ICMPv6'``, ``'IPv6'``, ``'SSDP'``, ``'IP_RESTO'``.
            * ``ip_src`` (str, optional) – source IP address.
            * ``ip_dst`` (str, optional) – destination IP address.
            * ``is_arp_to_existing_ip`` (bool, optional) – True if this is
              an ARP request whose target IP exists in ``seen_ips``.
        """
        mac_src: str = pkt_info.get("mac_src", "")
        ip_src: str  = pkt_info.get("ip_src", "")
        ip_dst: str  = pkt_info.get("ip_dst", "")
        pkt_type: str = pkt_info.get("pkt_type", "")
        is_arp_to_existing: bool = bool(pkt_info.get("is_arp_to_existing_ip", False))

        if not mac_src:
            return

        with self._lock:
            stats = self._ensure_mac(mac_src)
            stats.total_packets += 1

            # Record IP associations from source
            if ip_src:
                self._record_ip_association(mac_src, ip_src)

            # Increment the appropriate counter
            pkt_type_upper = pkt_type.upper()

            if pkt_type_upper == "UCAST":
                stats.ucast += 1
            elif pkt_type_upper == "MCAST":
                stats.mcast += 1
            elif pkt_type_upper == "BCAST":
                stats.bcast += 1
            elif pkt_type_upper == "ARP":
                stats.arp += 1
                if ip_dst:
                    self.seen_ips.add(ip_dst)
                # IPF / ARP_noIP classification
                if is_arp_to_existing:
                    stats.ipf += 1
                else:
                    stats.arp_no_ip += 1
            elif pkt_type_upper == "GARP":
                stats.arp += 1
                stats.garp += 1
            elif pkt_type_upper == "ARP_PROBE":
                stats.arp += 1
                stats.arp_probe += 1
            elif pkt_type_upper == "ARP_ANNOUNCE":
                stats.arp += 1
                stats.arp_announce += 1
            elif pkt_type_upper == "TCP":
                stats.tcp += 1
            elif pkt_type_upper == "UDP":
                stats.udp += 1
            elif pkt_type_upper == "ICMP":
                stats.icmp += 1
            elif pkt_type_upper == "ICMPV6":
                stats.icmpv6 += 1
            elif pkt_type_upper == "IPV6":
                stats.ipv6 += 1
            elif pkt_type_upper == "SSDP":
                stats.ssdp += 1
            elif pkt_type_upper == "IP_RESTO":
                stats.ip_resto += 1
            else:
                logger.debug("Unknown pkt_type '%s' from MAC %s – ignored", pkt_type, mac_src)

    def get_snapshot(self) -> Dict[str, dict]:
        """Return normalized feature vectors for all active MACs and persist a JSON snapshot.

        Only MACs that have sent at least one packet in the current window
        are included.

        Returns
        -------
        dict
            Mapping ``{mac_str: feature_vector_dict}`` where each
            ``feature_vector_dict`` is the output of
            ``MACTrafficStats.to_normalized_feature_vector()``.
        """
        with self._lock:
            snapshot: Dict[str, dict] = {}
            for mac, stats in self.mac_stats.items():
                if stats.total_packets > 0:
                    snapshot[mac] = stats.to_normalized_feature_vector()
            self.last_snapshot_time = time.monotonic()

        self.save_arp_snapshot()
        logger.debug("Snapshot taken: %d active MACs", len(snapshot))
        return snapshot

    def reset_counters(self) -> None:
        """Zero out all per-MAC packet counters.

        Should be called after ``get_snapshot()`` to start a fresh 10-second
        window.  MAC entries, IP association maps, and ``seen_ips`` are
        **preserved** across resets.
        """
        with self._lock:
            for stats in self.mac_stats.values():
                stats.reset()
        logger.debug("Counters reset for %d MACs", len(self.mac_stats))

    def check_spoofing(self) -> List[dict]:
        """Detect potential MAC or IP spoofing based on association anomalies.

        Spoofing heuristics:

        * **MAC_SPOOF** – A single MAC is associated with more than one IP
          address (MAC address re-use or IP rotation attack).
        * **IP_SPOOF** – A single IP is claimed by more than one MAC address
          (ARP cache poisoning / spoofing).

        Returns
        -------
        list of dict
            Each alert dict has the following keys:

            * ``type`` – ``'MAC_SPOOF'`` or ``'IP_SPOOF'``.
            * ``mac`` – the offending MAC (or ``None`` for IP_SPOOF).
            * ``ips`` – list of associated IPs (or MACs for IP_SPOOF).
            * ``alert`` – human-readable description string.
        """
        alerts: List[dict] = []

        with self._lock:
            # Check MAC → multiple IPs
            for mac, ips in self.mac_ip_map.items():
                if len(ips) > 1:
                    ip_list = sorted(ips)
                    alerts.append({
                        "type":  "MAC_SPOOF",
                        "mac":   mac,
                        "ips":   ip_list,
                        "alert": (
                            f"MAC {mac} is associated with multiple IPs: "
                            f"{', '.join(ip_list)}"
                        ),
                    })

            # Check IP → multiple MACs
            for ip, macs in self.ip_mac_map.items():
                if len(macs) > 1:
                    mac_list = sorted(macs)
                    alerts.append({
                        "type":  "IP_SPOOF",
                        "mac":   None,
                        "ips":   mac_list,
                        "alert": (
                            f"IP {ip} is claimed by multiple MACs: "
                            f"{', '.join(mac_list)}"
                        ),
                    })

        if alerts:
            logger.warning("Spoofing check found %d alert(s)", len(alerts))

        return alerts

    def save_arp_snapshot(self) -> None:
        """Persist current ARP association state to JSON.

        Writes a JSON file to ``self.arp_associations_file`` containing:

        * ``mac_ip_map`` – MAC → list of IPs.
        * ``ip_mac_map`` – IP  → list of MACs.
        * ``seen_ips_count`` – total distinct IPs observed.
        * ``timestamp`` – ISO-8601 UTC timestamp.
        """
        try:
            os.makedirs(os.path.dirname(self.arp_associations_file) or ".", exist_ok=True)

            with self._lock:
                payload = {
                    "mac_ip_map":     {m: sorted(ips) for m, ips in self.mac_ip_map.items()},
                    "ip_mac_map":     {ip: sorted(macs) for ip, macs in self.ip_mac_map.items()},
                    "seen_ips_count": len(self.seen_ips),
                    "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }

            with open(self.arp_associations_file, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)

            logger.debug("ARP snapshot saved to %s", self.arp_associations_file)

        except OSError as exc:
            logger.error("Failed to save ARP snapshot: %s", exc)

    def get_feature_matrix(self) -> Tuple[List[List[float]], List[str]]:
        """Return a feature matrix and corresponding MAC labels for ML training.

        Only MACs with at least one packet in the current window are included.

        Returns
        -------
        tuple
            * ``matrix`` – list of feature vectors (each a 16-element list of
              floats in ``FEATURE_NAMES`` order).
            * ``mac_labels`` – list of MAC strings aligned with *matrix* rows.
        """
        matrix: List[List[float]] = []
        mac_labels: List[str] = []

        with self._lock:
            for mac, stats in self.mac_stats.items():
                if stats.total_packets > 0:
                    matrix.append(stats.to_feature_list())
                    mac_labels.append(mac)

        logger.debug(
            "Feature matrix built: %d samples × %d features",
            len(matrix),
            len(FEATURE_NAMES),
        )
        return matrix, mac_labels
