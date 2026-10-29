"""
NetSentinel - BUM Packet Capture Layer
=======================================
Live sniffer for Broadcast, Unknown-unicast, and Multicast (BUM) traffic.
This is the core sensor of NetSentinel's ML-based anomaly pipeline.

Architecture
------------
  AsyncSniffer / sniff thread
         │
         ▼
   queue.Queue  (lock-free producer→consumer handoff)
         │
         ▼
  Consumer Thread  ──► feature_extractor.update(pkt_info)
         │
   Timer Thread   ──► _process_window()  every WINDOW_SECONDS
                            │
                            ├─► feature_extractor.get_snapshot()
                            ├─► feature_extractor.check_spoofing()
                            ├─► ml_engine.predict() / add_training_sample()
                            ├─► anomaly_callback()
                            ├─► evidence_collector.save_anomaly_pcap()
                            └─► feature_extractor.reset_counters()
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional scapy import
# ---------------------------------------------------------------------------
try:
    import scapy.all as scapy  # type: ignore

    SCAPY_AVAILABLE = True
    _scapy_version = getattr(scapy, "__version__", "unknown")
    logger.debug("scapy loaded successfully (version %s)", _scapy_version)
except ImportError:  # pragma: no cover
    SCAPY_AVAILABLE = False
    logger.warning(
        "scapy is not installed – packet capture is disabled. "
        "Install with:  pip install scapy"
    )

# ---------------------------------------------------------------------------
# Lazy module-level imports (avoids circular import at load time)
# ---------------------------------------------------------------------------
try:
    from threat_engine.feature_extractor import FeatureExtractor  # noqa: F401
    from threat_engine.ml_engine import ml_engine  # noqa: F401
except Exception as _import_err:  # pragma: no cover
    logger.debug("Could not import feature_extractor / ml_engine at module load: %s", _import_err)
    FeatureExtractor = None  # type: ignore
    ml_engine = None  # type: ignore


# ---------------------------------------------------------------------------
# BUMPacketCapture
# ---------------------------------------------------------------------------

class BUMPacketCapture:
    """
    Captures BUM (Broadcast, Unknown Unicast, Multicast) traffic from a
    network interface, classifies each packet, feeds parsed metadata to a
    ``FeatureExtractor``, and runs periodic ML-based anomaly detection.

    Parameters
    ----------
    interface : str
        Network interface name (e.g. ``"eth0"``, ``"wlan0"``).
    feature_extractor : FeatureExtractor
        Per-MAC feature accumulator instance.
    ml_engine : object
        Object exposing ``is_trained``, ``predict(vector)``,
        ``add_training_sample(vector)``, ``retrain_if_needed()``.
    anomaly_callback : callable, optional
        Called as ``anomaly_callback(mac, feature_vector, prediction_result)``
        when an anomaly is detected.
    spoofing_callback : callable, optional
        Called with spoofing alert dicts from ``feature_extractor.check_spoofing()``.
    evidence_collector : object, optional
        Object exposing ``add_packet(pkt)`` and
        ``save_anomaly_pcap(mac, score, feature_vector)``.
    """

    WINDOW_SECONDS: int = 10          # Feature-extraction window duration
    SSDP_MCAST_IP: str = "239.255.255.250"
    SSDP_PORT: int = 1900
    RETRAIN_EVERY_N_WINDOWS: int = 60  # retrain every ~10 minutes

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        interface: str,
        feature_extractor: Any,
        ml_engine: Any,
        anomaly_callback: Optional[Callable] = None,
        spoofing_callback: Optional[Callable] = None,
        evidence_collector: Any = None,
    ) -> None:
        self.interface = interface
        self.feature_extractor = feature_extractor
        self.ml_engine = ml_engine
        self.anomaly_callback: Optional[Callable] = anomaly_callback
        self.spoofing_callback: Optional[Callable] = spoofing_callback
        self.evidence_collector = evidence_collector

        # State
        self._running: bool = False
        self._packets_captured: int = 0
        self._windows_processed: int = 0
        self._anomalies_detected: int = 0
        self._lock = threading.Lock()

        # Packet queue for producer-consumer decoupling
        self._pkt_queue: queue.Queue = queue.Queue(maxsize=0)  # unbounded

        # Threads
        self._sniffer: Optional[Any] = None       # scapy AsyncSniffer
        self._consumer_thread: Optional[threading.Thread] = None
        self._timer_thread_obj: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        logger.info(
            "BUMPacketCapture initialised  interface=%s  window=%ds  scapy=%s",
            self.interface,
            self.WINDOW_SECONDS,
            SCAPY_AVAILABLE,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the sniffer, consumer thread, and window-timer thread."""
        if self._running:
            logger.warning("BUMPacketCapture.start() called while already running – ignoring.")
            return

        if not SCAPY_AVAILABLE:
            logger.warning("scapy not available – capture disabled; start() is a no-op.")
            return

        self._stop_event.clear()
        self._running = True

        # Consumer thread: drains the packet queue
        self._consumer_thread = threading.Thread(
            target=self._consumer_loop,
            name="bum-consumer",
            daemon=True,
        )
        self._consumer_thread.start()

        # Timer thread: fires _process_window() periodically
        self._timer_thread_obj = threading.Thread(
            target=self._timer_thread,
            name="bum-timer",
            daemon=True,
        )
        self._timer_thread_obj.start()

        # Scapy async sniffer
        try:
            self._sniffer = scapy.AsyncSniffer(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
            )
            self._sniffer.start()
            logger.info(
                "BUMPacketCapture started  interface=%s  pid=%d",
                self.interface,
                os.getpid(),
            )
        except Exception as exc:
            logger.error("Failed to start AsyncSniffer on %s: %s", self.interface, exc)
            self._running = False
            self._stop_event.set()

    def stop(self) -> None:
        """Stop the sniffer and all background threads cleanly."""
        if not self._running:
            return

        logger.info("BUMPacketCapture stopping…")
        self._running = False
        self._stop_event.set()

        # Stop scapy sniffer
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                logger.debug("AsyncSniffer.stop() raised: %s", exc)
            self._sniffer = None

        # Drain and stop consumer
        if self._consumer_thread is not None:
            self._consumer_thread.join(timeout=5)

        # Stop timer thread
        if self._timer_thread_obj is not None:
            self._timer_thread_obj.join(timeout=self.WINDOW_SECONDS + 2)

        logger.info(
            "BUMPacketCapture stopped  packets=%d  windows=%d  anomalies=%d",
            self._packets_captured,
            self._windows_processed,
            self._anomalies_detected,
        )

    def get_status(self) -> Dict[str, Any]:
        """
        Return a status snapshot.

        Returns
        -------
        dict
            Keys: ``running``, ``interface``, ``packets_captured``,
            ``windows_processed``, ``anomalies_detected``, ``scapy_available``.
        """
        return {
            "running": self._running,
            "interface": self.interface,
            "packets_captured": self._packets_captured,
            "windows_processed": self._windows_processed,
            "anomalies_detected": self._anomalies_detected,
            "scapy_available": SCAPY_AVAILABLE,
        }

    # ------------------------------------------------------------------
    # Packet classification
    # ------------------------------------------------------------------

    def _classify_packet(self, pkt: Any) -> Dict[str, Any]:
        """
        Parse a scapy packet into a structured ``pkt_info`` dictionary.

        Classification priority (highest → lowest):
        ARP_PROBE → GARP/ARP_ANNOUNCE → ARP → SSDP → ICMPv6 → IPv6 →
        ICMP → TCP → UDP → IP_RESTO → BCAST → MCAST → UCAST.

        Parameters
        ----------
        pkt : scapy packet
            Raw packet from the sniffer.

        Returns
        -------
        dict
            Parsed packet metadata.
        """
        pkt_info: Dict[str, Any] = {
            "timestamp": time.time(),
            "mac_src": None,
            "mac_dst": None,
            "pkt_type": "UCAST",
            "ip_src": None,
            "ip_dst": None,
            "is_arp_to_existing_ip": False,  # resolved by feature_extractor
        }

        # ── Ethernet layer ────────────────────────────────────────────
        if pkt.haslayer(scapy.Ether):
            eth = pkt[scapy.Ether]
            pkt_info["mac_src"] = eth.src.lower() if eth.src else None
            pkt_info["mac_dst"] = eth.dst.lower() if eth.dst else None

        mac_dst: str = pkt_info.get("mac_dst") or ""

        # ── ARP classification ────────────────────────────────────────
        if pkt.haslayer(scapy.ARP):
            arp = pkt[scapy.ARP]
            psrc: str = getattr(arp, "psrc", "") or ""
            pdst: str = getattr(arp, "pdst", "") or ""
            op: int = getattr(arp, "op", 0)

            if psrc == "0.0.0.0":
                pkt_type = "ARP_PROBE"
            elif psrc == pdst and psrc != "0.0.0.0":
                # GARP and ARP_ANNOUNCE share the same predicate;
                # differentiate by ARP operation code (op=1 → request → ARP_ANNOUNCE)
                pkt_type = "ARP_ANNOUNCE" if op == 1 else "GARP"
            else:
                pkt_type = "ARP"

            pkt_info["pkt_type"] = pkt_type
            pkt_info["ip_src"] = psrc if psrc else None
            pkt_info["ip_dst"] = pdst if pdst else None
            return pkt_info

        # ── IP layer info (shared by remaining types) ─────────────────
        if pkt.haslayer(scapy.IP):
            ip = pkt[scapy.IP]
            pkt_info["ip_src"] = ip.src
            pkt_info["ip_dst"] = ip.dst

        # ── SSDP ──────────────────────────────────────────────────────
        udp_dst_port: Optional[int] = None
        if pkt.haslayer(scapy.UDP):
            udp_dst_port = pkt[scapy.UDP].dport

        ip_dst: Optional[str] = pkt_info.get("ip_dst")
        if udp_dst_port == self.SSDP_PORT or ip_dst == self.SSDP_MCAST_IP:
            pkt_info["pkt_type"] = "SSDP"
            return pkt_info

        # ── ICMPv6 ────────────────────────────────────────────────────
        if pkt.haslayer(scapy.IPv6):
            pkt_info["ip_src"] = pkt_info["ip_src"] or pkt[scapy.IPv6].src
            pkt_info["ip_dst"] = pkt_info["ip_dst"] or pkt[scapy.IPv6].dst
            if pkt.haslayer(scapy.ICMPv6Unknown) or pkt.haslayer(scapy.ICMPv6EchoRequest) \
                    or any(pkt.haslayer(l) for l in _ICMPV6_LAYER_TYPES):
                pkt_info["pkt_type"] = "ICMPv6"
            else:
                pkt_info["pkt_type"] = "IPv6"
            return pkt_info

        # ── Layer-4 classification (IP only beyond this point) ────────
        if pkt.haslayer(scapy.ICMP):
            pkt_info["pkt_type"] = "ICMP"
        elif pkt.haslayer(scapy.TCP):
            pkt_info["pkt_type"] = "TCP"
        elif pkt.haslayer(scapy.UDP):
            pkt_info["pkt_type"] = "UDP"
        elif pkt.haslayer(scapy.IP):
            pkt_info["pkt_type"] = "IP_RESTO"
        # ── Ethernet-only classification ──────────────────────────────
        elif mac_dst == "ff:ff:ff:ff:ff:ff":
            pkt_info["pkt_type"] = "BCAST"
        elif mac_dst.startswith("01:") or mac_dst.startswith("33:33:"):
            pkt_info["pkt_type"] = "MCAST"
        else:
            pkt_info["pkt_type"] = "UCAST"

        return pkt_info

    def _packet_handler(self, pkt: Any) -> None:
        """
        Scapy callback: classify packet and enqueue for async processing.

        Parameters
        ----------
        pkt : scapy packet
            Captured packet delivered by the sniffer.
        """
        try:
            pkt_info = self._classify_packet(pkt)
            self._pkt_queue.put_nowait(pkt_info)

            with self._lock:
                self._packets_captured += 1

            # Feed raw packet to evidence collector's rolling buffer
            if self.evidence_collector is not None:
                try:
                    self.evidence_collector.add_packet(pkt)
                except Exception as ec_exc:
                    logger.debug("evidence_collector.add_packet error: %s", ec_exc)

        except Exception as exc:
            logger.debug("_packet_handler exception (packet dropped): %s", exc)

    # ------------------------------------------------------------------
    # Consumer loop
    # ------------------------------------------------------------------

    def _consumer_loop(self) -> None:
        """Drain ``_pkt_queue`` and forward each item to ``feature_extractor``."""
        logger.debug("BUM consumer thread started")
        while not self._stop_event.is_set() or not self._pkt_queue.empty():
            try:
                pkt_info = self._pkt_queue.get(timeout=0.5)
                if self.feature_extractor is not None:
                    self.feature_extractor.update(pkt_info)
                self._pkt_queue.task_done()
            except queue.Empty:
                continue
            except Exception as exc:
                logger.error("Consumer loop error: %s", exc, exc_info=True)
        logger.debug("BUM consumer thread exited")

    # ------------------------------------------------------------------
    # Window processing
    # ------------------------------------------------------------------

    def _process_window(self) -> None:
        """
        Execute per-window ML inference and anomaly reporting.

        Steps
        -----
        1. ``feature_extractor.get_snapshot()`` → ``{mac: feature_vector}``
        2. ``feature_extractor.check_spoofing()`` → dispatch spoofing alerts
        3. For each MAC: feed vector to ML engine (train or predict)
        4. Fire ``anomaly_callback`` and save PCAP evidence on anomaly
        5. ``feature_extractor.reset_counters()``
        6. Periodic ``ml_engine.retrain_if_needed()``
        """
        with self._lock:
            window_index = self._windows_processed + 1

        try:
            if self.feature_extractor is None:
                logger.debug("_process_window: feature_extractor not set, skipping.")
                return

            # ── 1. Feature snapshot ───────────────────────────────────
            snapshot: Dict[str, Any] = {}
            try:
                snapshot = self.feature_extractor.get_snapshot() or {}
            except Exception as exc:
                logger.error("feature_extractor.get_snapshot() failed: %s", exc)

            # ── 2. Spoofing check ─────────────────────────────────────
            try:
                spoofing_alerts = self.feature_extractor.check_spoofing() or []
                for alert in spoofing_alerts:
                    if self.spoofing_callback is not None:
                        try:
                            self.spoofing_callback(alert)
                        except Exception as cb_exc:
                            logger.error("spoofing_callback raised: %s", cb_exc)
            except Exception as exc:
                logger.error("feature_extractor.check_spoofing() failed: %s", exc)

            # ── 3 & 4. ML inference per MAC ───────────────────────────
            for mac, feature_vector in snapshot.items():
                if self.ml_engine is None:
                    break
                try:
                    if not getattr(self.ml_engine, "is_trained", False):
                        self.ml_engine.add_training_sample(feature_vector)
                    else:
                        prediction_result = self.ml_engine.predict(feature_vector)
                        is_anomaly: bool = prediction_result.get("is_anomaly", False) \
                            if isinstance(prediction_result, dict) else bool(prediction_result)

                        if is_anomaly:
                            with self._lock:
                                self._anomalies_detected += 1

                            logger.warning(
                                "Anomaly detected  mac=%s  window=%d  result=%s",
                                mac, window_index, prediction_result,
                            )

                            # Anomaly callback
                            if self.anomaly_callback is not None:
                                try:
                                    self.anomaly_callback(mac, feature_vector, prediction_result)
                                except Exception as cb_exc:
                                    logger.error("anomaly_callback raised: %s", cb_exc)

                            # Save PCAP evidence
                            if self.evidence_collector is not None:
                                try:
                                    anomaly_score = prediction_result.get("score", 1.0) \
                                        if isinstance(prediction_result, dict) else 1.0
                                    self.evidence_collector.save_anomaly_pcap(
                                        mac=mac,
                                        anomaly_score=float(anomaly_score),
                                        feature_vector=feature_vector,
                                    )
                                except Exception as ec_exc:
                                    logger.error("evidence_collector.save_anomaly_pcap raised: %s", ec_exc)

                except Exception as ml_exc:
                    logger.error("ML engine error for mac=%s: %s", mac, ml_exc)

            # ── 5. Reset feature counters ─────────────────────────────
            try:
                self.feature_extractor.reset_counters()
            except Exception as exc:
                logger.error("feature_extractor.reset_counters() failed: %s", exc)

            # ── 6. Periodic retraining ────────────────────────────────
            if self.ml_engine is not None and window_index % self.RETRAIN_EVERY_N_WINDOWS == 0:
                try:
                    self.ml_engine.retrain_if_needed()
                    logger.info("ml_engine.retrain_if_needed() called at window %d", window_index)
                except Exception as exc:
                    logger.error("ml_engine.retrain_if_needed() failed: %s", exc)

        except Exception as exc:
            logger.error("_process_window unhandled error (window %d): %s", window_index, exc, exc_info=True)
        finally:
            with self._lock:
                self._windows_processed += 1

    # ------------------------------------------------------------------
    # Timer thread
    # ------------------------------------------------------------------

    def _timer_thread(self) -> None:
        """
        Background thread that triggers :meth:`_process_window` every
        :attr:`WINDOW_SECONDS` seconds.
        """
        logger.debug("BUM timer thread started (interval=%ds)", self.WINDOW_SECONDS)
        while not self._stop_event.is_set():
            # Wait for the window duration (interruptible)
            self._stop_event.wait(timeout=self.WINDOW_SECONDS)
            if self._stop_event.is_set():
                break
            self._process_window()
        logger.debug("BUM timer thread exited")


# ---------------------------------------------------------------------------
# ICMPv6 layer helper – list of common ICMPv6 layer types for detection
# ---------------------------------------------------------------------------
def _build_icmpv6_types() -> tuple:
    """Build a tuple of known ICMPv6 scapy layer classes (best-effort)."""
    if not SCAPY_AVAILABLE:
        return ()
    candidates = [
        "ICMPv6EchoRequest",
        "ICMPv6EchoReply",
        "ICMPv6ND_NS",
        "ICMPv6ND_NA",
        "ICMPv6ND_RA",
        "ICMPv6ND_RS",
        "ICMPv6MLQuery",
        "ICMPv6MLReport",
        "ICMPv6MLDone",
        "ICMPv6Unknown",
    ]
    result = []
    for name in candidates:
        cls = getattr(scapy, name, None)
        if cls is not None:
            result.append(cls)
    return tuple(result)


_ICMPV6_LAYER_TYPES: tuple = _build_icmpv6_types()
