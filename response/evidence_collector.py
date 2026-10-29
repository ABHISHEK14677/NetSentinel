"""
NetSentinel - Evidence Collector
=================================
Saves PCAP evidence files and JSON metadata sidecars when anomalies are
detected.  Maintains a rolling in-memory packet buffer and enforces a
configurable maximum disk footprint, automatically evicting the oldest
evidence when the limit is exceeded.

Directory layout
----------------
  <project_root>/
  └── evidence/
      ├── 20240101_120000_aabbccddeeff_score0.92.pcap
      ├── 20240101_120000_aabbccddeeff_score0.92.json
      ├── …

Singleton
---------
The module exposes a ready-to-use ``evidence_collector`` singleton:

    from response.evidence_collector import evidence_collector
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional scapy import
# ---------------------------------------------------------------------------
try:
    import scapy.all as scapy  # type: ignore

    SCAPY_AVAILABLE = True
    logger.debug("scapy loaded successfully in evidence_collector")
except ImportError:  # pragma: no cover
    SCAPY_AVAILABLE = False
    logger.warning(
        "scapy is not installed – PCAP evidence saving is disabled. "
        "Install with:  pip install scapy"
    )


# ---------------------------------------------------------------------------
# EvidenceCollector
# ---------------------------------------------------------------------------

class EvidenceCollector:
    """
    Thread-safe evidence collector that buffers raw packets and flushes them
    to disk (`.pcap` + `.json` sidecar) when an anomaly is confirmed.

    Parameters
    ----------
    project_root : str
        Absolute path to the NetSentinel project root directory.
        The ``evidence/`` sub-directory is created here automatically.

    Class constants
    ---------------
    EVIDENCE_DIR : str
        Sub-directory name (relative to ``project_root``) for saved files.
    MAX_DISK_GB : float
        Maximum allowed evidence directory size in gigabytes.  Oldest files
        are deleted automatically when this limit is exceeded.
    ROLLING_BUFFER_SIZE : int
        Maximum number of packets kept in the in-memory rolling buffer.
        The oldest packet is evicted when the buffer is full.
    """

    EVIDENCE_DIR: str = "evidence"
    MAX_DISK_GB: float = 2.0
    ROLLING_BUFFER_SIZE: int = 200

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, project_root: str) -> None:
        self.project_root: str = project_root
        self.evidence_dir: str = os.path.join(project_root, self.EVIDENCE_DIR)

        # Create evidence directory (parents already exist)
        os.makedirs(self.evidence_dir, exist_ok=True)
        logger.info("EvidenceCollector initialised  evidence_dir=%s", self.evidence_dir)

        # Rolling packet buffer (list of scapy packets)
        self._buffer: List[Any] = []
        self._buffer_lock = threading.Lock()

        # File-system lock (guards saves + cleanup)
        self._fs_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Rolling buffer
    # ------------------------------------------------------------------

    def add_packet(self, pkt: Any) -> None:
        """
        Append a scapy packet to the rolling buffer.

        If the buffer has reached :attr:`ROLLING_BUFFER_SIZE`, the oldest
        packet is silently discarded before the new one is appended.

        If scapy is not available this method is a no-op.

        Parameters
        ----------
        pkt : scapy packet
            Raw captured packet to buffer.
        """
        if not SCAPY_AVAILABLE:
            return

        with self._buffer_lock:
            if len(self._buffer) >= self.ROLLING_BUFFER_SIZE:
                self._buffer.pop(0)  # evict oldest
            self._buffer.append(pkt)

    def _get_buffer_snapshot(self) -> List[Any]:
        """Return a shallow copy of the current rolling buffer (thread-safe)."""
        with self._buffer_lock:
            return list(self._buffer)

    # ------------------------------------------------------------------
    # PCAP save
    # ------------------------------------------------------------------

    def save_anomaly_pcap(
        self,
        mac: str,
        anomaly_score: float,
        feature_vector: Dict[str, Any],
    ) -> Optional[str]:
        """
        Flush the current rolling buffer to a ``.pcap`` file and write a
        companion ``.json`` sidecar with anomaly metadata.

        File naming
        -----------
        ``YYYYMMDD_HHMMSS_<mac_clean>_score<score>.pcap``

        where ``<mac_clean>`` is the MAC address with colons replaced by
        empty strings (e.g. ``aabbccddeeff``), and ``<score>`` is rounded
        to two decimal places.

        Parameters
        ----------
        mac : str
            Source MAC address of the anomalous device.
        anomaly_score : float
            Anomaly confidence score (0.0 – 1.0).
        feature_vector : dict
            Feature snapshot for the device at this window.

        Returns
        -------
        str or None
            Absolute path to the saved ``.pcap`` file, or ``None`` if
            scapy is unavailable or no packets are buffered.
        """
        if not SCAPY_AVAILABLE:
            logger.warning(
                "save_anomaly_pcap called but scapy not available – skipping evidence save."
            )
            return None

        packets = self._get_buffer_snapshot()
        if not packets:
            logger.debug("save_anomaly_pcap: rolling buffer is empty, nothing to save.")
            return None

        # Build file stem
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        mac_clean = mac.replace(":", "").replace("-", "").lower()
        score_str = f"{anomaly_score:.2f}".replace(".", "")  # e.g. "092"
        stem = f"{ts}_{mac_clean}_score{anomaly_score:.2f}"
        pcap_path = os.path.join(self.evidence_dir, f"{stem}.pcap")
        json_path = os.path.join(self.evidence_dir, f"{stem}.json")

        with self._fs_lock:
            # ── Save PCAP ─────────────────────────────────────────────
            try:
                scapy.wrpcap(pcap_path, packets)
                logger.info(
                    "Anomaly PCAP saved  mac=%s  score=%.4f  packets=%d  path=%s",
                    mac, anomaly_score, len(packets), pcap_path,
                )
            except Exception as exc:
                logger.error("Failed to write PCAP %s: %s", pcap_path, exc)
                return None

            # ── Save JSON sidecar ─────────────────────────────────────
            sidecar: Dict[str, Any] = {
                "timestamp": time.time(),
                "timestamp_human": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "mac": mac,
                "anomaly_score": anomaly_score,
                "packet_count": len(packets),
                "pcap_file": os.path.basename(pcap_path),
                "feature_vector": feature_vector,
            }
            try:
                with open(json_path, "w", encoding="utf-8") as fh:
                    json.dump(sidecar, fh, indent=2, default=str)
                logger.debug("Sidecar JSON saved  path=%s", json_path)
            except Exception as exc:
                logger.warning("Failed to write JSON sidecar %s: %s", json_path, exc)

            # ── Disk cleanup ──────────────────────────────────────────
            self._check_and_cleanup_disk()

        return pcap_path

    # ------------------------------------------------------------------
    # Disk management
    # ------------------------------------------------------------------

    def _dir_size_bytes(self) -> int:
        """Return the total size in bytes of all files in :attr:`evidence_dir`."""
        total = 0
        try:
            for entry in os.scandir(self.evidence_dir):
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat().st_size
        except OSError as exc:
            logger.warning("Could not stat evidence directory: %s", exc)
        return total

    def _check_and_cleanup_disk(self) -> None:
        """
        Delete the oldest ``.pcap`` / ``.json`` evidence pairs until the
        evidence directory is below :attr:`MAX_DISK_GB`.

        This method is called automatically after every PCAP save and is
        *not* thread-safe on its own – the caller must hold ``_fs_lock``.
        """
        max_bytes = int(self.MAX_DISK_GB * 1024 ** 3)
        current_bytes = self._dir_size_bytes()

        if current_bytes <= max_bytes:
            return

        logger.info(
            "Evidence disk usage %.2f GB exceeds limit %.2f GB – cleaning up…",
            current_bytes / 1024 ** 3,
            self.MAX_DISK_GB,
        )

        # Collect .pcap files sorted by modification time (oldest first)
        pcap_files: List[tuple] = []
        try:
            for entry in os.scandir(self.evidence_dir):
                if entry.is_file(follow_symlinks=False) and entry.name.endswith(".pcap"):
                    pcap_files.append((entry.stat().st_mtime, entry.path))
        except OSError as exc:
            logger.error("Disk cleanup scandir failed: %s", exc)
            return

        pcap_files.sort()  # ascending mtime → oldest first

        for _, pcap_path in pcap_files:
            if current_bytes <= max_bytes:
                break
            # Delete PCAP
            pcap_size = 0
            try:
                pcap_size = os.path.getsize(pcap_path)
                os.remove(pcap_path)
                current_bytes -= pcap_size
                logger.info("Evicted old evidence PCAP: %s", pcap_path)
            except OSError as exc:
                logger.warning("Could not delete PCAP %s: %s", pcap_path, exc)

            # Delete companion JSON sidecar
            json_path = pcap_path.replace(".pcap", ".json")
            if os.path.exists(json_path):
                try:
                    json_size = os.path.getsize(json_path)
                    os.remove(json_path)
                    current_bytes -= json_size
                    logger.debug("Evicted sidecar JSON: %s", json_path)
                except OSError as exc:
                    logger.warning("Could not delete JSON sidecar %s: %s", json_path, exc)

    # ------------------------------------------------------------------
    # Evidence listing
    # ------------------------------------------------------------------

    def get_evidence_list(self) -> List[Dict[str, Any]]:
        """
        Return metadata for every saved evidence entry by reading their
        ``.json`` sidecar files.

        Returns
        -------
        list of dict
            Each dict contains the fields written by :meth:`save_anomaly_pcap`
            plus ``"json_path"`` and ``"pcap_exists"`` convenience keys.
            Sorted by ``timestamp`` descending (newest first).
        """
        entries: List[Dict[str, Any]] = []
        try:
            for entry in os.scandir(self.evidence_dir):
                if entry.is_file(follow_symlinks=False) and entry.name.endswith(".json"):
                    try:
                        with open(entry.path, "r", encoding="utf-8") as fh:
                            data: Dict[str, Any] = json.load(fh)
                        data["json_path"] = entry.path
                        pcap_path = entry.path.replace(".json", ".pcap")
                        data["pcap_exists"] = os.path.exists(pcap_path)
                        entries.append(data)
                    except Exception as exc:
                        logger.debug("Could not read sidecar %s: %s", entry.path, exc)
        except OSError as exc:
            logger.error("get_evidence_list scandir failed: %s", exc)

        entries.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
        return entries

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """
        Return a summary of the evidence store.

        Returns
        -------
        dict
            Keys: ``evidence_dir``, ``file_count``, ``total_size_mb``,
            ``max_disk_gb``.
        """
        file_count = 0
        total_bytes = 0
        try:
            for entry in os.scandir(self.evidence_dir):
                if entry.is_file(follow_symlinks=False):
                    file_count += 1
                    total_bytes += entry.stat().st_size
        except OSError:
            pass

        return {
            "evidence_dir": self.evidence_dir,
            "file_count": file_count,
            "total_size_mb": round(total_bytes / (1024 ** 2), 3),
            "max_disk_gb": self.MAX_DISK_GB,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

#: Ready-to-use singleton.  Import as::
#:
#:     from response.evidence_collector import evidence_collector
evidence_collector = EvidenceCollector(
    project_root=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
