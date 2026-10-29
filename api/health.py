"""
health.py
=========
System health monitoring FastAPI router for NetSentinel.

Exposes endpoints that report OS-level resource usage (CPU, RAM, disk,
network) via ``psutil`` as well as convenience routes for ML model status,
evidence listing, and email connectivity testing.

``psutil`` is treated as an optional dependency; if it cannot be imported
every metric is returned as ``-1`` and ``health_status`` is ``"UNKNOWN"``.
"""

from __future__ import annotations

import logging
import os
import platform
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional psutil import
# ---------------------------------------------------------------------------
try:
    import psutil  # type: ignore

    PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available; system health metrics will be unavailable.")

from fastapi import APIRouter
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Health computation
# ---------------------------------------------------------------------------

def get_system_health() -> Dict[str, Any]:
    """
    Collect current OS resource metrics and derive an overall health status.

    Returns
    -------
    dict
        A flat dictionary with the following keys:

        * ``cpu_percent``        – CPU utilisation over a short sample window.
        * ``cpu_count``          – Logical CPU core count.
        * ``ram_total_mb``       – Total physical RAM in megabytes.
        * ``ram_used_mb``        – Used physical RAM in megabytes.
        * ``ram_percent``        – RAM utilisation percentage.
        * ``disk_total_gb``      – Total capacity of the project-root filesystem.
        * ``disk_used_gb``       – Used capacity of the project-root filesystem.
        * ``disk_percent``       – Disk utilisation percentage.
        * ``network_bytes_sent`` – Cumulative bytes sent since boot.
        * ``network_bytes_recv`` – Cumulative bytes received since boot.
        * ``uptime_seconds``     – Seconds since the OS was last booted.
        * ``python_pid``         – PID of the current Python process.
        * ``platform``           – Detailed OS/kernel string.
        * ``health_status``      – ``"HEALTHY"``, ``"WARNING"``, or ``"CRITICAL"``.
        * ``warnings``           – Human-readable list of threshold breaches.
        * ``psutil_available``   – Whether psutil was importable.
        * ``timestamp``          – Unix epoch at the time of the call.

    If ``psutil`` is unavailable, all numeric fields are ``-1``,
    ``health_status`` is ``"UNKNOWN"``, and ``warnings`` is empty.
    """
    if not PSUTIL_AVAILABLE:
        return {
            "cpu_percent": -1,
            "cpu_count": -1,
            "ram_total_mb": -1,
            "ram_used_mb": -1,
            "ram_percent": -1,
            "disk_total_gb": -1,
            "disk_used_gb": -1,
            "disk_percent": -1,
            "network_bytes_sent": -1,
            "network_bytes_recv": -1,
            "uptime_seconds": -1,
            "python_pid": os.getpid(),
            "platform": platform.platform(),
            "health_status": "UNKNOWN",
            "warnings": [],
            "psutil_available": False,
            "timestamp": time.time(),
        }

    # --- CPU ---------------------------------------------------------------
    cpu_percent: float = psutil.cpu_percent(interval=0.1)
    cpu_count: int = psutil.cpu_count(logical=True) or 0

    # --- RAM ---------------------------------------------------------------
    ram = psutil.virtual_memory()
    ram_total_mb: float = ram.total / 1024 / 1024
    ram_used_mb: float = ram.used / 1024 / 1024
    ram_percent: float = ram.percent

    # --- Disk (project root filesystem) ------------------------------------
    project_root = os.path.abspath(
        os.getenv("NETSENTINEL_ROOT", os.path.dirname(os.path.dirname(__file__)))
    )
    disk = psutil.disk_usage(project_root)
    disk_total_gb: float = disk.total / 1024 / 1024 / 1024
    disk_used_gb: float = disk.used / 1024 / 1024 / 1024
    disk_percent: float = disk.percent

    # --- Network -----------------------------------------------------------
    net = psutil.net_io_counters()
    network_bytes_sent: int = net.bytes_sent
    network_bytes_recv: int = net.bytes_recv

    # --- Uptime ------------------------------------------------------------
    uptime_seconds: float = time.time() - psutil.boot_time()

    # --- Health status logic -----------------------------------------------
    warnings: List[str] = []

    if cpu_percent > 90:
        warnings.append(f"CPU at {cpu_percent:.0f}%")
    elif cpu_percent > 75:
        warnings.append(f"CPU at {cpu_percent:.0f}%")

    if ram_percent > 90:
        warnings.append(f"RAM at {ram_percent:.0f}%")
    elif ram_percent > 80:
        warnings.append(f"RAM at {ram_percent:.0f}%")

    if disk_percent > 95:
        warnings.append(f"Disk at {disk_percent:.0f}%")
    elif disk_percent > 85:
        warnings.append(f"Disk at {disk_percent:.0f}%")

    if cpu_percent > 90 or ram_percent > 90 or disk_percent > 95:
        health_status = "CRITICAL"
    elif cpu_percent > 75 or ram_percent > 80 or disk_percent > 85:
        health_status = "WARNING"
    else:
        health_status = "HEALTHY"

    return {
        "cpu_percent": cpu_percent,
        "cpu_count": cpu_count,
        "ram_total_mb": round(ram_total_mb, 2),
        "ram_used_mb": round(ram_used_mb, 2),
        "ram_percent": ram_percent,
        "disk_total_gb": round(disk_total_gb, 2),
        "disk_used_gb": round(disk_used_gb, 2),
        "disk_percent": disk_percent,
        "network_bytes_sent": network_bytes_sent,
        "network_bytes_recv": network_bytes_recv,
        "uptime_seconds": round(uptime_seconds, 2),
        "python_pid": os.getpid(),
        "platform": platform.platform(),
        "health_status": health_status,
        "warnings": warnings,
        "psutil_available": True,
        "timestamp": time.time(),
    }


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/health", tags=["Health"])


@router.get("", summary="System health metrics")
async def health_endpoint() -> Dict[str, Any]:
    """
    Return current system health metrics.

    Collects CPU, RAM, disk, and network statistics via psutil and returns
    an overall ``health_status`` of ``HEALTHY``, ``WARNING``, or ``CRITICAL``.
    """
    return get_system_health()


@router.get("/evidence", summary="List collected evidence")
async def evidence_endpoint() -> Any:
    """
    Return a list of all evidence items collected by the evidence collector.

    Imports :mod:`response.evidence_collector` at request time so that the
    module is not required at application startup.
    """
    try:
        from response.evidence_collector import evidence_collector  # type: ignore

        return evidence_collector.get_evidence_list()
    except ImportError as exc:
        logger.error("Could not import evidence_collector: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"error": "Evidence collector module not available", "detail": str(exc)},
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Error retrieving evidence list: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to retrieve evidence list", "detail": str(exc)},
        )


# ---------------------------------------------------------------------------
# ML routes (kept in this router for convenience)
# ---------------------------------------------------------------------------

@router.get("/../../ml/status", include_in_schema=False)
async def _ml_status_alias():
    """Internal alias — use the path registered below."""
    return await ml_status_endpoint()


# Register under a sibling prefix so it appears as /api/ml/status
_ml_router = APIRouter(prefix="/api/ml", tags=["ML"])


@_ml_router.get("/status", summary="ML engine status")
async def ml_status_endpoint() -> Any:
    """
    Return the current status of the NetSentinel ML/threat engine.

    Imports :mod:`threat_engine.ml_engine` at request time.
    """
    try:
        from threat_engine.ml_engine import ml_engine  # type: ignore

        return ml_engine.get_status()
    except ImportError as exc:
        logger.error("Could not import ml_engine: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"error": "ML engine module not available", "detail": str(exc)},
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Error retrieving ML status: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to retrieve ML status", "detail": str(exc)},
        )


@_ml_router.get("/features", summary="ML feature importance")
async def ml_features_endpoint() -> Any:
    """
    Return approximate feature importances from the ML engine.

    Imports :mod:`threat_engine.ml_engine` at request time.
    """
    try:
        from threat_engine.ml_engine import ml_engine  # type: ignore

        return ml_engine.get_feature_importance_approx()
    except ImportError as exc:
        logger.error("Could not import ml_engine: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"error": "ML engine module not available", "detail": str(exc)},
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Error retrieving feature importances: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to retrieve feature importances", "detail": str(exc)},
        )


# ---------------------------------------------------------------------------
# Capture status route
# ---------------------------------------------------------------------------

_capture_router = APIRouter(prefix="/api/capture", tags=["Capture"])


@_capture_router.get("/status", summary="Packet capture status")
async def capture_status_endpoint() -> Any:
    """
    Return the current packet-capture subsystem status.

    Attempts to read status from application state.  Falls back to a
    placeholder response when the capture module is unavailable.
    """
    try:
        from capture.packet_capture import packet_capture  # type: ignore

        return packet_capture.get_status()
    except ImportError:
        logger.debug("packet_capture module not available; returning placeholder status")
        return {
            "status": "unavailable",
            "message": "Packet capture module is not loaded",
            "capturing": False,
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("Error retrieving capture status: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to retrieve capture status", "detail": str(exc)},
        )


# ---------------------------------------------------------------------------
# Email test route
# ---------------------------------------------------------------------------

_email_router = APIRouter(prefix="/api/email", tags=["Email"])


@_email_router.post("/test", summary="Test SMTP connection")
async def email_test_endpoint() -> Any:
    """
    Test the SMTP connection configured for NetSentinel alerts.

    Imports :mod:`response.email_notifier` at request time and calls
    :meth:`~response.email_notifier.EmailNotifier.test_connection`.
    No email is actually sent.
    """
    try:
        from response.email_notifier import email_notifier  # type: ignore

        result = email_notifier.test_connection()
        status_code = 200 if result.get("success") else 503
        return JSONResponse(status_code=status_code, content=result)
    except ImportError as exc:
        logger.error("Could not import email_notifier: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"error": "Email notifier module not available", "detail": str(exc)},
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Error testing email connection: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Email connection test failed", "detail": str(exc)},
        )


# ---------------------------------------------------------------------------
# Expose all sub-routers so the application can include them
# ---------------------------------------------------------------------------

all_routers = [router, _ml_router, _capture_router, _email_router]
