"""
NetSentinel - Main Application Entrypoint
Unified Active Threat Protection & Automated Response Engine

Startup order:
  1. Database initialisation
  2. Firewall chain setup (nftables)
  3. ML engine model load (Isolation Forest)
  4. BUM packet capture sensor start (if enabled)
  5. Background expiration worker (temporary block cleanup)
"""

import os
import asyncio
import logging
import threading
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from config.config import settings
from database.db_service import init_db
from response.linux_firewall import linux_firewall
from response.rollback_manager import rollback_manager
from api.routes import router as api_router

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("NetSentinel")

# ── Background workers ────────────────────────────────────────────────────────

async def background_expiration_worker():
    """Periodically scans and expires temporary blocks per Section 14.11 Step 10."""
    logger.info("Started background expiration worker (cycle: 5 seconds)...")
    while True:
        try:
            expired_count = rollback_manager.process_expired_actions()
            if expired_count > 0:
                logger.info(f"Background worker safely expired {expired_count} temporary restrictions.")
        except Exception as e:
            logger.error(f"Error in background expiration worker: {e}")
        await asyncio.sleep(5)


def _start_packet_capture() -> object:
    """
    Initialise and start the BUM packet capture sensor + ML engine.
    Returns the BUMPacketCapture instance (or None if capture disabled / deps missing).
    """
    if not settings.packet_capture_enabled:
        logger.info("BUM packet capture disabled (NETSENTINEL_CAPTURE_ENABLED=false). "
                    "Set env var to 'true' to enable live ML detection.")
        return None

    try:
        from threat_engine.feature_extractor import FeatureExtractor
        from threat_engine.ml_engine import ml_engine
        from threat_engine.packet_capture import BUMPacketCapture, SCAPY_AVAILABLE
        from response.email_notifier import email_notifier
        from response.evidence_collector import evidence_collector

        if not SCAPY_AVAILABLE:
            logger.warning("scapy not installed — BUM packet capture unavailable. "
                           "Install with: pip install scapy")
            return None

        feature_extractor = FeatureExtractor(
            arp_snapshot_path=settings.arp_snapshot_path
        )

        def anomaly_callback(mac: str, feature_vector: dict, prediction: dict):
            """Called by packet_capture when Isolation Forest flags an anomaly."""
            score = prediction.get("anomaly_score", 0)
            logger.warning(
                f"[ML ANOMALY] MAC={mac}  score={score:.1f}  "
                f"confidence={prediction.get('confidence', 0):.2f}"
            )
            # Save PCAP evidence
            pcap_path = evidence_collector.save_anomaly_pcap(mac, score, feature_vector)
            # Send email alert
            email_notifier.send_anomaly_alert(mac, score, feature_vector, pcap_path)

        def spoofing_callback(alerts: list):
            """Called by packet_capture when MAC/IP spoofing is detected."""
            for alert in alerts:
                logger.warning(f"[SPOOF ALERT] {alert}")
                email_notifier.send_spoofing_alert(alert)

        capture = BUMPacketCapture(
            interface=settings.monitored_interface,
            feature_extractor=feature_extractor,
            ml_engine=ml_engine,
            anomaly_callback=anomaly_callback,
            spoofing_callback=spoofing_callback,
        )
        capture.start()
        logger.info(
            f"[✓] BUM packet capture started on interface '{settings.monitored_interface}' "
            f"(window={settings.bum_window_seconds}s)"
        )
        return capture

    except Exception as e:
        logger.error(f"Failed to start packet capture sensor: {e}", exc_info=True)
        return None


# ── App lifespan ──────────────────────────────────────────────────────────────

_capture_instance = None   # module-level reference for status endpoint

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _capture_instance

    # 1. Database
    logger.info(f"Initializing {settings.app_name} v{settings.version} "
                f"in {settings.protection_mode.value} mode...")
    init_db()

    # 2. Firewall chains
    fw_init = linux_firewall.initialize_chains(dry_run=settings.dry_run_mode)
    logger.info(f"Firewall subsystem: {fw_init.get('message')}")

    # 3. ML engine (try loading saved model)
    try:
        from threat_engine.ml_engine import ml_engine
        if ml_engine.load_model():
            logger.info("[✓] Isolation Forest model loaded from disk.")
        else:
            logger.info("[i] No saved ML model found — will train after "
                        f"{ml_engine.MIN_TRAINING_SAMPLES} capture windows.")
    except Exception as e:
        logger.warning(f"ML engine init skipped: {e}")

    # 4. BUM packet capture sensor (runs in its own threads)
    _capture_instance = _start_packet_capture()
    app.state.capture = _capture_instance

    # 5. Background expiration worker
    worker_task = asyncio.create_task(background_expiration_worker())

    yield  # ── server is live ──

    # Shutdown
    if _capture_instance:
        try:
            _capture_instance.stop()
            logger.info("BUM packet capture stopped.")
        except Exception as e:
            logger.error(f"Error stopping packet capture: {e}")
    worker_task.cancel()
    logger.info("NetSentinel shutdown completed.")


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description=(
        "Intelligent, policy-controlled Network Intrusion Detection and Prevention System "
        "(NIDS/NIPS) with Isolation Forest ML anomaly detection, live BUM packet capture, "
        "nftables kernel enforcement, and tamper-evident cryptographic audit logging."
    ),
    lifespan=lifespan,
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(api_router)

# Health / ML / Capture / Email endpoints
try:
    from api.health import all_routers as health_routers
    for r in health_routers:
        app.include_router(r)
    logger.debug("Health/ML/Capture/Email routers registered.")
except ImportError as e:
    logger.warning(f"Health router not available: {e}")

# ── Static files & dashboard ──────────────────────────────────────────────────
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(_BASE_DIR, "dashboard", "static")),
    name="static",
)
templates = Jinja2Templates(directory=os.path.join(_BASE_DIR, "dashboard", "templates"))


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Renders the primary Active Protection dashboard panel."""
    return templates.TemplateResponse(request, "index.html", {"app_name": settings.app_name})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
