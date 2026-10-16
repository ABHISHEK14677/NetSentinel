"""
NetSentinel - Main Application Entrypoint
Unified Active Threat Protection & Automated Response Engine
"""

import os
import asyncio
import logging
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

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("NetSentinel")

# Background task for expiring temporary firewall restrictions
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info(f"Initializing {settings.app_name} v{settings.version} in {settings.protection_mode.value} mode...")
    init_db()
    fw_init = linux_firewall.initialize_chains(dry_run=settings.dry_run_mode)
    logger.info(f"Firewall subsystem status: {fw_init.get('message')}")
    
    # Start background expiration task
    worker_task = asyncio.create_task(background_expiration_worker())
    yield
    # Shutdown
    worker_task.cancel()
    logger.info("NetSentinel shutdown completed.")

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Intelligent, policy-controlled Network Intrusion Detection and Prevention System (NIDS/NIPS)",
    lifespan=lifespan
)

# Mount API
app.include_router(api_router)

# Mount Static and Templates
app.mount("/static", StaticFiles(directory="/home/kali/NetSentinel/dashboard/static"), name="static")
templates = Jinja2Templates(directory="/home/kali/NetSentinel/dashboard/templates")

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Renders the primary Active Protection dashboard panel."""
    return templates.TemplateResponse(request, "index.html", {"app_name": settings.app_name})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
