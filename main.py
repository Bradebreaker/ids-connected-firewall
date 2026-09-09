"""
main.py — FastAPI application entry point.

This is the orchestrator that wires together all modules:
    - Initialises the database and creates the default admin user
    - Starts the packet sniffer as a background task
    - Runs the detection pipeline consumer
    - Starts the APScheduler for block auto-expiry
    - Runs initial iptables reconciliation
    - Mounts static files and includes all API routers
    - Configures CORS, rate limiting, and structured logging

Run with:  sudo uvicorn main:app --host 0.0.0.0 --port 8000
"""

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pythonjsonlogger import jsonlogger

from config import settings
from db.database import init_db, async_session
from db.models import User
from api.auth import hash_password
from api.websocket_manager import WebSocketManager
from api import routes_auth, routes_alerts, routes_firewall, routes_stats
from firewall.manager import FirewallManager
from firewall.scheduler import create_scheduler
from firewall.sync import reconcile
from decision.engine import DecisionEngine
from detection.signature import SignatureDetector
from detection.port_scan import PortScanDetector
from detection.brute_force import BruteForceDetector
from detection.syn_flood import SynFloodDetector

from sqlalchemy import select


# ══════════════════════════════════════════════════════════════════════
#  Logging setup (structured JSON)
# ══════════════════════════════════════════════════════════════════════

def setup_logging():
    """Configure structured JSON logging to console and file."""
    log_handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    log_handler.setFormatter(formatter)

    # File handler
    os.makedirs(settings.LOG_DIR, exist_ok=True)
    file_handler = logging.FileHandler(
        os.path.join(settings.LOG_DIR, "ids_firewall.log")
    )
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL))
    root_logger.addHandler(log_handler)
    root_logger.addHandler(file_handler)

setup_logging()
logger = logging.getLogger("ids.main")


# ══════════════════════════════════════════════════════════════════════
#  Shared instances
# ══════════════════════════════════════════════════════════════════════

packet_queue = asyncio.Queue()
ws_manager = WebSocketManager()
fw_manager = FirewallManager()
decision_engine = DecisionEngine(fw_manager, ws_manager)

# Detection pipeline — all four independent detectors
detectors = [
    SignatureDetector(),
    PortScanDetector(),
    BruteForceDetector(),
    SynFloodDetector(),
]


# ══════════════════════════════════════════════════════════════════════
#  Detection pipeline consumer
# ══════════════════════════════════════════════════════════════════════

async def detection_pipeline():
    """
    Consumes packets from the queue and runs them through all detectors.

    Each packet is analysed by every detector independently.  If any
    detector raises an alert, it's passed to the decision engine.
    """
    logger.info("Detection pipeline started — %d detectors active", len(detectors))

    while True:
        packet_data = await packet_queue.get()

        for detector in detectors:
            try:
                alert_event = await detector.analyze(packet_data)
                if alert_event:
                    # Process through decision engine
                    async with async_session() as db:
                        try:
                            await decision_engine.process_alert(alert_event, db)
                        except Exception as e:
                            logger.error(
                                "Decision engine error for %s alert: %s",
                                alert_event.alert_type, e,
                            )
                            await db.rollback()
            except Exception as e:
                logger.error(
                    "Detector '%s' error: %s",
                    detector.name, e,
                )


# ══════════════════════════════════════════════════════════════════════
#  Application lifespan (startup / shutdown)
# ══════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages application startup and shutdown events.

    On startup:
        1. Initialise the database tables
        2. Create default admin user if none exists
        3. Initialise the iptables custom chain
        4. Run iptables ↔ DB reconciliation
        5. Start the detection pipeline consumer
        6. Start the packet sniffer (if enabled)
        7. Start the APScheduler for block expiry

    On shutdown:
        - Cancel background tasks
        - Stop the scheduler
    """
    logger.info("═" * 60)
    logger.info("  %s v%s starting up", settings.APP_NAME, settings.APP_VERSION)
    logger.info("═" * 60)

    # 1. Database init
    await init_db()
    logger.info("Database tables initialised")

    # 2. Create default admin
    async with async_session() as db:
        result = await db.execute(select(User).limit(1))
        if not result.scalar_one_or_none():
            admin = User(
                username=settings.DEFAULT_ADMIN_USER,
                hashed_password=hash_password(settings.DEFAULT_ADMIN_PASS),
                is_admin=True,
            )
            db.add(admin)
            await db.commit()
            logger.info(
                "Default admin user created: %s (CHANGE THE PASSWORD!)",
                settings.DEFAULT_ADMIN_USER,
            )

    # 3. Init iptables chain
    try:
        await fw_manager.init_chain()
    except Exception as e:
        logger.warning("iptables init failed (expected on non-Linux): %s", e)

    # 4. Reconcile iptables with DB
    try:
        async with async_session() as db:
            await reconcile(db, fw_manager)
    except Exception as e:
        logger.warning("iptables reconciliation failed: %s", e)

    # 5. Start detection pipeline
    pipeline_task = asyncio.create_task(detection_pipeline())

    # 6. Start sniffer (if enabled)
    sniffer_task = None
    if settings.SNIFFER_ENABLED:
        try:
            from sniffer.capture import start_sniffer
            sniffer_task = asyncio.create_task(start_sniffer(packet_queue))
            logger.info("Packet sniffer started")
        except Exception as e:
            logger.warning("Sniffer failed to start (needs root): %s", e)
    else:
        logger.info("Sniffer disabled via config")

    # 7. Start scheduler
    scheduler = create_scheduler(fw_manager)
    scheduler.start()
    logger.info("APScheduler started")

    logger.info("═" * 60)
    logger.info("  All systems operational — dashboard at http://%s:%d", settings.HOST, settings.PORT)
    logger.info("═" * 60)

    yield  # ── Application runs here ──

    # ── Shutdown ──────────────────────────────────────────────────
    logger.info("Shutting down …")
    pipeline_task.cancel()
    if sniffer_task:
        sniffer_task.cancel()
    scheduler.shutdown(wait=False)
    logger.info("Shutdown complete")


# ══════════════════════════════════════════════════════════════════════
#  FastAPI app
# ══════════════════════════════════════════════════════════════════════

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="IDS-Connected Firewall — Intrusion Detection + Automated Firewall Enforcement",
    lifespan=lifespan,
)

# ── Rate limiting ─────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_DEFAULT])
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please slow down."},
    )

# ── CORS ──────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Inject managers into route modules ────────────────────────────────
routes_alerts.set_ws_manager(ws_manager)
routes_firewall.set_managers(fw_manager, ws_manager)

# ── Include API routers ──────────────────────────────────────────────
app.include_router(routes_auth.router)
app.include_router(routes_alerts.router)
app.include_router(routes_firewall.router)
app.include_router(routes_stats.router)

# ── Mount static files ───────────────────────────────────────────────
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ── Serve frontend pages ─────────────────────────────────────────────

@app.get("/")
async def serve_dashboard():
    """Serve the main dashboard page."""
    return FileResponse(os.path.join(static_dir, "pages", "index.html"))

@app.get("/login")
async def serve_login():
    """Serve the login page."""
    return FileResponse(os.path.join(static_dir, "pages", "login.html"))

@app.get("/blocked")
async def serve_blocked():
    """Serve the blocked IPs management page."""
    return FileResponse(os.path.join(static_dir, "pages", "blocked.html"))

@app.get("/rules")
async def serve_rules():
    """Serve the firewall rules editor page."""
    return FileResponse(os.path.join(static_dir, "pages", "rules.html"))


# ══════════════════════════════════════════════════════════════════════
#  Run directly (for development)
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
