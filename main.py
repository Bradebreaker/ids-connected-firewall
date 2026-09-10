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

import check_environment
check_environment.run_preflight_checks()

from fastapi import FastAPI, Request, Depends
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
from api.dependencies import get_current_user
from api.websocket_manager import WebSocketManager
from api import routes_auth, routes_alerts, routes_firewall, routes_stats, routes_generator, routes_report, routes_system
from sniffer.packet_event import (
    record_packet,
    get_recent_packets,
    get_recent_buffer_count,
    get_current_packet_count,
    reset_recent_packets,
)
from firewall.manager import FirewallManager
from firewall.scheduler import create_scheduler
from firewall.sync import reconcile
from decision.engine import DecisionEngine
from detection.signature import SignatureDetector
from detection.port_scan import PortScanDetector
from detection.brute_force import BruteForceDetector
from detection.syn_flood import SynFloodDetector
from detection.flood import FloodDetector

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

# Detection pipeline — five independent detectors
detectors = [
    SignatureDetector(),
    PortScanDetector(),
    BruteForceDetector(),
    SynFloodDetector(),
    FloodDetector(),
]


# ══════════════════════════════════════════════════════════════════════
#  Detection pipeline consumer
# ══════════════════════════════════════════════════════════════════════

async def detection_pipeline():
    """
    Consumes packets from the queue and runs them through all detectors.

    Order:
        1. Run all detectors independently
        2. If alert triggered, process through decision engine & associate alert_id
        3. Enrich packet with threat metadata
        4. Record in thread-safe bounded recent buffer (max 1000)
        5. Broadcast enriched traffic event over WebSocket
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
                            alert = await decision_engine.process_alert(alert_event, db)
                            if alert:
                                packet_data["alert_id"] = alert.id
                                # Ensure threat level is at least SUSPICIOUS, or MALICIOUS for HIGH/CRITICAL
                                if alert.severity in ["CRITICAL", "HIGH"]:
                                    packet_data["threat_level"] = "MALICIOUS"
                                elif packet_data.get("threat_level") != "MALICIOUS":
                                    packet_data["threat_level"] = "SUSPICIOUS"
                                packet_data["threat_type"] = alert.alert_type
                                packet_data["threat_detail"] = alert.description
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

        # 1. Record packet in bounded rolling buffer for page hydration
        record_packet(packet_data)

        # 2. Broadcast enriched traffic event over WebSocket
        ws_count = len(ws_manager._connections)
        logger.debug(
            "[TRAFFIC] Broadcast pkt #%s (%s %s -> %s) | Threat: %s | Alert: %s | Clients: %d",
            packet_data.get("packet_number"),
            packet_data.get("protocol"),
            packet_data.get("source_ip"),
            packet_data.get("dest_ip"),
            packet_data.get("threat_level"),
            packet_data.get("alert_id"),
            ws_count,
        )
        await ws_manager.broadcast({
            "type": "traffic",
            "data": packet_data
        })


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
app.state.packet_queue = packet_queue

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
routes_system.set_managers(fw_manager, ws_manager)

# ── Include API routers ──────────────────────────────────────────────
app.include_router(routes_auth.router)
app.include_router(routes_alerts.router)
app.include_router(routes_firewall.router)
app.include_router(routes_stats.router)
app.include_router(routes_generator.router)
app.include_router(routes_report.router)
app.include_router(routes_system.router)

# ── Live Traffic Buffer Hydration Endpoint ────────────────────────────
@app.get("/api/traffic/recent")
async def get_recent_traffic(
    limit: int = 200,
    _user: User = Depends(get_current_user),
):
    """
    Return recent packets from the in-memory bounded rolling buffer.
    Provides instant page hydration so full-page navigation preserves live history.
    """
    packets = get_recent_packets(limit=min(limit, 1000))
    return {
        "packets": packets,
        "buffer_count": get_recent_buffer_count(),
        "total_processed": get_current_packet_count(),
    }

@app.post("/api/traffic/reset")
async def reset_traffic_session(
    _user: User = Depends(get_current_user),
):
    """
    Safely reset the in-memory recent packet buffer for traffic demonstration.
    Does NOT delete database alerts, blocked IPs, firewall rules, or security events.
    """
    reset_recent_packets()
    return {
        "status": "ok",
        "message": "Traffic analyzer session buffer reset successfully.",
        "buffer_count": get_recent_buffer_count(),
    }

# ── Mount static files ───────────────────────────────────────────────
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ── Serve frontend pages ─────────────────────────────────────────────

@app.get("/")
@app.get("/index.html")
async def serve_dashboard():
    """Serve the SOC Command Center dashboard."""
    return FileResponse(os.path.join(static_dir, "pages", "index.html"))

@app.get("/login")
@app.get("/login.html")
async def serve_login():
    """Serve the SOC authentication gateway."""
    return FileResponse(os.path.join(static_dir, "pages", "login.html"))

@app.get("/traffic")
@app.get("/traffic.html")
async def serve_traffic():
    """Serve the Live Traffic Analyzer (Wireshark-style SOC viewer)."""
    return FileResponse(os.path.join(static_dir, "pages", "traffic.html"))

@app.get("/alerts")
@app.get("/alerts.html")
async def serve_alerts():
    """Serve the comprehensive alerts management page."""
    return FileResponse(os.path.join(static_dir, "pages", "alerts.html"))

@app.get("/blocked")
@app.get("/blocked-ips")
@app.get("/blocked-ips.html")
@app.get("/blocked.html")
async def serve_blocked():
    """Serve the blocked IPs management page."""
    target_file = os.path.join(static_dir, "pages", "blocked-ips.html")
    if not os.path.isfile(target_file):
        target_file = os.path.join(static_dir, "pages", "blocked.html")
    return FileResponse(target_file)

@app.get("/rules")
@app.get("/firewall-rules")
@app.get("/firewall-rules.html")
@app.get("/rules.html")
async def serve_rules():
    """Serve the firewall rules management page."""
    target_file = os.path.join(static_dir, "pages", "firewall-rules.html")
    if not os.path.isfile(target_file):
        target_file = os.path.join(static_dir, "pages", "rules.html")
    return FileResponse(target_file)

@app.get("/attacks")
@app.get("/attack-intelligence")
@app.get("/attack-intelligence.html")
@app.get("/attacks.html")
async def serve_attacks():
    """Serve the Attack Intelligence Center."""
    target_file = os.path.join(static_dir, "pages", "attack-intelligence.html")
    if not os.path.isfile(target_file):
        target_file = os.path.join(static_dir, "pages", "attacks.html")
    return FileResponse(target_file)

@app.get("/attack-details")
@app.get("/attack-details.html")
async def serve_attack_details():
    """Serve the attack detail analysis page."""
    return FileResponse(os.path.join(static_dir, "pages", "attack-details.html"))

@app.get("/reports")
@app.get("/reports.html")
async def serve_reports():
    """Serve the Security Report Center."""
    return FileResponse(os.path.join(static_dir, "pages", "reports.html"))

@app.get("/system-status")
@app.get("/system-status.html")
async def serve_system_status():
    """Serve the System Status and Health Observability page."""
    return FileResponse(os.path.join(static_dir, "pages", "system-status.html"))

@app.get("/attacks/{attack_name}.html")
@app.get("/attacks/{attack_name}")
async def serve_attack_page(attack_name: str):
    """Serve individual attack intelligence deep-dive pages."""
    clean_name = attack_name.replace(".html", "")
    page_path = os.path.join(static_dir, "pages", "attacks", f"{clean_name}.html")
    if os.path.isfile(page_path):
        return FileResponse(page_path)
    # Dynamic fallback to attack-details.html
    return FileResponse(os.path.join(static_dir, "pages", "attack-details.html"))


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
