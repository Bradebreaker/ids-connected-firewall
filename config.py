"""
config.py — Central Configuration for the IDS-Connected Firewall

All tuneable parameters (thresholds, secrets, whitelist IPs, paths) are
defined here so every module imports from one place.  Values can be
overridden by environment variables via pydantic-settings.
"""

from pydantic_settings import BaseSettings
from typing import List
import os
import sys


# Auto-detect platform — sniffer & iptables only work on Linux
IS_LINUX = sys.platform.startswith("linux")


class Settings(BaseSettings):
    """Application-wide settings loaded from environment or defaults."""

    # ── Application ───────────────────────────────────────────────
    APP_NAME: str = "IDS-Connected Firewall"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"
    LOG_DIR: str = "logs"

    # ── Database ──────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./ids_firewall.db"
    DB_BUSY_TIMEOUT_MS: int = 30000        # 30-second busy timeout for concurrent transactions
    DB_CACHE_SIZE_KB: int = 128000         # 128 MB RAM page cache for SQLite
    DB_MAX_PAGE_COUNT: int = 2147483646    # Maximum allowable SQLite pages (~2TB capacity limit)
    DB_MMAP_SIZE_BYTES: int = 30000000000  # 30 GB memory-mapped I/O support
    DB_MAX_ALERTS_RETENTION: int = 100000  # Retention safety cap to prevent table exhaustion
    DB_AUTO_CHECKPOINT_INTERVAL: int = 300 # Passive WAL checkpoint interval (seconds)

    # ── JWT Authentication ────────────────────────────────────────
    JWT_SECRET_KEY: str = "change-this-to-a-real-secret-key-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── Default Admin (created on first run) ──────────────────────
    DEFAULT_ADMIN_USER: str = "admin"
    DEFAULT_ADMIN_PASS: str = "admin123"

    # ── Whitelist — IPs that must NEVER be blocked ────────────────
    # Always includes localhost; add the management/SSH IP here.
    WHITELIST_IPS: List[str] = [
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    ]
    # Set this to the IP you SSH into the box from:
    MANAGEMENT_IP: str = ""

    # ── Packet Sniffer ────────────────────────────────────────────
    SNIFFER_INTERFACE: str = ""          # empty = sniff all interfaces
    SNIFFER_BPF_FILTER: str = "tcp or udp or icmp"
    SNIFFER_ENABLED: bool = IS_LINUX     # auto-disabled on Windows

    # ── Detection Thresholds ──────────────────────────────────────

    # Port scan: N distinct ports in WINDOW seconds
    PORT_SCAN_THRESHOLD: int = 15
    PORT_SCAN_WINDOW: int = 60           # seconds

    # Brute force: N attempts to sensitive ports in WINDOW seconds
    BRUTE_FORCE_THRESHOLD: int = 10
    BRUTE_FORCE_WINDOW: int = 120        # seconds
    BRUTE_FORCE_PORTS: List[int] = [21, 22, 23, 3389, 5900]

    # SYN flood: current rate > mean + N * stddev
    SYN_FLOOD_STDDEV_MULTIPLIER: float = 3.0
    SYN_FLOOD_WINDOW: int = 30           # seconds
    SYN_FLOOD_MIN_PACKETS: int = 50      # ignore until baseline is built

    # Severity scoring — auto-block threshold
    AUTO_BLOCK_MIN_SEVERITY: str = "medium"   # "low", "medium", "high"

    # ── Firewall ──────────────────────────────────────────────────
    IPTABLES_CHAIN: str = "IDS_FIREWALL"
    TEMP_BLOCK_TTL_SECONDS: int = 1800   # 30 minutes default
    FIREWALL_SYNC_INTERVAL: int = 300    # reconcile every 5 min
    BLOCK_EXPIRY_CHECK_INTERVAL: int = 60  # check expiry every 60s

    # ── Rate Limiting ─────────────────────────────────────────────
    RATE_LIMIT_DEFAULT: str = "60/minute"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Singleton settings instance used throughout the application
settings = Settings()

# Ensure management IP is in the whitelist
if settings.MANAGEMENT_IP and settings.MANAGEMENT_IP not in settings.WHITELIST_IPS:
    settings.WHITELIST_IPS.append(settings.MANAGEMENT_IP)

# Create log directory
os.makedirs(settings.LOG_DIR, exist_ok=True)
