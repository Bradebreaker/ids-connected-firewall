"""
db/database.py — Async SQLAlchemy engine and session factory for SQLite.

Uses aiosqlite as the async driver.  The `get_db` dependency yields a
session that auto-closes after each request.
"""

import logging
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from config import settings

logger = logging.getLogger("ids.database")

# ── Async engine ──────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    # Configure SQLite timeout to allow concurrent transactions to resolve naturally:
    connect_args={
        "check_same_thread": False,
        "timeout": float(settings.DB_BUSY_TIMEOUT_MS) / 1000.0,
    },
)

# ── Connection-level PRAGMA configuration ────────────────────────────────
@event.listens_for(engine.sync_engine, "connect")
def configure_sqlite_connection(dbapi_connection, connection_record):
    """
    Apply connection-level PRAGMAs to every SQLite connection in the pool.
    Ensures optimal page caching, busy timeout, memory temp store, and mmap.
    """
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute(f"PRAGMA busy_timeout = {settings.DB_BUSY_TIMEOUT_MS};")
        cursor.execute("PRAGMA synchronous = NORMAL;")
        cursor.execute(f"PRAGMA cache_size = -{settings.DB_CACHE_SIZE_KB};")
        cursor.execute("PRAGMA temp_store = MEMORY;")
        cursor.execute(f"PRAGMA mmap_size = {settings.DB_MMAP_SIZE_BYTES};")
        cursor.close()
    except Exception as e:
        logger.warning("Failed to configure connection PRAGMAs: %s", e)

# ── Session factory ───────────────────────────────────────────────────────
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── Declarative base ─────────────────────────────────────────────────────
class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


async def init_db():
    """
    Initialize SQLite pragmas (WAL mode, cache, timeouts) and ensure
    all tables exist without modifying or dropping existing records.
    Validates returned PRAGMA values and logs the active configuration.
    """
    async with engine.begin() as conn:
        # 1. Enable WAL mode on the database file
        try:
            res_wal = await conn.execute(text("PRAGMA journal_mode = WAL;"))
            journal_mode = res_wal.scalar()
        except Exception as e:
            journal_mode = f"ERROR: {e}"
            logger.warning("Failed to enable WAL mode: %s", e)

        # 2. Configure & validate storage & performance pragmas
        try:
            await conn.execute(text("PRAGMA synchronous = NORMAL;"))
            await conn.execute(text(f"PRAGMA busy_timeout = {settings.DB_BUSY_TIMEOUT_MS};"))
            await conn.execute(text(f"PRAGMA cache_size = -{settings.DB_CACHE_SIZE_KB};"))
            await conn.execute(text("PRAGMA temp_store = MEMORY;"))
            await conn.execute(text(f"PRAGMA mmap_size = {settings.DB_MMAP_SIZE_BYTES};"))
            await conn.execute(text(f"PRAGMA max_page_count = {settings.DB_MAX_PAGE_COUNT};"))

            # Query and log actual returned values from SQLite engine
            q_sync = await conn.execute(text("PRAGMA synchronous;"))
            sync_val = q_sync.scalar()

            q_timeout = await conn.execute(text("PRAGMA busy_timeout;"))
            timeout_val = q_timeout.scalar()

            q_cache = await conn.execute(text("PRAGMA cache_size;"))
            cache_val = q_cache.scalar()

            q_temp = await conn.execute(text("PRAGMA temp_store;"))
            temp_val = q_temp.scalar()

            q_mmap = await conn.execute(text("PRAGMA mmap_size;"))
            mmap_val = q_mmap.scalar()

            q_pages = await conn.execute(text("PRAGMA max_page_count;"))
            pages_val = q_pages.scalar()

            logger.info(
                "SQLite PRAGMAs validated: journal_mode=%s, synchronous=%s, "
                "busy_timeout=%sms, cache_size=%s, temp_store=%s, mmap_size=%s bytes, max_page_count=%s",
                journal_mode, sync_val, timeout_val, cache_val, temp_val, mmap_val, pages_val
            )
        except Exception as e:
            logger.warning("Error reading SQLite PRAGMAs: %s", e)

        # 3. Create tables if not already existing (safe against existing data)
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields a DB session per request."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
