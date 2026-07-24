from __future__ import annotations

import os
import secrets
import sqlite3
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .security import hash_password, validate_password


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = ROOT / "instance" / "market.db"
REPORT_THRESHOLD = 3
INITIAL_BALANCE = 0
DEMO_BALANCE = 100_000


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def database_path() -> Path:
    return Path(os.environ.get("MARKET_DB_PATH", DEFAULT_DB_PATH)).resolve()


def set_private_permissions(path: Path, mode: int) -> bool:
    try:
        path.chmod(mode)
        return has_private_permissions(path)
    except OSError:
        return False


def has_private_permissions(path: Path) -> bool:
    try:
        return (path.stat().st_mode & 0o077) == 0
    except OSError:
        return False


def connect(path: Path | None = None) -> sqlite3.Connection:
    target = path or database_path()
    parent_created = not target.parent.exists()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent_created:
        set_private_permissions(target.parent, 0o700)
    connection = sqlite3.connect(target, timeout=5)
    set_private_permissions(target, 0o600)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    bio TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price INTEGER NOT NULL CHECK (price >= 0),
    image_path TEXT,
    seller_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'blocked', 'sold', 'deleted')),
    report_count INTEGER NOT NULL DEFAULT 0 CHECK (report_count >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER REFERENCES users(id),
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL REFERENCES users(id),
    target_type TEXT NOT NULL CHECK (target_type IN ('user', 'product')),
    target_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    created_at TEXT NOT NULL,
    UNIQUE (reporter_id, target_type, target_id)
);

CREATE TABLE IF NOT EXISTS transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    amount INTEGER NOT NULL CHECK (amount > 0),
    memo TEXT NOT NULL DEFAULT '',
    request_token_hash TEXT,
    created_at TEXT NOT NULL,
    CHECK (sender_id <> recipient_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id INTEGER,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS request_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_products_status_created
    ON products(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_products_seller
    ON products(seller_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_global
    ON messages(recipient_id, id);
CREATE INDEX IF NOT EXISTS idx_messages_direct
    ON messages(sender_id, recipient_id, id);
CREATE INDEX IF NOT EXISTS idx_reports_target
    ON reports(target_type, target_id, status);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry
    ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_request_events_lookup
    ON request_events(event_type, key_hash, created_at);
"""


def init_database(path: Path | None = None) -> None:
    connection = connect(path)
    try:
        connection.executescript(SCHEMA)
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(transfers)").fetchall()
        }
        if "request_token_hash" not in columns:
            connection.execute(
                "ALTER TABLE transfers ADD COLUMN request_token_hash TEXT"
            )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_transfers_request_token
            ON transfers(request_token_hash)
            WHERE request_token_hash IS NOT NULL
            """
        )
        connection.commit()
    finally:
        connection.close()


def audit(
    connection: sqlite3.Connection,
    actor_id: int | None,
    action: str,
    target_type: str,
    target_id: int | None,
    detail: str = "",
) -> None:
    connection.execute(
        """
        INSERT INTO audit_logs(actor_id, action, target_type, target_id, detail, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (actor_id, action, target_type, target_id, detail[:500], utc_now()),
    )


def allow_action(
    event_type: str,
    key: str,
    limit: int,
    window_seconds: int,
    path: Path | None = None,
) -> bool:
    """Persist a bounded request window so limits survive restarts."""
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    now = datetime.now(UTC)
    cutoff = (now - timedelta(seconds=window_seconds)).isoformat(timespec="seconds")
    cleanup_cutoff = (now - timedelta(days=7)).isoformat(timespec="seconds")
    connection = connect(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM request_events WHERE created_at <= ?", (cleanup_cutoff,)
        )
        count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_events
            WHERE event_type = ? AND key_hash = ? AND created_at > ?
            """,
            (event_type, key_hash, cutoff),
        ).fetchone()["count"]
        if count >= limit:
            connection.commit()
            return False
        connection.execute(
            """
            INSERT INTO request_events(event_type, key_hash, created_at)
            VALUES (?, ?, ?)
            """,
            (event_type, key_hash, now.isoformat(timespec="seconds")),
        )
        connection.commit()
        return True
    finally:
        connection.close()


def ensure_admin(
    path: Path | None = None,
    *,
    require_configured: bool = False,
) -> tuple[str, str] | None:
    connection = connect(path)
    try:
        existing = connection.execute(
            "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()
        if existing:
            return None

        username = os.environ.get("ADMIN_USERNAME", "admin").strip().lower()
        configured = os.environ.get("ADMIN_PASSWORD")
        if require_configured and (
            not configured or validate_password(configured, username)
        ):
            raise ValueError(
                "운영 모드에서 최초 관리자를 만들려면 보안 정책을 만족하는 "
                "ADMIN_PASSWORD가 필요합니다."
            )
        password = (
            configured
            if configured and not validate_password(configured, username)
            else secrets.token_urlsafe(14)
        )
        connection.execute(
            """
            INSERT INTO users(
                username, display_name, password_hash, bio, role, balance, created_at
            ) VALUES (?, ?, ?, ?, 'admin', ?, ?)
            """,
            (
                username,
                "운영자",
                hash_password(password),
                "되살림 마켓 운영자입니다.",
                INITIAL_BALANCE,
                utc_now(),
            ),
        )
        connection.commit()
        return username, password
    finally:
        connection.close()


def seed_demo(path: Path | None = None) -> tuple[str, str] | None:
    connection = connect(path)
    try:
        existing = connection.execute(
            "SELECT id FROM users WHERE username = 'demo_seller'"
        ).fetchone()
        if existing:
            return None

        now = (datetime.now(UTC) - timedelta(days=7)).isoformat(timespec="seconds")
        configured = os.environ.get("DEMO_PASSWORD")
        demo_password_plain = (
            configured if configured and len(configured) >= 12 else secrets.token_urlsafe(14)
        )
        demo_password = hash_password(demo_password_plain)
        seller_id = connection.execute(
            """
            INSERT INTO users(
                username, display_name, password_hash, bio, balance, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "demo_seller",
                "정리하는 민서",
                demo_password,
                "오래 쓰고 다시 건네는 물건을 좋아해요.",
                DEMO_BALANCE,
                now,
            ),
        ).lastrowid
        buyer_id = connection.execute(
            """
            INSERT INTO users(
                username, display_name, password_hash, bio, balance, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "demo_buyer",
                "동네 수집가 준",
                demo_password,
                "필요한 만큼만 사고 오래 사용합니다.",
                DEMO_BALANCE,
                now,
            ),
        ).lastrowid
        demo_products = [
            (
                "필름 카메라",
                "작동 확인을 마친 35mm 필름 카메라입니다. 생활 흠집이 조금 있습니다.",
                78_000,
                "/static/images/camera.svg",
            ),
            (
                "원목 스툴",
                "작은 화분이나 책을 올려두기 좋은 단단한 원목 스툴입니다.",
                32_000,
                "/static/images/stool.svg",
            ),
            (
                "여행용 백팩",
                "노트북 수납 공간이 있고 가볍게 세탁한 24L 백팩입니다.",
                45_000,
                "/static/images/backpack.svg",
            ),
        ]
        for name, description, price, image_path in demo_products:
            connection.execute(
                """
                INSERT INTO products(
                    name, description, price, image_path, seller_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (name, description, price, image_path, seller_id, now, now),
            )
        connection.execute(
            """
            INSERT INTO messages(sender_id, recipient_id, body, created_at)
            VALUES (?, NULL, ?, ?), (?, NULL, ?, ?)
            """,
            (
                seller_id,
                "안녕하세요! 물건 상태가 궁금하면 편하게 물어보세요.",
                now,
                buyer_id,
                "반가워요. 오래 쓸 물건을 찾아보고 있어요.",
                now,
            ),
        )
        connection.commit()
        return "demo_seller / demo_buyer", demo_password_plain
    finally:
        connection.close()
