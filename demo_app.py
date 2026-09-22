"""지인 공유용 데모 실행 파일.

실행: python -m streamlit run demo_app.py

이 파일은 app.py의 화면과 기능을 그대로 사용하면서 데이터 저장소만
로컬 SQLite로 바꿉니다. 실제 고객 발주용으로 사용하지 마세요.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import app as core


DEMO_DB = Path(__file__).resolve().with_name("ktg_demo.db")
DEMO_ADMIN_ID = os.getenv("KTG_ADMIN_ID", "대표").strip() or "대표"
DEMO_ADMIN_PASSWORD = os.getenv("KTG_ADMIN_PASSWORD", "1234")


class SQLiteCompatConnection:
    """app.py의 PostgreSQL 쿼리를 SQLite 형식으로 바꿔 실행합니다."""

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        query = sql.replace("%s", "?").replace(" FOR UPDATE", "")
        return self.connection.execute(query, params)

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        self.connection.close()


@contextmanager
def demo_db_connection() -> Iterator[SQLiteCompatConnection]:
    raw = sqlite3.connect(DEMO_DB, timeout=15, check_same_thread=False)
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA foreign_keys = ON")
    raw.execute("PRAGMA journal_mode = WAL")
    conn = SQLiteCompatConnection(raw)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_demo_db() -> bool:
    with demo_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                usertype TEXT DEFAULT '개인 고객 (B2C)',
                phone TEXT DEFAULT '',
                company_name TEXT DEFAULT '',
                role TEXT DEFAULT 'customer',
                created_at TEXT DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                category TEXT NOT NULL,
                material TEXT DEFAULT '',
                details TEXT DEFAULT '',
                quantity INTEGER DEFAULT 1,
                cost REAL DEFAULT 0,
                date TEXT DEFAULT '',
                width_mm REAL,
                length_mm REAL,
                thickness_mm REAL,
                diameter_mm REAL,
                hole_count INTEGER DEFAULT 0,
                unit_weight_kg REAL DEFAULT 0,
                request_note TEXT DEFAULT '',
                project_name TEXT DEFAULT '',
                desired_date TEXT DEFAULT '',
                tolerance TEXT DEFAULT '',
                surface_finish TEXT DEFAULT '',
                admin_reply TEXT DEFAULT '',
                quoted_cost REAL DEFAULT 0,
                quoted_delivery TEXT DEFAULT '',
                quote_valid_until TEXT DEFAULT '',
                quote_accepted_at TEXT DEFAULT '',
                status TEXT DEFAULT '접수',
                payment_method TEXT DEFAULT '카드',
                attachment_name TEXT DEFAULT '',
                attachment_mime TEXT DEFAULT '',
                attachment_data BLOB,
                updated_at TEXT DEFAULT '',
                FOREIGN KEY(username) REFERENCES users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pricing_settings (
                setting_key TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT NOT NULL,
                updated_at TEXT DEFAULT ''
            )
            """
        )
        # 기존 데모 파일도 삭제하지 않고 필요한 열만 더합니다.
        for table, columns in {
            "users": {"company_name": "TEXT DEFAULT ''"},
            "orders": {
                "project_name": "TEXT DEFAULT ''", "desired_date": "TEXT DEFAULT ''",
                "tolerance": "TEXT DEFAULT ''", "surface_finish": "TEXT DEFAULT ''",
                "quoted_delivery": "TEXT DEFAULT ''", "quote_valid_until": "TEXT DEFAULT ''",
                "quote_accepted_at": "TEXT DEFAULT ''",
            },
        }.items():
            existing_columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for name, definition in columns.items():
                if name not in existing_columns:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        for setting_key, setting in core.PRICING_DEFAULTS.items():
            conn.execute(
                """
                INSERT OR IGNORE INTO pricing_settings
                    (setting_key, label, value, unit, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    setting_key,
                    setting["label"],
                    setting["value"],
                    setting["unit"],
                    core.now_text(),
                ),
            )
        existing = conn.execute(
            "SELECT username FROM users WHERE username=?", (DEMO_ADMIN_ID,)
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO users
                    (username, password, usertype, phone, role, created_at)
                VALUES (?, ?, '대표 관리자', '', 'admin', ?)
                """,
                (
                    DEMO_ADMIN_ID,
                    core.hash_password(DEMO_ADMIN_PASSWORD),
                    core.now_text(),
                ),
            )
        else:
            conn.execute(
                "UPDATE users SET role='admin', usertype='대표 관리자' WHERE username=?",
                (DEMO_ADMIN_ID,),
            )
    return True


def register_demo_user(
    username: str, password: str, usertype: str, phone: str, company_name: str = ""
) -> tuple[bool, str]:
    username = username.strip()
    normalized_phone = core.normalize_phone(phone)
    if not core.re.fullmatch(r"[A-Za-z0-9가-힣_.-]{2,30}", username):
        return False, "아이디는 2~30자의 한글, 영문, 숫자, 밑줄, 마침표, 하이픈만 사용할 수 있습니다."
    if username == DEMO_ADMIN_ID:
        return False, "대표 계정 아이디는 사용할 수 없습니다."
    if len(password) < 8:
        return False, "비밀번호는 8자 이상 입력해 주세요."
    if normalized_phone is None:
        return False, "연락 가능한 휴대폰 번호를 정확히 입력해 주세요."
    try:
        with demo_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO users
                    (username, password, usertype, phone, company_name, role, created_at)
                VALUES (?, ?, ?, ?, ?, 'customer', ?)
                """,
                (
                    username,
                    core.hash_password(password),
                    usertype,
                    normalized_phone,
                    company_name.strip()[:100],
                    core.now_text(),
                ),
            )
        return True, "회원가입이 완료되었습니다. 왼쪽에서 로그인해 주세요."
    except sqlite3.IntegrityError:
        return False, "이미 사용 중인 아이디입니다."


def create_demo_order(values: dict[str, Any]) -> int:
    columns = [
        "username",
        "category",
        "material",
        "details",
        "quantity",
        "cost",
        "date",
        "width_mm",
        "length_mm",
        "thickness_mm",
        "diameter_mm",
        "hole_count",
        "unit_weight_kg",
        "request_note",
        "project_name",
        "desired_date",
        "tolerance",
        "surface_finish",
        "admin_reply",
        "quoted_cost",
        "quoted_delivery",
        "quote_valid_until",
        "quote_accepted_at",
        "status",
        "payment_method",
        "attachment_name",
        "attachment_mime",
        "attachment_data",
        "updated_at",
    ]
    payload = {name: values.get(name) for name in columns}
    payload.update(
        {
            "date": values.get("date") or core.now_text(),
            "admin_reply": values.get("admin_reply") or "",
            "quoted_cost": values.get("quoted_cost") or 0,
            "quoted_delivery": values.get("quoted_delivery") or "",
            "quote_valid_until": values.get("quote_valid_until") or "",
            "quote_accepted_at": values.get("quote_accepted_at") or "",
            "status": values.get("status") or "접수",
            "payment_method": values.get("payment_method") or "카드",
            "updated_at": core.now_text(),
        }
    )
    placeholders = ", ".join("?" for _ in columns)
    with demo_db_connection() as conn:
        cursor = conn.execute(
            f"INSERT INTO orders ({', '.join(columns)}) VALUES ({placeholders})",
            tuple(payload[name] for name in columns),
        )
        return int(cursor.lastrowid)


# app.py가 사용하는 저장 함수와 설정만 데모용으로 교체합니다.
core.DATABASE_URL = "sqlite-demo-mode"
core.ADMIN_ID = DEMO_ADMIN_ID
core.ADMIN_PASSWORD = DEMO_ADMIN_PASSWORD
core.db_connection = demo_db_connection
core.init_db = init_demo_db
core.register_user = register_demo_user
core.create_order = create_demo_order


if __name__ == "__main__":
    core.main()
