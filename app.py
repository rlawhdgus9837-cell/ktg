from __future__ import annotations

import hashlib
import hmac
import html
import csv
import io
import json
import math
import os
import re
import secrets
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
from zoneinfo import ZoneInfo

import psycopg
from psycopg import errors
from psycopg.rows import dict_row
import streamlit as st
import streamlit.components.v1 as components


# -----------------------------------------------------------------------------
# 기본 설정
# -----------------------------------------------------------------------------
APP_TITLE = "KTG 가공 견적 프로그램"
KOREA_TZ = ZoneInfo("Asia/Seoul")

# Streamlit Community Cloud의 Secrets에 반드시 등록해야 합니다.
# 값이 없으면 로컬 SQLite로 대체하지 않고 실행을 중단하여 데이터 유실을 막습니다.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
ADMIN_ID = os.getenv("KTG_ADMIN_ID", "").strip()
ADMIN_PASSWORD = os.getenv("KTG_ADMIN_PASSWORD", "")

MATERIALS = {
    "알루미늄 6061": {"density": 2.70, "price_key": "material_aluminum_6061"},
    "스틸 SS400": {"density": 7.85, "price_key": "material_steel_ss400"},
    "스테인리스 304": {"density": 7.93, "price_key": "material_stainless_304"},
    "스테인리스 316": {"density": 7.98, "price_key": "material_stainless_316"},
    "황동": {"density": 8.50, "price_key": "material_brass"},
}

# 대표 관리자가 화면에서 바꿀 수 있는 예상 견적 기준값입니다.
PRICING_DEFAULTS = {
    "milling_base": {"label": "밀링 기본 가공비", "value": 15_000.0, "unit": "원/주문"},
    "milling_width": {"label": "밀링 가로 단가", "value": 35.0, "unit": "원/mm"},
    "milling_length": {"label": "밀링 세로 단가", "value": 35.0, "unit": "원/mm"},
    "milling_thickness": {"label": "밀링 두께 단가", "value": 120.0, "unit": "원/mm"},
    "lathe_base": {"label": "선반 기본 가공비", "value": 15_000.0, "unit": "원/주문"},
    "lathe_diameter": {"label": "선반 지름 단가", "value": 90.0, "unit": "원/mm"},
    "lathe_length": {"label": "선반 길이 단가", "value": 45.0, "unit": "원/mm"},
    "hole_each": {"label": "홀 가공 단가", "value": 1_000.0, "unit": "원/개"},
    "material_aluminum_6061": {"label": "알루미늄 6061 재료 단가", "value": 5_000.0, "unit": "원/kg"},
    "material_steel_ss400": {"label": "스틸 SS400 재료 단가", "value": 2_000.0, "unit": "원/kg"},
    "material_stainless_304": {"label": "스테인리스 304 재료 단가", "value": 5_000.0, "unit": "원/kg"},
    "material_stainless_316": {"label": "스테인리스 316 재료 단가", "value": 6_000.0, "unit": "원/kg"},
    "material_brass": {"label": "황동 재료 단가", "value": 9_000.0, "unit": "원/kg"},
}

ORDER_STATUSES = [
    "접수",
    "견적 검토",
    "견적 제안",
    "결제 대기",
    "가공 준비",
    "가공 시작",
    "가공 완료",
    "포장",
    "출하",
]

CATEGORY_LABELS = {
    "milling": "MCT(밀링)",
    "lathe": "CNC(선반)",
    "drawing": "기타 도면 첨부",
    # 이전 버전의 분류명도 그대로 표시합니다.
    "판재(밀링)": "MCT(밀링)",
    "원통(선반)": "CNC(선반)",
    "도면첨부": "기타 도면 첨부",
}


# -----------------------------------------------------------------------------
# 영구 PostgreSQL 데이터베이스
# -----------------------------------------------------------------------------
@contextmanager
def db_connection() -> Iterator[psycopg.Connection]:
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL이 설정되지 않았습니다.")
    conn = psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=12,
        sslmode="require",
    )
    # Supabase Transaction pooler에서도 작동하도록 서버 측 prepared statement를 끕니다.
    conn.prepare_threshold = None
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), 200_000
    ).hex()
    return f"pbkdf2_sha256$200000${salt}${digest}"


def verify_password(password: str, stored_password: str | None) -> bool:
    if not stored_password:
        return False
    if not stored_password.startswith("pbkdf2_sha256$"):
        # 이전 버전에서 평문으로 저장한 비밀번호와의 호환
        return hmac.compare_digest(password, stored_password)
    try:
        _, rounds_text, salt, expected = stored_password.split("$", 3)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            int(rounds_text),
        ).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


@st.cache_resource(show_spinner=False)
def init_db() -> bool:
    with db_connection() as conn:
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
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS usertype TEXT DEFAULT '개인 고객 (B2C)'")
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT ''")
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS company_name TEXT DEFAULT ''")
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'customer'")
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TEXT DEFAULT ''")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id BIGSERIAL PRIMARY KEY,
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
                attachment_data BYTEA,
                updated_at TEXT DEFAULT '',
                FOREIGN KEY(username) REFERENCES users(username)
            )
            """
        )
        for statement in [
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS width_mm REAL",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS length_mm REAL",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS thickness_mm REAL",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS diameter_mm REAL",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS hole_count INTEGER DEFAULT 0",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS unit_weight_kg REAL DEFAULT 0",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS request_note TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS project_name TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS desired_date TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS tolerance TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS surface_finish TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS admin_reply TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS quoted_cost REAL DEFAULT 0",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS quoted_delivery TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS quote_valid_until TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS quote_accepted_at TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS status TEXT DEFAULT '접수'",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT DEFAULT '카드'",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS attachment_name TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS attachment_mime TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS attachment_data BYTEA",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS updated_at TEXT DEFAULT ''",
        ]:
            conn.execute(statement)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_username ON orders(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_date ON orders(date DESC)")
        conn.execute("UPDATE users SET role='customer' WHERE role IS NULL OR role='' ")
        conn.execute("UPDATE users SET phone='' WHERE phone IS NULL")
        conn.execute("UPDATE orders SET status='접수' WHERE status IS NULL OR status='' ")
        conn.execute("UPDATE orders SET admin_reply='' WHERE admin_reply IS NULL")
        conn.execute("UPDATE orders SET request_note='' WHERE request_note IS NULL")

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
        for setting_key, setting in PRICING_DEFAULTS.items():
            conn.execute(
                """
                INSERT INTO pricing_settings
                    (setting_key, label, value, unit, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (setting_key) DO NOTHING
                """,
                (
                    setting_key,
                    setting["label"],
                    setting["value"],
                    setting["unit"],
                    now_text(),
                ),
            )

        conn.execute(
            """
            INSERT INTO users
                (username, password, usertype, phone, role, created_at)
            VALUES (%s, %s, %s, '', 'admin', %s)
            ON CONFLICT (username) DO UPDATE
            SET role='admin', usertype='대표 관리자'
            """,
            (
                ADMIN_ID,
                hash_password(ADMIN_PASSWORD),
                "대표 관리자",
                now_text(),
            ),
        )
    return True


def now_text() -> str:
    return datetime.now(KOREA_TZ).strftime("%Y-%m-%d %H:%M:%S")


def normalize_phone(value: str) -> str | None:
    digits = re.sub(r"\D", "", value or "")
    if re.fullmatch(r"01[016789]\d{7,8}", digits):
        if len(digits) == 11:
            return f"{digits[:3]}-{digits[3:7]}-{digits[7:]}"
        return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    return None


def register_user(username: str, password: str, usertype: str, phone: str, company_name: str = "") -> tuple[bool, str]:
    username = username.strip()
    normalized_phone = normalize_phone(phone)
    if not re.fullmatch(r"[A-Za-z0-9가-힣_.-]{2,30}", username):
        return False, "아이디는 2~30자의 한글, 영문, 숫자, 밑줄, 마침표, 하이픈만 사용할 수 있습니다."
    if username == ADMIN_ID:
        return False, "대표 계정 아이디는 사용할 수 없습니다."
    if len(password) < 8:
        return False, "비밀번호는 8자 이상 입력해 주세요."
    if normalized_phone is None:
        return False, "연락 가능한 휴대폰 번호를 정확히 입력해 주세요."
    try:
        with db_connection() as conn:
            conn.execute(
                """
                INSERT INTO users
                    (username, password, usertype, phone, company_name, role, created_at)
                VALUES (%s, %s, %s, %s, %s, 'customer', %s)
                """,
                (username, hash_password(password), usertype, normalized_phone, company_name.strip()[:100], now_text()),
            )
        return True, "회원가입이 완료되었습니다. 왼쪽에서 로그인해 주세요."
    except errors.UniqueViolation:
        return False, "이미 사용 중인 아이디입니다."


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    username = username.strip()
    with db_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username=%s", (username,)
        ).fetchone()
        if user is None or not verify_password(password, user["password"]):
            return None
        # 기존 평문 비밀번호는 로그인 성공 시 안전한 형식으로 교체합니다.
        if not str(user["password"]).startswith("pbkdf2_sha256$"):
            conn.execute(
                "UPDATE users SET password=%s WHERE username=%s",
                (hash_password(password), username),
            )
        return user


def update_phone(username: str, phone: str) -> tuple[bool, str]:
    normalized = normalize_phone(phone)
    if normalized is None:
        return False, "휴대폰 번호를 정확히 입력해 주세요."
    with db_connection() as conn:
        conn.execute("UPDATE users SET phone=%s WHERE username=%s", (normalized, username))
    return True, normalized


def update_company_name(username: str, company_name: str) -> str:
    company_name = company_name.strip()[:100]
    with db_connection() as conn:
        conn.execute("UPDATE users SET company_name=%s WHERE username=%s", (company_name, username))
    return company_name


def change_password(username: str, current: str, new: str) -> tuple[bool, str]:
    if len(new) < 8:
        return False, "새 비밀번호는 8자 이상 입력해 주세요."
    with db_connection() as conn:
        user = conn.execute(
            "SELECT password FROM users WHERE username=%s", (username,)
        ).fetchone()
        if user is None or not verify_password(current, user["password"]):
            return False, "현재 비밀번호가 일치하지 않습니다."
        conn.execute(
            "UPDATE users SET password=%s WHERE username=%s",
            (hash_password(new), username),
        )
    return True, "비밀번호를 변경했습니다."


def create_order(values: dict[str, Any]) -> int:
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
            "date": values.get("date") or now_text(),
            "admin_reply": values.get("admin_reply") or "",
            "quoted_cost": values.get("quoted_cost") or 0,
            "quoted_delivery": values.get("quoted_delivery") or "",
            "quote_valid_until": values.get("quote_valid_until") or "",
            "quote_accepted_at": values.get("quote_accepted_at") or "",
            "status": values.get("status") or "접수",
            "payment_method": values.get("payment_method") or "카드",
            "updated_at": now_text(),
        }
    )
    placeholders = ", ".join("%s" for _ in columns)
    with db_connection() as conn:
        row = conn.execute(
            f"INSERT INTO orders ({', '.join(columns)}) VALUES ({placeholders}) RETURNING id",
            tuple(payload[name] for name in columns),
        ).fetchone()
        return int(row["id"])


def get_orders(username: str | None = None) -> list[dict[str, Any]]:
    query = """
        SELECT o.*, u.phone, u.usertype, u.company_name
        FROM orders o
        LEFT JOIN users u ON u.username=o.username
    """
    params: tuple[Any, ...] = ()
    if username is not None:
        query += " WHERE o.username=%s"
        params = (username,)
    query += " ORDER BY o.id DESC"
    with db_connection() as conn:
        return conn.execute(query, params).fetchall()


def update_order_by_admin(
    order_id: int, status: str, quoted_cost: float, admin_reply: str,
    quoted_delivery: str = "", quote_valid_until: str = "",
) -> None:
    if status not in ORDER_STATUSES:
        raise ValueError("허용되지 않은 진행 상태입니다.")
    with db_connection() as conn:
        previous = conn.execute(
            "SELECT status, quoted_cost, quote_accepted_at FROM orders WHERE id=%s FOR UPDATE",
            (order_id,),
        ).fetchone()
        if previous is None:
            raise ValueError("발주를 찾지 못했습니다.")
        new_quote = max(0, float(quoted_cost))
        quote_changed = abs(float(previous["quoted_cost"] or 0) - new_quote) >= 0.5
        accepted = bool(previous["quote_accepted_at"])
        advanced = {"결제 대기", "가공 준비", "가공 시작", "가공 완료", "포장", "출하"}
        if accepted and quote_changed and previous["status"] in advanced:
            raise ValueError("고객이 수락한 견적은 진행 중에 수정할 수 없습니다. 고객에게 별도로 안내해 주세요.")
        if accepted and status not in advanced:
            raise ValueError("고객이 수락한 견적은 이전 검토 단계로 되돌릴 수 없습니다.")
        if status in advanced and not accepted and previous["status"] not in advanced:
            raise ValueError("고객이 견적을 확인한 뒤에 결제 대기·가공 단계로 변경할 수 있습니다.")
        if new_quote > 0 and (quote_changed or status == "견적 제안") and status not in advanced:
            status = "견적 제안"
        if status == "견적 제안" and new_quote <= 0:
            raise ValueError("견적 금액을 입력해 주세요.")
        conn.execute(
            """
            UPDATE orders
            SET status=%s, quoted_cost=%s, admin_reply=%s,
                quoted_delivery=%s, quote_valid_until=%s, quote_accepted_at=%s,
                updated_at=%s
            WHERE id=%s
            """,
            (status, new_quote, admin_reply.strip(), quoted_delivery.strip()[:100],
             quote_valid_until.strip(), "" if quote_changed else previous["quote_accepted_at"] or "",
             now_text(), order_id),
        )


def accept_quote(order_id: int, username: str) -> bool:
    """고객 본인만, 유효한 대표 견적을 한 번 승인할 수 있습니다."""
    with db_connection() as conn:
        row = conn.execute(
            """
            UPDATE orders
            SET status='결제 대기', quote_accepted_at=%s, updated_at=%s
            WHERE id=%s AND username=%s AND status='견적 제안'
              AND quoted_cost>0 AND (quote_valid_until='' OR quote_valid_until IS NULL OR quote_valid_until>=%s)
            RETURNING id
            """,
            (now_text(), now_text(), order_id, username, now_text()[:10]),
        ).fetchone()
        return row is not None


def get_pricing_settings() -> dict[str, float]:
    values = {
        setting_key: float(setting["value"])
        for setting_key, setting in PRICING_DEFAULTS.items()
    }
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT setting_key, value FROM pricing_settings"
        ).fetchall()
    for row in rows:
        if row["setting_key"] in values:
            values[row["setting_key"]] = float(row["value"])
    return values


def save_pricing_settings(values: dict[str, float]) -> None:
    with db_connection() as conn:
        for setting_key, value in values.items():
            if setting_key not in PRICING_DEFAULTS:
                continue
            conn.execute(
                """
                UPDATE pricing_settings
                SET value=%s, updated_at=%s
                WHERE setting_key=%s
                """,
                (max(0.0, float(value)), now_text(), setting_key),
            )


def process_machining(machine_type: str, material: str, operation_time: float) -> str:
    """이전 app.py에서 사용하던 함수와의 호환을 위한 처리 함수입니다."""
    if machine_type in {"Milling (밀링)", "MCT(밀링)"}:
        return f"밀링 작업이 {material} 소재로 {operation_time:g}시간 예약되었습니다."
    if machine_type in {"Lathe (선반)", "CNC(선반)"}:
        return f"선반 작업이 {material} 소재로 {operation_time:g}시간 예약되었습니다."
    return "지원하지 않는 기계 장비입니다."


# -----------------------------------------------------------------------------
# 화면 공통 요소
# -----------------------------------------------------------------------------
def inject_global_style() -> None:
    st.markdown(
        """
        <meta name="google" content="notranslate">
        <style>
        :root, html { color-scheme: only light !important; }
        html, body, .stApp, [class*="css"] {
            font-family: "Pretendard", "Noto Sans KR", "Malgun Gothic", sans-serif !important;
        }
        html, body, .stApp, [data-testid="stAppViewContainer"],
        [data-testid="stMain"], [data-testid="stMainBlockContainer"] {
            background: #f5f7fa !important;
            color: #293548 !important;
            color-scheme: only light !important;
        }
        .stApp p, .stApp label, .stApp small,
        .stApp [data-testid="stMarkdownContainer"],
        .stApp [data-testid="stMarkdownContainer"] p,
        .stApp [data-testid="stWidgetLabel"],
        .stApp [data-testid="stWidgetLabel"] p,
        .stApp [data-testid="stCaptionContainer"],
        .stApp [data-testid="stExpander"] summary,
        .stApp [role="radiogroup"] label,
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] span {
            color: #293548 !important;
            -webkit-text-fill-color: #293548 !important;
        }
        .stApp input, .stApp textarea {
            background: #ffffff !important;
            color: #293548 !important;
            -webkit-text-fill-color: #293548 !important;
            caret-color: #293548 !important;
        }
        .stApp input::placeholder, .stApp textarea::placeholder {
            color: #7b8797 !important;
            -webkit-text-fill-color: #7b8797 !important;
            opacity: 1 !important;
        }
        .stApp [data-baseweb="select"] > div,
        .stApp [data-baseweb="base-input"],
        .stApp [data-baseweb="input"] {
            background: #ffffff !important;
            color: #293548 !important;
        }
        .stApp [data-baseweb="select"] span,
        .stApp [data-baseweb="select"] div {
            color: #293548 !important;
            -webkit-text-fill-color: #293548 !important;
        }
        [data-testid="stHeader"], [data-testid="stToolbar"], #MainMenu, footer { display: none !important; }
        [data-testid="stHeaderActionElements"], a.anchor-link,
        h1 > a, h2 > a, h3 > a, h4 > a, h5 > a, h6 > a { display: none !important; }
        a { text-decoration: none !important; }
        .block-container { max-width: 1180px; padding-top: 2rem; padding-bottom: 4rem; }
        .app-title { font-size: 1.9rem; font-weight: 800; letter-spacing: -0.04em; color: #233f5a; }
        .app-title.centered { text-align: center; margin: .35rem 0 1rem; }
        .app-subtitle { color: #64748b; margin-top: .25rem; margin-bottom: 1.35rem; }
        .section-title { font-size: 1.22rem; font-weight: 750; color: #293548; margin: .2rem 0 1rem; }
        .top-bar {
            display: flex; align-items: center; justify-content: space-between; gap: 1rem;
            padding: .8rem 1rem; margin-bottom: 1rem; background: #ffffff;
            border: 1px solid #e2e8f0; border-radius: 12px;
        }
        .top-bar strong { color: #254f73; }
        .process-grid {
            display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .7rem;
            margin: .25rem 0 1.4rem;
        }
        .process-item {
            background: #ffffff; border: 1px solid #e2e8f0; border-radius: 11px;
            padding: .8rem .9rem; color: #435268; font-size: .9rem;
        }
        .process-item b { display: block; color: #254f73; margin-bottom: .2rem; }
        .process-item span { display: block; }
        .summary-grid {
            display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: .7rem; margin: .7rem 0 0;
        }
        .summary-item {
            background: #fff; border: 1px solid #e2e8f0; border-radius: 11px;
            padding: .8rem 1rem; min-width: 0;
        }
        .summary-item span { display: block; color: #64748b; font-size: .83rem; }
        .summary-item strong {
            display: block; margin-top: .25rem; color: #254f73;
            font-size: 1.18rem; overflow-wrap: anywhere;
        }
        .summary-total { border-color: #b6cadd; background: #f0f6fb; }
        .dashboard-grid {
            display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: .7rem; margin: .5rem 0 1rem;
        }
        .dashboard-item {
            background: #fff; border: 1px solid #e2e8f0; border-radius: 11px;
            padding: .75rem .95rem; min-width: 0;
        }
        .dashboard-item span { display: block; color: #64748b; font-size: .86rem; }
        .dashboard-item strong { color: #254f73; font-size: 1.4rem; }
        .mobile-only { display: none; }
        .soft-card {
            background: #ffffff; border: 1px solid #e2e8f0; border-radius: 14px;
            padding: 1.05rem 1.15rem; box-shadow: 0 4px 14px rgba(15, 23, 42, .04);
        }
        .notice-card {
            background: #f1f7ff; border: 1px solid #cfe2f7; border-radius: 12px;
            padding: .9rem 1rem; color: #34516f;
        }
        .muted { color: #64748b; font-size: .92rem; }
        .preview-title { font-size: 1.05rem; font-weight: 750; color: #293548; margin-bottom: .15rem; }
        .estimate-note {
            background: #fff; border: 1px solid #e2e8f0; border-radius: 11px;
            padding: .85rem 1rem; color: #566579; font-size: .88rem; margin-top: .7rem;
        }
        .auth-gate {
            background: #f3f8ff; border: 1px solid #cfe2f7; border-radius: 14px;
            padding: 1rem 1.1rem; margin: 1rem 0;
        }
        .money { font-size: 1.45rem; font-weight: 800; color: #254f73; }
        .status-row { display: flex; flex-wrap: wrap; gap: 7px; margin: .55rem 0 .25rem; }
        .status-step {
            padding: 5px 9px; border-radius: 999px; border: 1px solid #dbe3ed;
            background: #f8fafc; color: #8793a5; font-size: .78rem;
        }
        .status-step.done { background: #edf3f8; border-color: #c4d4e1; color: #254f73; }
        .status-step.current { background: #254f73; border-color: #254f73; color: #fff; font-weight: 700; }
        .stButton > button, .stDownloadButton > button {
            border-radius: 9px; min-height: 2.75rem; font-weight: 700;
            border: 1px solid #254f73; background: #254f73; color: #fff !important;
            -webkit-text-fill-color: #fff !important;
        }
        .stButton > button *, .stButton > button p, .stButton > button span,
        .stDownloadButton > button *, .stDownloadButton > button p, .stDownloadButton > button span {
            color: #fff !important; -webkit-text-fill-color: #fff !important;
        }
        .stButton > button:hover, .stDownloadButton > button:hover {
            border-color: #183b59; background: #183b59; color: #fff;
        }
        [data-testid="stButton"] button,
        [data-testid="stFormSubmitButton"] button,
        [data-testid="stDownloadButton"] button {
            border-color: #254f73 !important; background: #254f73 !important;
        }
        [data-testid="stButton"] button p,
        [data-testid="stButton"] button span,
        [data-testid="stFormSubmitButton"] button p,
        [data-testid="stFormSubmitButton"] button span,
        [data-testid="stDownloadButton"] button p,
        [data-testid="stDownloadButton"] button span {
            color: #ffffff !important; -webkit-text-fill-color: #ffffff !important;
        }
        .stApp [data-testid="stButton"] button [data-testid="stMarkdownContainer"],
        .stApp [data-testid="stButton"] button [data-testid="stMarkdownContainer"] p,
        .stApp [data-testid="stButton"] button [data-testid="stMarkdownContainer"] span,
        .stApp [data-testid="stFormSubmitButton"] button [data-testid="stMarkdownContainer"],
        .stApp [data-testid="stFormSubmitButton"] button [data-testid="stMarkdownContainer"] p,
        .stApp [data-testid="stFormSubmitButton"] button [data-testid="stMarkdownContainer"] span,
        .stApp button[data-testid^="stBaseButton"] [data-testid="stMarkdownContainer"],
        .stApp button[data-testid^="stBaseButton"] [data-testid="stMarkdownContainer"] p,
        .stApp button[data-testid^="stBaseButton"] [data-testid="stMarkdownContainer"] span {
            color: #ffffff !important;
            -webkit-text-fill-color: #ffffff !important;
        }
        [data-testid="stButton"] button:hover,
        [data-testid="stFormSubmitButton"] button:hover,
        [data-testid="stDownloadButton"] button:hover {
            border-color: #183b59 !important; background: #183b59 !important;
        }
        [data-testid="stButton"] button:disabled {
            border-color: #cbd5df !important;
            background: #e7ecf2 !important;
            cursor: not-allowed !important;
            opacity: 1 !important;
        }
        [data-testid="stButton"] button:disabled *,
        [data-testid="stButton"] button:disabled p,
        [data-testid="stButton"] button:disabled span {
            color: #7b8797 !important;
            -webkit-text-fill-color: #7b8797 !important;
        }
        [data-testid="stDialog"] > div,
        [data-testid="stDialog"] section,
        [data-testid="stDialog"] [role="dialog"] {
            background: #ffffff !important;
            color: #293548 !important;
            color-scheme: only light !important;
        }
        [data-testid="stForm"] { border: 1px solid #e2e8f0; border-radius: 14px; background: #fff; }
        [data-testid="stMetric"] { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: .8rem 1rem; }
        [data-testid="stExpander"] { background: #fff; border-color: #e2e8f0; border-radius: 12px; }
        [data-testid="stSidebar"] { background: #eef2f6 !important; border-right: 1px solid #dce3eb; }
        [data-testid="stFileUploaderDropzone"] { background: #f8fafc !important; border: 1px dashed #aab7c7; }
        [data-testid="stFileUploaderDropzone"] * {
            color: #293548 !important; -webkit-text-fill-color: #293548 !important;
        }
        @media (max-width: 768px) {
            .mobile-only { display: grid; }
            .st-key-desktop_estimate, .st-key-desktop_dashboard { display: none !important; }
            .block-container { padding: .8rem .85rem 2.5rem !important; }
            .app-title { font-size: 1.45rem; }
            .app-subtitle { font-size: .92rem; }
            .process-grid { grid-template-columns: minmax(0, 1fr); gap: 0; margin: .6rem 0 1rem; }
            .process-item {
                display: grid; grid-template-columns: minmax(112px, 38%) minmax(0, 1fr);
                align-items: center; gap: .5rem; border-radius: 0;
                border-bottom: 0; padding: .65rem .8rem; font-size: .82rem;
                line-height: 1.35; overflow-wrap: anywhere;
            }
            .process-item:first-child { border-radius: 11px 11px 0 0; }
            .process-item:last-child { border-bottom: 1px solid #e2e8f0; border-radius: 0 0 11px 11px; }
            .process-item b { margin: 0; font-size: .84rem; }
            .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .5rem; }
            .summary-item { padding: .7rem .8rem; }
            .summary-item strong { font-size: 1rem; }
            .summary-total { grid-column: 1 / -1; grid-row: 1; }
            .summary-total strong { font-size: 1.35rem; }
            .dashboard-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .5rem; }
            .dashboard-item { padding: .7rem .8rem; }
            .dashboard-item strong { font-size: 1.2rem; }
            .st-key-order_type [role="radiogroup"] {
                display: grid !important; grid-template-columns: 1fr !important; gap: .45rem !important;
            }
            .st-key-admin_top_menu [role="radiogroup"] {
                display: grid !important; grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
                gap: .45rem !important;
            }
            .st-key-order_type [role="radiogroup"] > label,
            .st-key-admin_top_menu [role="radiogroup"] > label {
                box-sizing: border-box; width: 100%; margin: 0;
                border: 1px solid #dce3eb; border-radius: 9px;
                background: #fff; padding: .45rem .7rem;
            }
            .top-bar { align-items: flex-start; flex-direction: column; }
            .stApp, .stApp p, .stApp label, .stApp span, .stApp div {
                color-scheme: only light !important;
            }
        }
        @media (prefers-color-scheme: dark) {
            html, body, .stApp, [data-testid="stAppViewContainer"],
            [data-testid="stMain"], [data-testid="stMainBlockContainer"] {
                background: #f5f7fa !important;
                color: #293548 !important;
                color-scheme: only light !important;
            }
            .stApp input, .stApp textarea,
            .stApp [data-baseweb="select"] > div,
            .stApp [data-baseweb="base-input"],
            .stApp [data-baseweb="input"] {
                background: #ffffff !important;
                color: #293548 !important;
                -webkit-text-fill-color: #293548 !important;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # 브라우저의 자동 번역 제안을 줄이기 위해 최상위 문서를 한국어/번역 제외로 지정합니다.
    components.html(
        """
        <script>
        try {
          const d = window.parent.document;
          d.documentElement.lang = "ko";
          d.documentElement.setAttribute("translate", "no");
          d.body.classList.add("notranslate");
          let meta = d.querySelector('meta[name="google"]');
          if (!meta) {
            meta = d.createElement("meta");
            meta.name = "google";
            d.head.appendChild(meta);
          }
          meta.content = "notranslate";
          let detection = d.querySelector('meta[name="format-detection"]');
          if (!detection) {
            detection = d.createElement("meta");
            detection.name = "format-detection";
            d.head.appendChild(detection);
          }
          detection.content = "telephone=no,email=no,address=no";
        } catch (e) {}
        </script>
        """,
        height=0,
    )
    theme_file = Path(__file__).with_name("site.css")
    if theme_file.is_file():
        st.markdown(f"<style>{theme_file.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def app_header(description: str = "", centered: bool = False) -> None:
    title_class = "app-title centered" if centered else "app-title"
    st.markdown(
        f'<div class="{title_class}">{html.escape(APP_TITLE)}</div>',
        unsafe_allow_html=True,
    )
    if description:
        st.markdown(
            f'<div class="app-subtitle">{html.escape(description)}</div>',
            unsafe_allow_html=True,
        )


def initialize_session() -> None:
    defaults = {
        "logged_in": False,
        "username": "",
        "role": "",
        "phone": "",
        "company_name": "",
        "flash": "",
        "pending_order": None,
        "show_order_auth": False,
        "auth_alert": "",
        "auth_alert_nonce": 0,
        "customer_page": "새 견적",
        "customer_last_page": "새 견적",
        "customer_previous_page": "새 견적",
        "customer_has_history": False,
        "admin_top_menu": "전체 주문 관리",
        "admin_last_page": "전체 주문 관리",
        "admin_previous_page": "전체 주문 관리",
        "admin_has_history": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def logout() -> None:
    for key in [
        "logged_in",
        "username",
        "role",
        "phone",
        "company_name",
        "flash",
        "pending_order",
        "show_order_auth",
        "auth_alert",
        "auth_alert_nonce",
        "customer_page",
        "customer_last_page",
        "customer_previous_page",
        "customer_has_history",
        "admin_top_menu",
        "admin_last_page",
        "admin_previous_page",
        "admin_has_history",
    ]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()


def set_login_session(user: dict[str, Any]) -> None:
    st.session_state.logged_in = True
    st.session_state.username = user["username"]
    st.session_state.role = user["role"] or "customer"
    st.session_state.phone = user["phone"] or ""
    st.session_state.company_name = user["company_name"] or ""


def remember_navigation(scope: str, default_page: str) -> None:
    """라디오 메뉴 변경 전 화면을 기억해 사이드 이전 버튼에 연결합니다."""
    page_key = "admin_top_menu" if scope == "admin" else f"{scope}_page"
    last_key = f"{scope}_last_page"
    previous_key = f"{scope}_previous_page"
    history_key = f"{scope}_has_history"
    selected_page = st.session_state.get(page_key, default_page)
    last_page = st.session_state.get(last_key, default_page)
    if selected_page != last_page:
        st.session_state[previous_key] = last_page
        st.session_state[last_key] = selected_page
        st.session_state[history_key] = True


def go_to_previous_page(scope: str, default_page: str) -> None:
    """현재 메뉴와 직전 메뉴를 맞바꿔 자연스러운 이전 이동을 제공합니다."""
    page_key = "admin_top_menu" if scope == "admin" else f"{scope}_page"
    last_key = f"{scope}_last_page"
    previous_key = f"{scope}_previous_page"
    current_page = st.session_state.get(page_key, default_page)
    previous_page = st.session_state.get(previous_key, default_page)
    st.session_state[page_key] = previous_page
    st.session_state[last_key] = previous_page
    st.session_state[previous_key] = current_page
    st.session_state[f"{scope}_has_history"] = True


def render_sidebar_back(scope: str, default_page: str) -> None:
    """로그인 후 모든 상세 메뉴에서 공통으로 사용하는 이전 버튼입니다."""
    can_go_back = bool(st.session_state.get(f"{scope}_has_history", False))
    if st.button(
        "← 이전 화면",
        key=f"{scope}_back_button",
        use_container_width=True,
        disabled=not can_go_back,
        help="직전에 보던 메뉴로 돌아갑니다." if can_go_back else "이전 화면이 없습니다.",
    ):
        go_to_previous_page(scope, default_page)
        st.rerun()


def complete_pending_order() -> int | None:
    pending = st.session_state.get("pending_order")
    if not pending or st.session_state.role != "customer":
        return None
    if not normalize_phone(st.session_state.phone):
        st.session_state.flash = "주문 접수 전에 계정 설정에서 휴대폰 번호를 등록해 주세요."
        return None
    values = dict(pending)
    values["username"] = st.session_state.username
    order_id = create_order(values)
    st.session_state.pending_order = None
    st.session_state.show_order_auth = False
    st.session_state.flash = f"주문 요청 #{order_id}번이 접수되었습니다. 내 주문 내역에서 확인할 수 있습니다."
    return order_id


def submit_or_request_login(values: dict[str, Any]) -> None:
    if not st.session_state.logged_in:
        st.session_state.pending_order = values
        st.session_state.show_order_auth = True
        st.session_state.auth_alert = (
            "주문 요청은 로그인 후 접수할 수 있습니다. 아래에서 로그인하거나 회원가입해 주세요."
        )
        st.session_state.auth_alert_nonce += 1
        st.rerun()
    if st.session_state.role != "customer":
        st.warning("대표 계정에서는 주문을 접수할 수 없습니다. 고객 계정으로 로그인해 주세요.")
        return
    if not require_customer_phone():
        st.session_state.pending_order = values
        return
    values = dict(values)
    values["username"] = st.session_state.username
    order_id = create_order(values)
    st.success(f"주문 요청 #{order_id}번이 접수되었습니다. 내 주문 내역에서 확인할 수 있습니다.")


def category_text(category: str) -> str:
    return CATEGORY_LABELS.get(category, category or "미분류")


def status_html(current_status: str) -> str:
    try:
        current_index = ORDER_STATUSES.index(current_status)
    except ValueError:
        current_index = 0
    items = []
    for index, label in enumerate(ORDER_STATUSES):
        css = "current" if index == current_index else "done" if index < current_index else ""
        items.append(f'<span class="status-step {css}">{html.escape(label)}</span>')
    return '<div class="status-row">' + "".join(items) + "</div>"


def money_text(value: float | int | None) -> str:
    return f"{float(value or 0):,.0f}원"


def order_summary(order: dict[str, Any]) -> str:
    date = str(order["date"] or "")[:16]
    name = str(order["project_name"] or category_text(order["category"])).replace("\n", " ")
    name = name.translate(str.maketrans({"[": "［", "]": "］", "(": "（", ")": "）", "<": "〈", ">": "〉"}))
    return f"#{order['id']}  {name}  ·  {order['status']}  ·  {date}"


def order_details_html(order: dict[str, Any]) -> str:
    fields = [
        ("프로젝트", order["project_name"]),
        ("희망 납기", order["desired_date"]),
        ("요구 공차", order["tolerance"]),
        ("마감·후처리", order["surface_finish"]),
    ]
    items = "".join(
        f'<div><span>{label}</span><b>{html.escape(str(value))}</b></div>'
        for label, value in fields if value
    )
    return f'<div class="order-details">{items}</div>' if items else ""


def render_plain_field(label: str, value: str) -> None:
    st.markdown(
        f'<div class="plain-field"><strong>{html.escape(label)}</strong>'
        f'<p>{html.escape(str(value))}</p></div>',
        unsafe_allow_html=True,
    )


def export_orders_csv(orders: list[dict[str, Any]]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    columns = [
        ("발주번호", "id"), ("접수일", "date"), ("상태", "status"),
        ("프로젝트", "project_name"), ("회원", "username"), ("회사명", "company_name"),
        ("휴대폰", "phone"), ("가공", "category"), ("재료", "material"),
        ("규격", "details"), ("수량", "quantity"), ("예상금액", "cost"),
        ("최종금액", "quoted_cost"), ("희망납기", "desired_date"),
        ("제시납기", "quoted_delivery"), ("요청사항", "request_note"),
    ]
    writer.writerow([label for label, _ in columns])
    for order in orders:
        values = []
        for _, key in columns:
            value = str(order[key] or "")
            if key == "category":
                value = category_text(value)
            if value.lstrip().startswith(("=", "+", "-", "@")):
                value = "'" + value
            values.append(value)
        writer.writerow(values)
    return output.getvalue().encode("utf-8-sig")


def dimension_line(
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    label: str,
    label_x: float,
    label_y: float,
    anchor: str = "middle",
) -> str:
    arrow = min(7.0, max(1.5, (x2 - x1) / 3))
    return (
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        'stroke="#60758d" stroke-width="1.4"/>'
        f'<path d="M{x1:.1f} {y1:.1f} L{x1 + arrow:.1f} {y1 - 3:.1f} '
        f'L{x1 + arrow:.1f} {y1 + 3:.1f} Z" fill="#60758d"/>'
        f'<path d="M{x2:.1f} {y2:.1f} L{x2 - arrow:.1f} {y2 - 3:.1f} '
        f'L{x2 - arrow:.1f} {y2 + 3:.1f} Z" fill="#60758d"/>'
        f'<text x="{label_x:.1f}" y="{label_y:.1f}" text-anchor="{anchor}" '
        f'font-size="12" font-weight="700" fill="#334155">{html.escape(label)}</text>'
    )


def vertical_dimension_line(
    x: float,
    y1: float,
    y2: float,
    label: str,
    label_x: float,
) -> str:
    middle_y = (y1 + y2) / 2
    arrow = min(7.0, max(1.5, (y2 - y1) / 3))
    return (
        f'<line x1="{x:.1f}" y1="{y1:.1f}" x2="{x:.1f}" y2="{y2:.1f}" '
        'stroke="#60758d" stroke-width="1.4"/>'
        f'<path d="M{x:.1f} {y1:.1f} L{x - 3:.1f} {y1 + arrow:.1f} '
        f'L{x + 3:.1f} {y1 + arrow:.1f} Z" fill="#60758d"/>'
        f'<path d="M{x:.1f} {y2:.1f} L{x - 3:.1f} {y2 - arrow:.1f} '
        f'L{x + 3:.1f} {y2 - arrow:.1f} Z" fill="#60758d"/>'
        f'<text x="{label_x:.1f}" y="{middle_y:.1f}" text-anchor="middle" '
        f'transform="rotate(-90 {label_x:.1f} {middle_y:.1f})" '
        f'font-size="12" font-weight="700" fill="#334155">{html.escape(label)}</text>'
    )


def hatched_rectangle(x: float, y: float, width: float, height: float) -> str:
    """별도 SVG 패턴 없이, 실제 형상 안에만 빗금을 그립니다."""
    strokes = []
    for offset in range(-math.ceil(height / 11) * 11, math.ceil(width / 11) * 11 + 1, 11):
        left = max(x, x + offset)
        right = min(x + width, x + offset + height)
        if right <= left:
            continue
        top_y = y + height - (left - x - offset)
        bottom_y = y + height - (right - x - offset)
        strokes.append(
            f'<line x1="{left:.2f}" y1="{top_y:.2f}" '
            f'x2="{right:.2f}" y2="{bottom_y:.2f}" '
            'stroke="#abc9e5" stroke-width="2"/>'
        )
    return (
        f'<rect x="{x:.2f}" y="{y:.2f}" width="{width:.2f}" '
        f'height="{height:.2f}" fill="#edf5fc"/>'
        + "".join(strokes)
        + f'<rect x="{x:.2f}" y="{y:.2f}" width="{width:.2f}" '
        f'height="{height:.2f}" fill="none" stroke="#4f8ed8" stroke-width="2"/>'
    )


def hatched_circle(cx: float, cy: float, radius: float) -> str:
    strokes = []
    reach = math.sqrt(2) * radius
    for offset in range(-math.ceil(reach / 11) * 11, math.ceil(reach / 11) * 11 + 1, 11):
        if abs(offset) >= reach:
            continue
        half = math.sqrt(radius * radius - offset * offset / 2) / math.sqrt(2)
        center_x, center_y = cx + offset / 2, cy + offset / 2
        strokes.append(
            f'<line x1="{center_x - half:.2f}" y1="{center_y + half:.2f}" '
            f'x2="{center_x + half:.2f}" y2="{center_y - half:.2f}" '
            'stroke="#abc9e5" stroke-width="2"/>'
        )
    return (
        f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{radius:.2f}" fill="#edf5fc"/>'
        + "".join(strokes)
        + f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{radius:.2f}" '
        'fill="none" stroke="#4f8ed8" stroke-width="2"/>'
    )


def draw_milling_svg(width: float, length: float, thickness: float, holes: int) -> str:
    width = max(float(width), 0.1)
    length = max(float(length), 0.1)
    thickness = max(float(thickness), 0.1)
    scale = min(220 / width, 180 / length, 80 / thickness)
    sw, sl, stt = width * scale, length * scale, thickness * scale
    top_x, top_y = 90 + (220 - sw) / 2, 90 + (180 - sl) / 2
    side_x, side_y = 455 + (220 - sw) / 2, 135 + (80 - stt) / 2

    circles = []
    holes = max(0, int(holes))
    if holes:
        cols = math.ceil(math.sqrt(holes))
        rows = math.ceil(holes / cols)
        radius = max(2.5, min(8, min(sw / (cols + 2), sl / (rows + 2)) * 0.18))
        for index in range(holes):
            row, col = divmod(index, cols)
            cx = top_x + sw * (col + 1) / (cols + 1)
            cy = top_y + sl * (row + 1) / (rows + 1)
            circles.append(
                f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{radius:.1f}" fill="#fff" stroke="#4f8ed8" stroke-width="1.5"/>'
            )

    svg = f"""
    <svg viewBox="0 0 720 390" style="width:100%;height:auto;display:block;overflow:hidden" role="img" aria-label="밀링 규격 도면">
      <rect x="10" y="10" width="330" height="350" rx="12" fill="#fff" stroke="#dde5ee"/>
      <rect x="380" y="10" width="330" height="350" rx="12" fill="#fff" stroke="#dde5ee"/>
      <text x="30" y="42" font-size="16" font-weight="700" fill="#334155">평면도</text>
      <text x="400" y="42" font-size="16" font-weight="700" fill="#334155">측면도</text>
      {hatched_rectangle(top_x, top_y, sw, sl)}
      {''.join(circles)}
      {dimension_line(top_x, 72, top_x + sw, 72, f'가로 W {width:g} mm', top_x + sw / 2, 61)}
      {vertical_dimension_line(68, top_y, top_y + sl, f'세로 L {length:g} mm', 45)}
      {hatched_rectangle(side_x, side_y, sw, stt)}
      {dimension_line(side_x, 112, side_x + sw, 112, f'가로 W {width:g} mm', side_x + sw / 2, 100)}
      {vertical_dimension_line(432, side_y, side_y + stt, f'높이 T {thickness:g} mm', 409)}
      <text x="175" y="340" text-anchor="middle" font-size="13" fill="#64748b">가로 × 세로</text>
      <text x="545" y="340" text-anchor="middle" font-size="13" fill="#64748b">가로 × 두께</text>
    </svg>
    """
    return svg


def draw_lathe_svg(diameter: float, length: float) -> str:
    diameter = max(float(diameter), 0.1)
    length = max(float(length), 0.1)
    scale = min(300 / length, 160 / diameter)
    sl, sd = length * scale, diameter * scale
    body_x, body_y = 85 + (300 - sl) / 2, 100 + (160 - sd) / 2
    circle_r = sd / 2
    circle_x, circle_y = 590, 190
    svg = f"""
    <svg viewBox="0 0 720 390" style="width:100%;height:auto;display:block;overflow:hidden" role="img" aria-label="선반 규격 도면">
      <rect x="10" y="10" width="440" height="350" rx="12" fill="#fff" stroke="#dde5ee"/>
      <rect x="470" y="10" width="240" height="350" rx="12" fill="#fff" stroke="#dde5ee"/>
      <text x="30" y="42" font-size="16" font-weight="700" fill="#334155">측면도</text>
      <text x="490" y="42" font-size="16" font-weight="700" fill="#334155">정면도</text>
      {hatched_rectangle(body_x, body_y, sl, sd)}
      <line x1="{body_x - 12:.1f}" y1="{body_y + sd/2:.1f}" x2="{body_x + sl + 12:.1f}" y2="{body_y + sd/2:.1f}" stroke="#75869a" stroke-dasharray="7 5"/>
      {dimension_line(body_x, 76, body_x + sl, 76, f'길이 L {length:g} mm', body_x + sl / 2, 64)}
      {vertical_dimension_line(62, body_y, body_y + sd, f'지름 D {diameter:g} mm', 39)}
      {hatched_circle(circle_x, circle_y, circle_r)}
      <line x1="{circle_x - circle_r - 8:.1f}" y1="{circle_y}" x2="{circle_x + circle_r + 8:.1f}" y2="{circle_y}" stroke="#75869a" stroke-dasharray="7 5"/>
      {dimension_line(circle_x - circle_r, circle_y + circle_r + 24, circle_x + circle_r, circle_y + circle_r + 24, f'지름 D {diameter:g} mm', circle_x, circle_y + circle_r + 43)}
      <text x="230" y="340" text-anchor="middle" font-size="13" fill="#64748b">길이 × 지름</text>
      <text x="590" y="340" text-anchor="middle" font-size="13" fill="#64748b">원형 단면</text>
    </svg>
    """
    return svg


def show_svg(svg: str, kind: str) -> None:
    """데스크톱에서는 나란히, 휴대폰에서는 도면별로 크게 보여줍니다."""
    if kind == "milling":
        mobile_views = (("0 0 350 370", "", False), ("390 82 320 160", "측면도", True))
    elif kind == "lathe":
        mobile_views = (("0 0 460 370", "", False), ("465 75 250 255", "정면도", True))
    else:
        raise ValueError("알 수 없는 도면 종류입니다.")

    mobile_svgs = []
    for view_box, label, compact in mobile_views:
        # 기존 도형·화살표·치수값을 그대로 사용하고, 보이는 영역만 한 도면씩 확대합니다.
        cropped = svg.replace('viewBox="0 0 720 390"', f'viewBox="{view_box}"', 1)
        panel_class = "mobile-panel compact" if compact else "mobile-panel"
        mobile_svgs.append(
            f'<div class="{panel_class}">'
            + (f'<div class="mobile-panel-label">{label}</div>' if label else '')
            + f'{cropped}</div>'
        )

    st.iframe(
        """
        <style>
        html, body { margin: 0; padding: 0; overflow: hidden; background: #f5f7fa; }
        #drawing-root { width: 100%; font-family: Pretendard, 'Noto Sans KR', 'Malgun Gothic', sans-serif; }
        .desktop-diagram { max-width: 960px; margin: 0 auto; }
        .mobile-diagrams { display: none; }
        @media (max-width: 640px), (hover: none) and (pointer: coarse) and (max-width: 950px) {
          .desktop-diagram { display: none; }
          .mobile-diagrams { display: grid; gap: 10px; }
          .mobile-panel { min-width: 0; }
          .mobile-panel.compact {
            box-sizing: border-box; overflow: hidden; padding: 9px 6px 10px;
            background: #fff; border: 1px solid #dde5ee; border-radius: 12px;
          }
          .mobile-panel.compact svg rect[fill="#fff"][stroke="#dde5ee"] { display: none; }
          .mobile-panel.compact svg text[font-size="13"] { display: none; }
          .mobile-panel-label { color: #334155; font-size: 14px; font-weight: 700; margin: 0 0 3px 4px; }
          .mobile-panel svg { width: 100%; height: auto; display: block; }
          .mobile-panel svg text[font-size="12"] { font-size: 16px; }
        }
        </style>
        <div id="drawing-root">
          <div class="desktop-diagram">
        """
        + svg
        + '</div><div class="mobile-diagrams">'
        + "".join(mobile_svgs)
        + """</div></div>""",
        height="content",
        width="stretch",
    )


def render_estimate_summary(weight: float, kg_price: float, estimate: float) -> None:
    with st.container(key="desktop_estimate"):
        k1, k2, k3 = st.columns(3)
        k1.metric("개당 예상 중량", f"{weight:,.3f} kg")
        k2.metric("재료 기준 단가", f"{kg_price:,.0f}원/kg")
        k3.metric("예상 견적", money_text(estimate))
    st.markdown(
        '<div class="summary-grid mobile-only">'
        f'<div class="summary-item"><span>개당 예상 중량</span><strong>{weight:,.3f} kg</strong></div>'
        f'<div class="summary-item"><span>재료 기준 단가</span><strong>{kg_price:,.0f}원/kg</strong></div>'
        f'<div class="summary-item summary-total"><span>예상 견적</span><strong>{money_text(estimate)}</strong></div>'
        '</div>',
        unsafe_allow_html=True,
    )


def render_price_breakdown(base: float, material_each: float, machining_each: float, quantity: int) -> None:
    """자동 계산의 근거를 고객이 바로 읽을 수 있게 보여줍니다."""
    st.markdown(
        '<div class="price-breakdown">'
        f'<div><span>기본 가공비</span><strong>{money_text(base)}</strong></div>'
        f'<div><span>재료비 · {quantity}개</span><strong>{money_text(material_each * quantity)}</strong></div>'
        f'<div><span>치수·홀 가공비 · {quantity}개</span><strong>{money_text(machining_each * quantity)}</strong></div>'
        '</div>', unsafe_allow_html=True,
    )


def render_workflow() -> None:
    st.markdown(
        '<div class="workflow-title">가공 요청은 이렇게 진행됩니다</div>'
        '<div class="process-grid">'
        '<div class="process-item"><b><i>01</i> 가공 방식</b><span>밀링·선반·도면 검토 중 선택</span></div>'
        '<div class="process-item"><b><i>02</i> 규격과 재료</b><span>치수·수량과 요청 사항 입력</span></div>'
        '<div class="process-item"><b><i>03</i> 견적 확인</b><span>기본 형상은 예상 금액 바로 확인</span></div>'
        '<div class="process-item"><b><i>04</i> 요청 접수</b><span>로그인 후 대표자가 도면·조건 검토</span></div>'
        '</div><div class="workflow-footnote">대표자 견적을 확인한 뒤 카드 결제 방법을 안내합니다. 이 화면에서는 결제되지 않습니다.</div>',
        unsafe_allow_html=True,
    )


def render_order_options(prefix: str, category: str) -> dict[str, str]:
    st.markdown('<div class="section-title detail-heading">제작 조건</div>', unsafe_allow_html=True)
    first, second = st.columns(2, gap="medium")
    with first:
        project_name = st.text_input(
            "부품명 또는 프로젝트명", placeholder="예: 설비 브래킷 시제품",
            max_chars=100, key=f"{prefix}_project",
        )
        tolerance = st.selectbox(
            "요구 공차", ["일반 공차", "±0.1 mm", "±0.05 mm", "도면 기준 · 협의"],
            key=f"{prefix}_tolerance",
        )
    with second:
        desired_date = st.text_input(
            "희망 납기", placeholder="예: 10월 중순 / 협의 가능",
            max_chars=100, key=f"{prefix}_date",
        )
        finish = st.selectbox(
            "마감·후처리", ["기본 가공면", "버 제거", "표면 처리 협의", "도면 기준 · 협의"],
            key=f"{prefix}_finish",
        )
    note = st.text_area(
        "추가 요청 사항", placeholder="가공할 면, 나사·홈, 검사 기준 등을 적어 주세요.",
        max_chars=2000, key=f"{prefix}_note",
    )
    st.caption("공차·후처리·납기는 대표자가 확인한 뒤 최종 견적에 반영합니다.")
    return {
        "project_name": project_name.strip() or f"{category} 가공 요청",
        "desired_date": desired_date.strip(),
        "tolerance": tolerance,
        "surface_finish": finish,
        "request_note": note.strip(),
    }


def show_temporary_alert(message: str, nonce: int) -> None:
    message_json = json.dumps(message, ensure_ascii=False)
    components.html(
        f"""
        <script>
        // alert-run-{nonce}
        try {{
          const d = window.parent.document;
          const oldAlert = d.getElementById("ktg-temporary-alert");
          if (oldAlert) oldAlert.remove();

          const alertBox = d.createElement("div");
          alertBox.id = "ktg-temporary-alert";
          alertBox.textContent = {message_json};
          Object.assign(alertBox.style, {{
            position: "fixed",
            left: "50%",
            top: "24px",
            transform: "translate(-50%, -14px)",
            width: "calc(100% - 32px)",
            maxWidth: "560px",
            boxSizing: "border-box",
            padding: "15px 18px",
            borderRadius: "12px",
            border: "1px solid #f3a9b2",
            background: "#fff1f2",
            color: "#9f2135",
            fontFamily: "Pretendard, Noto Sans KR, Malgun Gothic, sans-serif",
            fontSize: "15px",
            fontWeight: "700",
            lineHeight: "1.5",
            textAlign: "center",
            boxShadow: "0 12px 30px rgba(120, 33, 48, 0.20)",
            opacity: "0",
            transition: "opacity .22s ease, transform .22s ease",
            zIndex: "999999"
          }});
          d.body.appendChild(alertBox);
          requestAnimationFrame(() => {{
            alertBox.style.opacity = "1";
            alertBox.style.transform = "translate(-50%, 0)";
          }});
          window.setTimeout(() => {{
            alertBox.style.opacity = "0";
            alertBox.style.transform = "translate(-50%, -14px)";
            window.setTimeout(() => alertBox.remove(), 250);
          }}, 3200);
        }} catch (e) {{}}
        </script>
        """,
        height=0,
    )


# -----------------------------------------------------------------------------
# 로그인 / 회원가입
# -----------------------------------------------------------------------------
def render_auth(embedded: bool = False) -> None:
    has_pending_order = bool(st.session_state.get("pending_order"))
    if embedded:
        st.markdown(
            '<div class="section-title">로그인 또는 회원가입</div>',
            unsafe_allow_html=True,
        )
    else:
        app_header("로그인하면 주문 내역과 대표 답변을 계속 확인할 수 있습니다.")

    left, right = st.columns(2, gap="large")
    form_suffix = "order" if embedded else "page"

    with left:
        st.markdown('<div class="section-title">로그인</div>', unsafe_allow_html=True)
        with st.form(f"login_form_{form_suffix}", clear_on_submit=False):
            login_id = st.text_input("아이디", key=f"login_id_{form_suffix}")
            login_pw = st.text_input(
                "비밀번호", type="password", key=f"login_pw_{form_suffix}"
            )
            login_submitted = st.form_submit_button("로그인", use_container_width=True)
        if login_submitted:
            user = authenticate(login_id, login_pw)
            if user is None:
                st.error("아이디 또는 비밀번호를 다시 확인해 주세요.")
            else:
                set_login_session(user)
                complete_pending_order()
                st.rerun()

        if not embedded:
            st.markdown(
                '<div class="notice-card"><b>대표자 로그인</b><br>'
                '대표 계정으로 로그인하면 전체 주문, 회원 연락처, 첨부 도면, 견적 답변과 가격 기준을 관리할 수 있습니다.</div>',
                unsafe_allow_html=True,
            )

    with right:
        st.markdown('<div class="section-title">처음 이용하시나요?</div>', unsafe_allow_html=True)
        with st.form(f"register_form_{form_suffix}", clear_on_submit=False):
            reg_type = st.radio(
                "고객 유형", ["사업자", "개인 고객"], horizontal=True,
                key=f"reg_type_{form_suffix}",
            )
            reg_id = st.text_input("사용할 아이디", key=f"reg_id_{form_suffix}")
            reg_phone = st.text_input(
                "휴대폰 번호",
                placeholder="010-1234-5678",
                help="견적 확인과 주문 안내 연락에 사용합니다.",
                key=f"reg_phone_{form_suffix}",
            )
            reg_company = ""
            if reg_type == "사업자":
                reg_company = st.text_input(
                    "회사명 (선택)", placeholder="견적서에 표시할 회사명",
                    max_chars=100, key=f"reg_company_{form_suffix}",
                )
            reg_pw = st.text_input(
                "비밀번호", type="password", key=f"reg_pw_{form_suffix}"
            )
            reg_pw_check = st.text_input(
                "비밀번호 확인", type="password", key=f"reg_pw_check_{form_suffix}"
            )
            register_label = "회원가입하고 주문하기" if has_pending_order else "회원가입"
            reg_submitted = st.form_submit_button(register_label, use_container_width=True)
        if reg_submitted:
            if reg_pw != reg_pw_check:
                st.error("비밀번호와 비밀번호 확인이 일치하지 않습니다.")
            else:
                usertype = "사업자 (B2B)" if reg_type == "사업자" else "개인 고객 (B2C)"
                ok, message = register_user(reg_id, reg_pw, usertype, reg_phone, reg_company)
                if not ok:
                    st.error(message)
                else:
                    user = authenticate(reg_id, reg_pw)
                    if user is None:
                        st.error("가입은 완료되었지만 자동 로그인에 실패했습니다. 로그인해 주세요.")
                    else:
                        set_login_session(user)
                        complete_pending_order()
                        st.rerun()

    if embedded and st.button("← 이전 화면으로", use_container_width=True):
        st.session_state.show_order_auth = False
        st.session_state.pending_order = None
        st.rerun()


def close_auth_dialog() -> None:
    st.session_state.show_order_auth = False


@st.dialog(
    "로그인 및 회원가입",
    width="large",
    dismissible=True,
    on_dismiss=close_auth_dialog,
)
def render_auth_dialog() -> None:
    render_auth(embedded=True)


# -----------------------------------------------------------------------------
# 고객 화면
# -----------------------------------------------------------------------------
def customer_sidebar() -> str:
    with st.sidebar:
        st.markdown(f"### {html.escape(st.session_state.username)} 님")
        st.caption(st.session_state.phone or "휴대폰 번호 미등록")
        render_sidebar_back("customer", "새 견적")
        st.divider()
        page = st.radio(
            "메뉴",
            ["새 견적", "내 주문 내역", "계정 설정"],
            key="customer_page",
            on_change=remember_navigation,
            args=("customer", "새 견적"),
        )
        st.divider()
        if st.button("로그아웃", use_container_width=True):
            logout()
    return page


def render_customer_home() -> None:
    page = customer_sidebar()
    if page == "새 견적":
        render_new_order()
    elif page == "내 주문 내역":
        render_my_orders()
    else:
        render_account_settings(is_admin=False)


def require_customer_phone() -> bool:
    if normalize_phone(st.session_state.phone):
        return True
    st.warning("발주 후 연락을 위해 계정 설정에서 휴대폰 번호를 먼저 등록해 주세요.")
    return False


def render_public_home() -> None:
    if st.session_state.get("auth_alert"):
        show_temporary_alert(
            st.session_state.auth_alert,
            int(st.session_state.get("auth_alert_nonce", 0)),
        )
        st.session_state.auth_alert = ""
    st.markdown(
        '<div class="site-brand"><span class="brand-mark">KTG</span>'
        '<span>가공 견적 프로그램</span></div>'
        '<div class="hero-panel"><div class="hero-overline">정밀 가공 · 온라인 견적 요청</div>'
        '<h1>필요한 부품, 도면부터 견적까지<br>한곳에서 확인하세요.</h1>'
        '<p>밀링과 선반은 치수를 바꾸며 예상 금액을 확인하고,<br>'
        '복잡한 형상은 도면과 제작 조건을 보내 검토받을 수 있습니다.</p>'
        '<div class="hero-highlights"><span>도면 중심 접수</span><span>예상 견적 확인</span>'
        '<span>발주 진행 상태 조회</span></div></div>', unsafe_allow_html=True,
    )
    left, top_right = st.columns([3.5, 1.4], gap="medium", vertical_alignment="center")
    with left:
        st.markdown(
            '<div class="home-intro"><b>가공 방식을 골라 시작하세요.</b>'
            '<span>아래 도면에서 치수와 형상을 바로 확인할 수 있습니다.</span></div>',
            unsafe_allow_html=True,
        )
    with top_right:
        if st.button("로그인 / 회원가입", use_container_width=True):
            st.session_state.show_order_auth = True
            st.session_state.auth_alert = ""
            st.rerun()
    render_new_order(show_header=False)
    if st.session_state.show_order_auth:
        render_auth_dialog()


def render_new_order(show_header: bool = True) -> None:
    if show_header:
        app_header("기본 형상은 바로 계산하고, 복잡한 형상은 도면을 첨부해 검토를 요청하세요.")
    if st.session_state.get("flash"):
        st.success(st.session_state.flash)
        st.session_state.flash = ""
    order_type = st.radio(
        "가공 방식 선택",
        ["MCT(밀링)", "CNC(선반)", "기타 도면 첨부"],
        horizontal=True,
        key="order_type",
    )
    if order_type == "MCT(밀링)":
        render_milling_order()
    elif order_type == "CNC(선반)":
        render_lathe_order()
    else:
        render_drawing_order()


def render_milling_order() -> None:
    pricing = get_pricing_settings()
    preview_slot = st.container(key="drawing_stage")

    st.markdown('<div class="section-title spec-title">01 · 밀링 기본 규격</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3, gap="medium")
    with c1:
        material = st.selectbox("재료", list(MATERIALS), key="m_material")
        width = st.number_input("가로 W (mm)", min_value=0.1, value=100.0, step=1.0)
    with c2:
        length = st.number_input("세로 L (mm)", min_value=0.1, value=150.0, step=1.0)
        thickness = st.number_input("높이(두께) T (mm)", min_value=0.1, value=10.0, step=1.0)
    with c3:
        holes = st.number_input("홀 수량 (개)", min_value=0, value=0, step=1)
        quantity = st.number_input("주문 수량 (개)", min_value=1, value=1, step=1)
    options = render_order_options("m", "밀링")

    density = MATERIALS[material]["density"]
    kg_price = pricing[MATERIALS[material]["price_key"]]
    weight = width * length * thickness * density / 1_000_000
    material_each = weight * kg_price
    machining_each = (
        width * pricing["milling_width"]
        + length * pricing["milling_length"]
        + thickness * pricing["milling_thickness"]
        + int(holes) * pricing["hole_each"]
    )
    estimate = pricing["milling_base"] + (material_each + machining_each) * int(quantity)

    with preview_slot:
        st.markdown('<div class="drawing-heading"><span>규격 도면</span><b>MCT · 밀링</b></div>', unsafe_allow_html=True)
        show_svg(draw_milling_svg(width, length, thickness, int(holes)), "milling")
        st.markdown(
            f'<div class="dimension-chips"><span>가로 <b>{width:g} mm</b></span>'
            f'<span>세로 <b>{length:g} mm</b></span><span>두께 <b>{thickness:g} mm</b></span>'
            f'<span>홀 <b>{int(holes)}개</b></span></div>', unsafe_allow_html=True,
        )
        render_workflow()

    st.markdown('<div class="section-title spec-title">02 · 예상 견적</div>', unsafe_allow_html=True)
    render_estimate_summary(weight, kg_price, estimate)
    render_price_breakdown(pricing["milling_base"], material_each, machining_each, int(quantity))
    st.markdown(
        '<div class="estimate-note">입력한 기본 규격을 기준으로 계산한 예상 금액입니다. '
        '공차, 가공 면수, 형상 난이도, 표면 처리와 납기에 따라 최종 견적이 달라질 수 있습니다. '
        '견적을 요청하면 대표자가 최종 금액과 납기를 제시합니다. 결제 안내는 견적 수락 후 진행합니다.</div>',
        unsafe_allow_html=True,
    )
    if st.button("이 조건으로 밀링 주문 요청", use_container_width=True):
        submit_or_request_login(
            {
                "category": "milling",
                "material": material,
                "details": f"가로 {width:g} × 세로 {length:g} × 두께 {thickness:g} mm, 홀 {int(holes)}개",
                "quantity": int(quantity),
                "cost": estimate,
                "width_mm": width,
                "length_mm": length,
                "thickness_mm": thickness,
                "diameter_mm": None,
                "hole_count": int(holes),
                "unit_weight_kg": weight,
                **options,
                "attachment_name": "",
                "attachment_mime": "",
                "attachment_data": None,
            }
        )


def render_lathe_order() -> None:
    pricing = get_pricing_settings()
    preview_slot = st.container(key="drawing_stage")

    st.markdown('<div class="section-title spec-title">01 · 선반 기본 규격</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3, gap="medium")
    with c1:
        material = st.selectbox("재료", list(MATERIALS), key="l_material")
    with c2:
        diameter = st.number_input("지름 D (mm)", min_value=0.1, value=50.0, step=1.0)
    with c3:
        length = st.number_input("길이 L (mm)", min_value=0.1, value=150.0, step=1.0)
    quantity = st.number_input("주문 수량 (개)", min_value=1, value=1, step=1, key="l_qty")
    options = render_order_options("l", "선반")

    density = MATERIALS[material]["density"]
    kg_price = pricing[MATERIALS[material]["price_key"]]
    weight = math.pi * (diameter / 2) ** 2 * length * density / 1_000_000
    material_each = weight * kg_price
    machining_each = (
        diameter * pricing["lathe_diameter"]
        + length * pricing["lathe_length"]
    )
    estimate = pricing["lathe_base"] + (material_each + machining_each) * int(quantity)

    with preview_slot:
        st.markdown('<div class="drawing-heading"><span>규격 도면</span><b>CNC · 선반</b></div>', unsafe_allow_html=True)
        show_svg(draw_lathe_svg(diameter, length), "lathe")
        st.markdown(
            f'<div class="dimension-chips"><span>지름 <b>{diameter:g} mm</b></span>'
            f'<span>길이 <b>{length:g} mm</b></span></div>', unsafe_allow_html=True,
        )
        render_workflow()

    st.markdown('<div class="section-title spec-title">02 · 예상 견적</div>', unsafe_allow_html=True)
    render_estimate_summary(weight, kg_price, estimate)
    render_price_breakdown(pricing["lathe_base"], material_each, machining_each, int(quantity))
    st.markdown(
        '<div class="estimate-note">입력한 기본 규격을 기준으로 계산한 예상 금액입니다. '
        '공차, 나사·홈 가공, 형상 난이도, 표면 처리와 납기에 따라 최종 견적이 달라질 수 있습니다. '
        '견적을 요청하면 대표자가 최종 금액과 납기를 제시합니다. 결제 안내는 견적 수락 후 진행합니다.</div>',
        unsafe_allow_html=True,
    )
    if st.button("이 조건으로 선반 주문 요청", use_container_width=True):
        submit_or_request_login(
            {
                "category": "lathe",
                "material": material,
                "details": f"지름 Φ{diameter:g} × 길이 {length:g} mm",
                "quantity": int(quantity),
                "cost": estimate,
                "width_mm": None,
                "length_mm": length,
                "thickness_mm": None,
                "diameter_mm": diameter,
                "hole_count": 0,
                "unit_weight_kg": weight,
                **options,
                "attachment_name": "",
                "attachment_mime": "",
                "attachment_data": None,
            }
        )


def render_drawing_order() -> None:
    st.markdown(
        '<div class="drawing-heading drawing-heading-spaced"><span>도면 검토</span><b>기타 가공 의뢰</b></div>'
        '<div class="drawing-upload-art" aria-label="가공 도면 접수 안내">'
        '<svg viewBox="0 0 760 230" role="img" aria-label="평면도, 단면도, 치수 도면의 예시">'
        '<defs><pattern id="hatch" width="12" height="12" patternUnits="userSpaceOnUse" '
        'patternTransform="rotate(45)"><rect width="12" height="12" fill="#eaf2f8"/>'
        '<path d="M0 0V12" stroke="#9ebed1" stroke-width="3"/></pattern></defs>'
        '<rect x="60" y="43" width="250" height="140" rx="6" fill="url(#hatch)" stroke="#477c9b" stroke-width="2"/>'
        '<circle cx="110" cy="86" r="13" fill="white" stroke="#477c9b" stroke-width="2"/>'
        '<circle cx="260" cy="143" r="13" fill="white" stroke="#477c9b" stroke-width="2"/>'
        '<path d="M60 27H310M44 43V183" stroke="#496b82" stroke-width="1.5"/>'
        '<text x="185" y="22" text-anchor="middle" fill="#2e4c63" font-size="15">가공 형상 · 평면도</text>'
        '<path d="M423 115h270" stroke="#496b82" stroke-width="1.5" stroke-dasharray="7 5"/>'
        '<circle cx="555" cy="115" r="69" fill="url(#hatch)" stroke="#477c9b" stroke-width="2"/>'
        '<text x="555" y="214" text-anchor="middle" fill="#2e4c63" font-size="15">치수 · 홀 · 단면</text>'
        '</svg><p>도면과 제작 조건을 함께 보내주시면 검토 후 견적을 안내합니다.</p></div>',
        unsafe_allow_html=True,
    )
    render_workflow()
    st.markdown(
        '<div class="notice-card"><b>도면에 표시된 내용과 별도로 필요한 조건을 적어 주세요.</b><br>'
        '공차·마감·희망 납기까지 알려주시면 대표자가 내용을 검토한 뒤 최종 견적을 제시합니다.</div>',
        unsafe_allow_html=True,
    )
    with st.form("drawing_order_form"):
        c1, c2 = st.columns(2)
        with c1:
            material = st.selectbox("재료", ["도면에 표시", *MATERIALS.keys(), "협의 필요"])
            quantity = st.number_input("주문 수량 (개)", min_value=1, value=1, step=1, key="d_qty")
        with c2:
            uploaded = st.file_uploader(
                "도면 파일",
                type=["jpg", "jpeg", "png", "pdf", "step", "stp", "dxf", "dwg", "igs", "iges"],
                help="이미지·PDF·STEP·DXF·DWG·IGES 파일을 지원하며 최대 10MB까지 첨부할 수 있습니다.",
            )
        n1, n2 = st.columns(2)
        with n1:
            project_name = st.text_input("부품명 또는 프로젝트명", max_chars=100, placeholder="예: 샤프트 가공품")
            tolerance = st.text_input("공차·검사 기준", max_chars=100, placeholder="예: 도면 기준")
        with n2:
            desired_date = st.text_input("희망 납기", max_chars=100, placeholder="예: 10월 중순 / 협의 가능")
            finish = st.text_input("표면 처리·마감", max_chars=100, placeholder="예: 버 제거 후 아노다이징")
        note = st.text_area(
            "추가 요청 사항",
            placeholder="가공할 부위, 재료 지급 여부, 중요한 검사 치수 등 도면에 없는 내용을 적어 주세요.",
            max_chars=2000,
        )
        submitted = st.form_submit_button("도면 검토와 견적 요청", use_container_width=True)

    if submitted:
        if uploaded is None:
            st.error("검토할 도면 파일을 첨부해 주세요.")
            return
        data = uploaded.getvalue()
        if len(data) > 10 * 1024 * 1024:
            st.error("도면 파일은 10MB 이하만 첨부할 수 있습니다.")
            return
        submit_or_request_login(
            {
                "category": "drawing",
                "material": material,
                "details": "첨부 도면 검토 요청",
                "quantity": int(quantity),
                "cost": 0,
                "width_mm": None,
                "length_mm": None,
                "thickness_mm": None,
                "diameter_mm": None,
                "hole_count": 0,
                "unit_weight_kg": 0,
                "project_name": project_name.strip() or "도면 검토 요청",
                "desired_date": desired_date.strip(),
                "tolerance": tolerance.strip(),
                "surface_finish": finish.strip(),
                "request_note": note.strip(),
                "attachment_name": Path(uploaded.name).name,
                "attachment_mime": uploaded.type or "application/octet-stream",
                "attachment_data": data,
            }
        )


def render_my_orders() -> None:
    app_header("요청한 부품의 견적, 답변과 가공 진행 상황을 확인하세요.")
    orders = get_orders(st.session_state.username)
    if not orders:
        st.info("아직 접수한 발주가 없습니다.")
        return
    for order in orders:
        with st.expander(order_summary(order), expanded=False):
            st.markdown(status_html(order["status"]), unsafe_allow_html=True)
            a, b, c = st.columns(3)
            a.markdown(f"**가공 방식**  \n{category_text(order['category'])}")
            b.markdown(f"**재료 / 수량**  \n{order['material'] or '-'} / {order['quantity']}개")
            final_cost = float(order["quoted_cost"] or 0)
            c.markdown(
                f"**금액**  \n{money_text(final_cost) if final_cost > 0 else '견적 검토 중'}"
            )
            render_plain_field("규격", order["details"] or "-")
            st.markdown(order_details_html(order), unsafe_allow_html=True)
            if order["request_note"]:
                render_plain_field("요청 사항", order["request_note"])
            if order["quoted_delivery"]:
                render_plain_field("제시 납기", order["quoted_delivery"])
            if order["quote_valid_until"]:
                st.caption(f"견적 유효기간: {order['quote_valid_until']}까지")
            if order["quote_accepted_at"]:
                st.success(f"{order['quote_accepted_at'][:16]}에 견적을 확인했습니다. 결제는 별도 안내됩니다.")
            elif order["status"] == "견적 제안" and final_cost > 0:
                if order["quote_valid_until"] and order["quote_valid_until"] < now_text()[:10]:
                    st.warning("견적 유효기간이 지났습니다. 대표자에게 재확인을 요청해 주세요.")
                elif st.button("제시 견적 확인 · 진행 요청", key=f"accept_{order['id']}"):
                    if accept_quote(order["id"], st.session_state.username):
                        st.success("견적 확인을 기록했습니다. 결제와 제작 일정은 별도로 안내됩니다.")
                        st.rerun()
                    else:
                        st.error("견적 상태가 변경되었습니다. 새로고침 후 다시 확인해 주세요.")
            if order["admin_reply"]:
                st.markdown(
                    f'<div class="notice-card"><b>대표 관리자 답변</b><br>{html.escape(order["admin_reply"]).replace(chr(10), "<br>")}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.caption("아직 등록된 관리자 답변이 없습니다.")
            if order["attachment_data"]:
                st.download_button(
                    "첨부한 도면 다시 받기",
                    data=bytes(order["attachment_data"]),
                    file_name=order["attachment_name"] or f"drawing_{order['id']}",
                    mime=order["attachment_mime"] or "application/octet-stream",
                    key=f"customer_download_{order['id']}",
                )


def render_account_settings(is_admin: bool) -> None:
    app_header("연락처와 로그인 정보를 관리합니다.")
    col1, col2 = st.columns(2, gap="large")
    with col1:
        st.markdown('<div class="section-title">연락처</div>', unsafe_allow_html=True)
        with st.form("phone_form"):
            phone = st.text_input("휴대폰 번호", value=st.session_state.phone)
            phone_submit = st.form_submit_button("연락처 저장", use_container_width=True)
        if phone_submit:
            ok, result = update_phone(st.session_state.username, phone)
            if ok:
                st.session_state.phone = result
                st.success("연락처를 저장했습니다.")
            else:
                st.error(result)
        if not is_admin:
            with st.form("company_form"):
                company_name = st.text_input(
                    "회사명 (사업자 고객)", value=st.session_state.company_name,
                    max_chars=100, placeholder="견적과 발주에 표시할 회사명",
                )
                company_saved = st.form_submit_button("회사명 저장", use_container_width=True)
            if company_saved:
                st.session_state.company_name = update_company_name(st.session_state.username, company_name)
                st.success("회사명을 저장했습니다.")
    with col2:
        st.markdown('<div class="section-title">비밀번호 변경</div>', unsafe_allow_html=True)
        with st.form("password_form"):
            current = st.text_input("현재 비밀번호", type="password")
            new = st.text_input("새 비밀번호", type="password")
            confirm = st.text_input("새 비밀번호 확인", type="password")
            password_submit = st.form_submit_button("비밀번호 변경", use_container_width=True)
        if password_submit:
            if new != confirm:
                st.error("새 비밀번호 확인이 일치하지 않습니다.")
            else:
                ok, message = change_password(st.session_state.username, current, new)
                (st.success if ok else st.error)(message)
    if is_admin:
        st.info(f"현재 대표 계정 아이디: {ADMIN_ID}")


# -----------------------------------------------------------------------------
# 대표 관리자 화면
# -----------------------------------------------------------------------------
def admin_sidebar() -> str:
    with st.sidebar:
        st.markdown("### 대표자 관리")
        st.caption(f"로그인 계정: {ADMIN_ID}")
        render_sidebar_back("admin", "전체 주문 관리")
        st.divider()
        st.caption("상단 메뉴에서 관리 화면을 선택할 수 있습니다.")

    identity, logout_column = st.columns([4, 1])
    with identity:
        st.markdown(
            f'<div class="soft-card"><b>대표자 관리</b><br>'
            f'<span class="muted">로그인 계정: {html.escape(ADMIN_ID)}</span></div>',
            unsafe_allow_html=True,
        )
    with logout_column:
        if st.button("로그아웃", use_container_width=True):
            logout()
    page = st.radio(
        "대표자 메뉴",
        ["전체 주문 관리", "가격 설정", "회원 연락처", "계정 설정"],
        horizontal=True,
        key="admin_top_menu",
        on_change=remember_navigation,
        args=("admin", "전체 주문 관리"),
    )
    st.divider()
    return page


def render_admin_home() -> None:
    page = admin_sidebar()
    if page == "전체 주문 관리":
        render_admin_orders()
    elif page == "가격 설정":
        render_admin_pricing()
    elif page == "회원 연락처":
        render_customer_contacts()
    else:
        render_account_settings(is_admin=True)


def render_admin_pricing() -> None:
    app_header("예상 견적에 사용하는 가공 치수 단가와 재료 단가를 관리합니다.")
    current = get_pricing_settings()
    st.markdown(
        '<div class="notice-card">고객이 보는 예상 견적에 바로 반영됩니다. '
        '최종 견적은 주문별 검토 후 전체 주문 관리에서 따로 확정할 수 있습니다.</div>',
        unsafe_allow_html=True,
    )
    with st.form("pricing_settings_form"):
        st.markdown('<div class="section-title">밀링 가공 기준</div>', unsafe_allow_html=True)
        m1, m2, m3, m4 = st.columns(4)
        milling_base = m1.number_input("기본 가공비 (원)", min_value=0.0, value=current["milling_base"], step=1_000.0, key="price_milling_base")
        milling_width = m2.number_input("가로 1mm당 가격 (원)", min_value=0.0, value=current["milling_width"], step=5.0, key="price_milling_width")
        milling_length = m3.number_input("세로(길이) 1mm당 가격 (원)", min_value=0.0, value=current["milling_length"], step=5.0, key="price_milling_length")
        milling_thickness = m4.number_input("높이(두께) 1mm당 가격 (원)", min_value=0.0, value=current["milling_thickness"], step=10.0, key="price_milling_thickness")

        st.markdown('<div class="section-title">선반 가공 기준</div>', unsafe_allow_html=True)
        l1, l2, l3, l4 = st.columns(4)
        lathe_base = l1.number_input("기본 가공비 (원)", min_value=0.0, value=current["lathe_base"], step=1_000.0, key="price_lathe_base")
        lathe_diameter = l2.number_input("지름 1mm당 가격 (원)", min_value=0.0, value=current["lathe_diameter"], step=5.0, key="price_lathe_diameter")
        lathe_length = l3.number_input("길이 1mm당 가격 (원)", min_value=0.0, value=current["lathe_length"], step=5.0, key="price_lathe_length")
        hole_each = l4.number_input("홀 1개당 가격 (원)", min_value=0.0, value=current["hole_each"], step=100.0, key="price_hole_each")

        st.markdown('<div class="section-title">재료 기준 단가</div>', unsafe_allow_html=True)
        material_values: dict[str, float] = {}
        material_columns = st.columns(3)
        for index, (material_name, material) in enumerate(MATERIALS.items()):
            price_key = material["price_key"]
            with material_columns[index % 3]:
                material_values[price_key] = st.number_input(
                    f"{material_name} (원/kg)",
                    min_value=0.0,
                    value=current[price_key],
                    step=500.0,
                    key=f"admin_price_{price_key}",
                )
        saved = st.form_submit_button("가격 기준 저장", use_container_width=True)

    if saved:
        save_pricing_settings(
            {
                "milling_base": milling_base,
                "milling_width": milling_width,
                "milling_length": milling_length,
                "milling_thickness": milling_thickness,
                "lathe_base": lathe_base,
                "lathe_diameter": lathe_diameter,
                "lathe_length": lathe_length,
                "hole_each": hole_each,
                **material_values,
            }
        )
        st.success("가격 기준을 저장했습니다. 새로 계산하는 예상 견적부터 적용됩니다.")


def render_admin_orders() -> None:
    app_header("모든 회원의 발주와 연락처를 확인하고 견적 답변 및 진행 상태를 저장합니다.")
    orders = get_orders()
    total = len(orders)
    waiting = sum(row["status"] in {"접수", "견적 검토"} for row in orders)
    quote_pending = sum(row["status"] == "견적 제안" for row in orders)
    drawing_waiting = sum(
        category_text(row["category"]) == "기타 도면 첨부" and not row["admin_reply"]
        for row in orders
    )
    shipped = sum(row["status"] == "출하" for row in orders)
    with st.container(key="desktop_dashboard"):
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("전체 발주", total)
        m2.metric("검토 필요", waiting)
        m3.metric("고객 확인 대기", quote_pending)
        m4.metric("도면 답변 대기", drawing_waiting)
        m5.metric("출하 완료", shipped)
    st.markdown(
        '<div class="dashboard-grid mobile-only">'
        f'<div class="dashboard-item"><span>전체 발주</span><strong>{total}</strong></div>'
        f'<div class="dashboard-item"><span>검토 필요</span><strong>{waiting}</strong></div>'
        f'<div class="dashboard-item"><span>고객 확인 대기</span><strong>{quote_pending}</strong></div>'
        f'<div class="dashboard-item"><span>도면 답변 대기</span><strong>{drawing_waiting}</strong></div>'
        f'<div class="dashboard-item"><span>출하 완료</span><strong>{shipped}</strong></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="section-title" style="margin-top:1.4rem">발주 검색</div>', unsafe_allow_html=True)
    f1, f2, f3 = st.columns([1, 1, 1.4])
    with f1:
        status_filter = st.selectbox("진행 상태", ["전체", *ORDER_STATUSES])
    with f2:
        category_filter = st.selectbox(
            "가공 방식", ["전체", "MCT(밀링)", "CNC(선반)", "기타 도면 첨부"]
        )
    with f3:
        keyword = st.text_input("아이디 / 회사명 / 부품명 / 휴대폰 / 발주번호 검색")

    normalized_keyword = keyword.strip().lower()
    filtered = []
    for row in orders:
        if status_filter != "전체" and row["status"] != status_filter:
            continue
        if category_filter != "전체" and category_text(row["category"]) != category_filter:
            continue
        haystack = f"{row['id']} {row['username']} {row['phone'] or ''} {row['company_name'] or ''} {row['project_name'] or ''}".lower()
        if normalized_keyword and normalized_keyword not in haystack:
            continue
        filtered.append(row)

    st.caption(f"검색 결과 {len(filtered)}건")
    if filtered:
        st.download_button(
            "검색한 발주 CSV 저장", export_orders_csv(filtered),
            file_name=f"KTG_발주목록_{now_text()[:10]}.csv",
            mime="text/csv", key="export_admin_orders",
        )
    if not filtered:
        st.info("조건에 맞는 발주가 없습니다.")
        return

    for order in filtered:
        title = f"#{order['id']}  {order['username']}  ·  {category_text(order['category'])}  ·  {order['status']}"
        with st.expander(title, expanded=False):
            st.markdown(status_html(order["status"]), unsafe_allow_html=True)
            i1, i2, i3, i4 = st.columns(4)
            i1.markdown(f"**회원 아이디**  \n{order['username']}")
            i2.markdown(f"**휴대폰**  \n{order['phone'] or '미등록'}")
            i3.markdown(f"**가입 유형**  \n{order['usertype'] or '-'}")
            i4.markdown(f"**접수 일시**  \n{str(order['date'] or '-')[:16]}")
            if order["company_name"]:
                render_plain_field("회사명", order["company_name"])

            st.markdown(f"**가공 / 재료 / 수량**  \n{category_text(order['category'])} / {order['material'] or '-'} / {order['quantity']}개")
            render_plain_field("규격", order["details"] or "-")
            st.markdown(order_details_html(order), unsafe_allow_html=True)
            if order["request_note"]:
                render_plain_field("고객 요청 사항", order["request_note"])
            if order["quote_accepted_at"]:
                st.success(f"고객 견적 확인: {str(order['quote_accepted_at'])[:16]}")
            st.caption(f"자동 계산 참고 금액: {money_text(order['cost'])}")

            if order["attachment_data"]:
                st.download_button(
                    "첨부 도면 받기",
                    data=bytes(order["attachment_data"]),
                    file_name=order["attachment_name"] or f"drawing_{order['id']}",
                    mime=order["attachment_mime"] or "application/octet-stream",
                    key=f"admin_download_{order['id']}",
                )

            with st.form(f"admin_order_form_{order['id']}"):
                c1, c2 = st.columns([1, 1])
                with c1:
                    current_status = order["status"] if order["status"] in ORDER_STATUSES else "접수"
                    new_status = st.selectbox(
                        "진행 상태",
                        ORDER_STATUSES,
                        index=ORDER_STATUSES.index(current_status),
                    )
                with c2:
                    quote = st.number_input(
                        "최종 견적 금액 (원)",
                        min_value=0.0,
                        value=float(order["quoted_cost"] or 0),
                        step=1_000.0,
                    )
                reply = st.text_area(
                    "고객에게 남길 답변",
                    value=order["admin_reply"] or "",
                    placeholder="도면 검토 결과, 추가 확인 사항, 견적 설명 등을 입력하세요.",
                )
                delivery = st.text_input(
                    "제작·납품 예상일", value=order["quoted_delivery"] or "",
                    placeholder="예: 견적 승인 후 7영업일", max_chars=100,
                )
                valid_until = st.text_input(
                    "견적 유효기간 (선택)", value=order["quote_valid_until"] or "",
                    placeholder="YYYY-MM-DD", max_chars=10,
                )
                save = st.form_submit_button("답변과 진행 상태 저장", use_container_width=True)
            if save:
                try:
                    if valid_until:
                        try:
                            datetime.strptime(valid_until, "%Y-%m-%d")
                        except ValueError as exc:
                            raise ValueError("견적 유효기간을 YYYY-MM-DD 형식으로 입력해 주세요.") from exc
                    update_order_by_admin(order["id"], new_status, quote, reply, delivery, valid_until)
                except ValueError as exc:
                    st.error(str(exc))
                else:
                    st.success(f"발주 #{order['id']}번의 내용을 저장했습니다.")
                    st.rerun()


def render_customer_contacts() -> None:
    app_header("발주 후 연락할 회원의 휴대폰 번호를 확인합니다.")
    with db_connection() as conn:
        users = conn.execute(
            """
            SELECT u.username, u.usertype, u.phone, u.company_name, u.created_at, COUNT(o.id) AS order_count
            FROM users u
            LEFT JOIN orders o ON o.username=u.username
            WHERE COALESCE(u.role, 'customer')='customer'
            GROUP BY u.username, u.usertype, u.phone, u.company_name, u.created_at
            ORDER BY order_count DESC, u.username
            """
        ).fetchall()
    if not users:
        st.info("가입한 일반 회원이 없습니다.")
        return
    for user in users:
        st.markdown(
            f"""
            <div class="soft-card" style="margin-bottom:.7rem">
              <b>{html.escape(user['username'])}</b><br>
              <span class="muted">{html.escape(user['company_name'] or user['usertype'] or '-')} · {html.escape(user['phone'] or '휴대폰 미등록')} · 발주 {user['order_count']}건</span>
            </div>
            """,
            unsafe_allow_html=True,
        )


def main() -> None:
    st.set_page_config(
        page_title=APP_TITLE,
        layout="wide",
        initial_sidebar_state=(
            "expanded" if st.session_state.get("logged_in", False) else "collapsed"
        ),
        page_icon=None,
    )
    inject_global_style()
    missing = []
    if not DATABASE_URL:
        missing.append("DATABASE_URL")
    if not ADMIN_ID:
        missing.append("KTG_ADMIN_ID")
    if not ADMIN_PASSWORD:
        missing.append("KTG_ADMIN_PASSWORD")
    if missing:
        st.error(
            "영구 데이터베이스 설정이 없어 앱 실행을 중단했습니다. "
            f"Streamlit Secrets에 {', '.join(missing)} 값을 등록해 주세요."
        )
        st.caption("로컬 SQLite로 대체하지 않으므로 배포 서버가 재시작되어도 임시 DB에 잘못 저장되는 일이 없습니다.")
        st.stop()
    try:
        init_db()
    except Exception:
        st.error("영구 데이터베이스에 연결하지 못했습니다. DATABASE_URL과 Supabase 프로젝트 상태를 확인해 주세요.")
        st.stop()
    initialize_session()

    if not st.session_state.logged_in:
        render_public_home()
    elif st.session_state.role == "admin":
        render_admin_home()
    else:
        render_customer_home()


if __name__ == "__main__":
    main()
