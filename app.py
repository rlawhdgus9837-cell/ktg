from __future__ import annotations

import hashlib
import hmac
import html
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
APP_TITLE = "KTG 가공 발주 시스템"
KOREA_TZ = ZoneInfo("Asia/Seoul")

# Streamlit Community Cloud의 Secrets에 반드시 등록해야 합니다.
# 값이 없으면 로컬 SQLite로 대체하지 않고 실행을 중단하여 데이터 유실을 막습니다.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
ADMIN_ID = os.getenv("KTG_ADMIN_ID", "").strip()
ADMIN_PASSWORD = os.getenv("KTG_ADMIN_PASSWORD", "")

MATERIALS = {
    "알루미늄 6061": {"density": 2.70, "default_price": 5_000},
    "스틸 SS400": {"density": 7.85, "default_price": 2_000},
    "스테인리스 304": {"density": 7.93, "default_price": 5_000},
    "스테인리스 316": {"density": 7.98, "default_price": 6_000},
    "황동": {"density": 8.50, "default_price": 9_000},
}

ORDER_STATUSES = [
    "접수",
    "견적 검토",
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
                role TEXT DEFAULT 'customer',
                created_at TEXT DEFAULT ''
            )
            """
        )
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS usertype TEXT DEFAULT '개인 고객 (B2C)'")
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT ''")
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
                admin_reply TEXT DEFAULT '',
                quoted_cost REAL DEFAULT 0,
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
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS admin_reply TEXT DEFAULT ''",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS quoted_cost REAL DEFAULT 0",
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


def register_user(username: str, password: str, usertype: str, phone: str) -> tuple[bool, str]:
    username = username.strip()
    normalized_phone = normalize_phone(phone)
    if not re.fullmatch(r"[A-Za-z0-9가-힣_.-]{2,30}", username):
        return False, "아이디는 2~30자의 한글, 영문, 숫자, 밑줄, 마침표, 하이픈만 사용할 수 있습니다."
    if username == ADMIN_ID:
        return False, "대표 계정 아이디는 사용할 수 없습니다."
    if len(password) < 6:
        return False, "비밀번호는 6자 이상 입력해 주세요."
    if normalized_phone is None:
        return False, "연락 가능한 휴대폰 번호를 정확히 입력해 주세요."
    try:
        with db_connection() as conn:
            conn.execute(
                """
                INSERT INTO users
                    (username, password, usertype, phone, role, created_at)
                VALUES (%s, %s, %s, %s, 'customer', %s)
                """,
                (username, hash_password(password), usertype, normalized_phone, now_text()),
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
        "admin_reply",
        "quoted_cost",
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
        SELECT o.*, u.phone, u.usertype
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
    order_id: int, status: str, quoted_cost: float, admin_reply: str
) -> None:
    if status not in ORDER_STATUSES:
        raise ValueError("허용되지 않은 진행 상태입니다.")
    with db_connection() as conn:
        conn.execute(
            """
            UPDATE orders
            SET status=%s, quoted_cost=%s, admin_reply=%s, updated_at=%s
            WHERE id=%s
            """,
            (status, max(0, quoted_cost), admin_reply.strip(), now_text(), order_id),
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
        :root { color-scheme: light; }
        html, body, .stApp, [class*="css"] {
            font-family: "Pretendard", "Noto Sans KR", "Malgun Gothic", sans-serif !important;
        }
        html, body, .stApp { background: #f5f7fa; color: #172033; }
        [data-testid="stHeader"], [data-testid="stToolbar"], #MainMenu, footer { display: none !important; }
        [data-testid="stHeaderActionElements"], a.anchor-link,
        h1 > a, h2 > a, h3 > a, h4 > a, h5 > a, h6 > a { display: none !important; }
        a { text-decoration: none !important; }
        .block-container { max-width: 1180px; padding-top: 2rem; padding-bottom: 4rem; }
        .app-title { font-size: 1.72rem; font-weight: 800; letter-spacing: -0.04em; color: #15243c; }
        .app-subtitle { color: #64748b; margin-top: .25rem; margin-bottom: 1.35rem; }
        .section-title { font-size: 1.22rem; font-weight: 750; color: #172033; margin: .2rem 0 1rem; }
        .soft-card {
            background: #ffffff; border: 1px solid #e2e8f0; border-radius: 14px;
            padding: 1.05rem 1.15rem; box-shadow: 0 4px 14px rgba(15, 23, 42, .04);
        }
        .notice-card {
            background: #eef5ff; border: 1px solid #cbdcf7; border-radius: 12px;
            padding: .9rem 1rem; color: #29476f;
        }
        .muted { color: #64748b; font-size: .92rem; }
        .money { font-size: 1.45rem; font-weight: 800; color: #17355f; }
        .status-row { display: flex; flex-wrap: wrap; gap: 7px; margin: .55rem 0 .25rem; }
        .status-step {
            padding: 5px 9px; border-radius: 999px; border: 1px solid #dbe3ed;
            background: #f8fafc; color: #8793a5; font-size: .78rem;
        }
        .status-step.done { background: #e8f0fb; border-color: #adc5e6; color: #214d82; }
        .status-step.current { background: #17355f; border-color: #17355f; color: #fff; font-weight: 700; }
        .stButton > button, .stDownloadButton > button {
            border-radius: 9px; min-height: 2.75rem; font-weight: 700;
            border: 1px solid #23466f; background: #23466f; color: #fff;
        }
        .stButton > button:hover, .stDownloadButton > button:hover {
            border-color: #17355f; background: #17355f; color: #fff;
        }
        [data-testid="stForm"] { border: 1px solid #e2e8f0; border-radius: 14px; background: #fff; }
        [data-testid="stMetric"] { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: .8rem 1rem; }
        [data-testid="stExpander"] { background: #fff; border-color: #e2e8f0; border-radius: 12px; }
        [data-testid="stSidebar"] { background: #eef2f6; border-right: 1px solid #dce3eb; }
        [data-testid="stFileUploaderDropzone"] { background: #f8fafc; border: 1px dashed #aab7c7; }
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
        } catch (e) {}
        </script>
        """,
        height=0,
    )


def app_header(description: str) -> None:
    st.markdown(f'<div class="app-title">{APP_TITLE}</div>', unsafe_allow_html=True)
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
        "flash": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def logout() -> None:
    for key in ["logged_in", "username", "role", "phone", "flash"]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()


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
    return f"#{order['id']}  {category_text(order['category'])}  ·  {order['status']}  ·  {date}"


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
    return (
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        'stroke="#3f5268" stroke-width="1.4" marker-start="url(#dimStart)" marker-end="url(#dimEnd)"/>'
        f'<text x="{label_x:.1f}" y="{label_y:.1f}" text-anchor="{anchor}" '
        f'font-size="13" font-weight="700" fill="#24364b">{html.escape(label)}</text>'
    )


def draw_milling_svg(width: float, length: float, thickness: float, holes: int) -> str:
    width = max(float(width), 0.1)
    length = max(float(length), 0.1)
    thickness = max(float(thickness), 0.1)
    scale = min(260 / width, 210 / length, 105 / thickness)
    sw, sl, stt = width * scale, length * scale, thickness * scale
    top_x, top_y = 45 + (280 - sw) / 2, 70 + (220 - sl) / 2
    side_x, side_y = 395 + (280 - sw) / 2, 120 + (120 - stt) / 2

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
                f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{radius:.1f}" fill="#fff" stroke="#17355f" stroke-width="1.5"/>'
            )

    svg = f"""
    <svg viewBox="0 0 720 390" width="100%" role="img" aria-label="밀링 규격 도면">
      <defs>
        <pattern id="millingHatch" width="9" height="9" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <line x1="0" y1="0" x2="0" y2="9" stroke="#9fb9d5" stroke-width="3"/>
        </pattern>
        <marker id="dimStart" markerWidth="7" markerHeight="7" refX="1" refY="3.5" orient="auto"><path d="M7,0 L0,3.5 L7,7" fill="#3f5268"/></marker>
        <marker id="dimEnd" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7" fill="#3f5268"/></marker>
      </defs>
      <rect x="10" y="10" width="330" height="350" rx="12" fill="#fff" stroke="#dde5ee"/>
      <rect x="380" y="10" width="330" height="350" rx="12" fill="#fff" stroke="#dde5ee"/>
      <text x="30" y="42" font-size="16" font-weight="700" fill="#172033">평면도</text>
      <text x="400" y="42" font-size="16" font-weight="700" fill="#172033">측면도</text>
      <rect x="{top_x:.1f}" y="{top_y:.1f}" width="{sw:.1f}" height="{sl:.1f}" fill="url(#millingHatch)" stroke="#1d5b88" stroke-width="2"/>
      {''.join(circles)}
      {dimension_line(top_x, top_y - 18, top_x + sw, top_y - 18, f'가로 W {width:g} mm', top_x + sw / 2, top_y - 27)}
      {dimension_line(top_x - 18, top_y, top_x - 18, top_y + sl, f'세로 L {length:g} mm', top_x - 25, top_y + sl / 2, 'end')}
      <rect x="{side_x:.1f}" y="{side_y:.1f}" width="{sw:.1f}" height="{stt:.1f}" fill="#b8c9da" stroke="#1d5b88" stroke-width="2"/>
      {dimension_line(side_x, side_y - 18, side_x + sw, side_y - 18, f'가로 W {width:g} mm', side_x + sw / 2, side_y - 27)}
      {dimension_line(side_x - 18, side_y, side_x - 18, side_y + stt, f'두께 T {thickness:g} mm', side_x - 25, side_y + stt / 2, 'end')}
      <text x="175" y="340" text-anchor="middle" font-size="13" fill="#64748b">가로 × 세로</text>
      <text x="545" y="340" text-anchor="middle" font-size="13" fill="#64748b">가로 × 두께</text>
    </svg>
    """
    return svg


def draw_lathe_svg(diameter: float, length: float) -> str:
    diameter = max(float(diameter), 0.1)
    length = max(float(length), 0.1)
    scale = min(370 / length, 210 / diameter, 175 / diameter)
    sl, sd = length * scale, diameter * scale
    body_x, body_y = 35 + (400 - sl) / 2, 83 + (220 - sd) / 2
    circle_r = sd / 2
    circle_x, circle_y = 575, 193
    svg = f"""
    <svg viewBox="0 0 720 390" width="100%" role="img" aria-label="선반 규격 도면">
      <defs>
        <linearGradient id="latheMetal" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#d9e4ee"/><stop offset=".5" stop-color="#9fb4c8"/><stop offset="1" stop-color="#d7e1ea"/></linearGradient>
        <marker id="dimStart" markerWidth="7" markerHeight="7" refX="1" refY="3.5" orient="auto"><path d="M7,0 L0,3.5 L7,7" fill="#3f5268"/></marker>
        <marker id="dimEnd" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7" fill="#3f5268"/></marker>
      </defs>
      <rect x="10" y="10" width="440" height="350" rx="12" fill="#fff" stroke="#dde5ee"/>
      <rect x="470" y="10" width="240" height="350" rx="12" fill="#fff" stroke="#dde5ee"/>
      <text x="30" y="42" font-size="16" font-weight="700" fill="#172033">측면도</text>
      <text x="490" y="42" font-size="16" font-weight="700" fill="#172033">정면도</text>
      <rect x="{body_x:.1f}" y="{body_y:.1f}" width="{sl:.1f}" height="{sd:.1f}" fill="url(#latheMetal)" stroke="#1d5b88" stroke-width="2"/>
      <line x1="{body_x - 12:.1f}" y1="{body_y + sd/2:.1f}" x2="{body_x + sl + 12:.1f}" y2="{body_y + sd/2:.1f}" stroke="#75869a" stroke-dasharray="7 5"/>
      {dimension_line(body_x, body_y - 20, body_x + sl, body_y - 20, f'길이 L {length:g} mm', body_x + sl / 2, body_y - 29)}
      {dimension_line(body_x - 20, body_y, body_x - 20, body_y + sd, f'지름 D {diameter:g} mm', body_x - 27, body_y + sd / 2, 'end')}
      <circle cx="{circle_x}" cy="{circle_y}" r="{circle_r:.1f}" fill="url(#latheMetal)" stroke="#1d5b88" stroke-width="2"/>
      <line x1="{circle_x - circle_r - 8:.1f}" y1="{circle_y}" x2="{circle_x + circle_r + 8:.1f}" y2="{circle_y}" stroke="#75869a" stroke-dasharray="7 5"/>
      {dimension_line(circle_x - circle_r, circle_y + circle_r + 24, circle_x + circle_r, circle_y + circle_r + 24, f'지름 D {diameter:g} mm', circle_x, circle_y + circle_r + 43)}
      <text x="230" y="340" text-anchor="middle" font-size="13" fill="#64748b">길이 × 지름</text>
      <text x="590" y="340" text-anchor="middle" font-size="13" fill="#64748b">원형 단면</text>
    </svg>
    """
    return svg


def show_svg(svg: str, height: int = 410) -> None:
    components.html(
        f'<div style="font-family:Pretendard,Noto Sans KR,Malgun Gothic,sans-serif;">{svg}</div>',
        height=height,
        scrolling=False,
    )


# -----------------------------------------------------------------------------
# 로그인 / 회원가입
# -----------------------------------------------------------------------------
def render_auth() -> None:
    app_header("회원가입 후 가공 신청과 진행 상황을 한곳에서 확인할 수 있습니다.")
    left, right = st.columns(2, gap="large")

    with left:
        st.markdown('<div class="section-title">로그인</div>', unsafe_allow_html=True)
        with st.form("login_form", clear_on_submit=False):
            login_id = st.text_input("아이디", key="login_id")
            login_pw = st.text_input("비밀번호", type="password", key="login_pw")
            login_submitted = st.form_submit_button("로그인", use_container_width=True)
        if login_submitted:
            user = authenticate(login_id, login_pw)
            if user is None:
                st.error("아이디 또는 비밀번호가 일치하지 않습니다.")
            else:
                st.session_state.logged_in = True
                st.session_state.username = user["username"]
                st.session_state.role = user["role"] or "customer"
                st.session_state.phone = user["phone"] or ""
                st.rerun()

        st.markdown(
            '<div class="notice-card"><b>대표 계정</b><br>대표 아이디로 로그인하면 모든 회원의 발주, 연락처, 첨부 도면, 견적 답변과 진행 상태를 관리할 수 있습니다.</div>',
            unsafe_allow_html=True,
        )

    with right:
        st.markdown('<div class="section-title">회원가입</div>', unsafe_allow_html=True)
        with st.form("register_form", clear_on_submit=False):
            reg_type = st.radio(
                "가입 유형", ["사업자 (B2B)", "개인 고객 (B2C)"], horizontal=True
            )
            reg_id = st.text_input("사용할 아이디", key="reg_id")
            reg_phone = st.text_input(
                "휴대폰 번호",
                placeholder="010-1234-5678",
                help="발주 확인과 견적 안내를 위해 사용합니다.",
            )
            reg_pw = st.text_input("비밀번호", type="password", key="reg_pw")
            reg_pw_check = st.text_input(
                "비밀번호 확인", type="password", key="reg_pw_check"
            )
            reg_submitted = st.form_submit_button("회원가입", use_container_width=True)
        if reg_submitted:
            if reg_pw != reg_pw_check:
                st.error("비밀번호와 비밀번호 확인이 일치하지 않습니다.")
            else:
                ok, message = register_user(reg_id, reg_pw, reg_type, reg_phone)
                (st.success if ok else st.error)(message)


# -----------------------------------------------------------------------------
# 고객 화면
# -----------------------------------------------------------------------------
def customer_sidebar() -> str:
    with st.sidebar:
        st.markdown(f"### {html.escape(st.session_state.username)} 님")
        st.caption(st.session_state.phone or "휴대폰 번호 미등록")
        page = st.radio("메뉴", ["새 발주 신청", "내 발주 내역", "계정 설정"])
        st.divider()
        if st.button("로그아웃", use_container_width=True):
            logout()
    return page


def render_customer_home() -> None:
    page = customer_sidebar()
    if page == "새 발주 신청":
        render_new_order()
    elif page == "내 발주 내역":
        render_my_orders()
    else:
        render_account_settings(is_admin=False)


def require_customer_phone() -> bool:
    if normalize_phone(st.session_state.phone):
        return True
    st.warning("발주 후 연락을 위해 계정 설정에서 휴대폰 번호를 먼저 등록해 주세요.")
    return False


def render_new_order() -> None:
    app_header("PPT 기준으로 MCT(밀링), CNC(선반), 기타 도면 첨부를 구분했습니다.")
    order_type = st.radio(
        "가공 방식",
        ["MCT(밀링)", "CNC(선반)", "기타 도면 첨부"],
        horizontal=True,
    )
    st.divider()
    if order_type == "MCT(밀링)":
        render_milling_order()
    elif order_type == "CNC(선반)":
        render_lathe_order()
    else:
        render_drawing_order()


def render_milling_order() -> None:
    left, right = st.columns([0.86, 1.14], gap="large")
    with left:
        st.markdown('<div class="section-title">밀링 규격 입력</div>', unsafe_allow_html=True)
        material = st.selectbox("재료", list(MATERIALS), key="m_material")
        c1, c2 = st.columns(2)
        with c1:
            width = st.number_input("가로 W (mm)", min_value=0.1, value=100.0, step=1.0)
            thickness = st.number_input("두께 T (mm)", min_value=0.1, value=10.0, step=1.0)
            quantity = st.number_input("수량 (개)", min_value=1, value=1, step=1)
        with c2:
            length = st.number_input("세로 L (mm)", min_value=0.1, value=150.0, step=1.0)
            holes = st.number_input("내부 홀 수량", min_value=0, value=0, step=1)
            kg_price = st.number_input(
                "재료 기준 단가 (원/kg)",
                min_value=0,
                value=int(MATERIALS[material]["default_price"]),
                step=500,
                help="예상 금액 계산용입니다. 최종 견적은 대표 관리자가 확정합니다.",
                key=f"m_price_{material}",
            )
        note = st.text_area("작업 요청 사항", placeholder="공차, 표면 처리, 납기 등 필요한 내용을 입력하세요.")

    density = MATERIALS[material]["density"]
    weight = width * length * thickness * density / 1_000_000
    estimate = (weight * kg_price + int(holes) * 1_000) * int(quantity)
    with right:
        st.markdown('<div class="section-title">규격 미리보기</div>', unsafe_allow_html=True)
        st.caption("평면도는 가로×세로, 측면도는 가로×두께입니다. 두 그림은 같은 축척을 사용합니다.")
        show_svg(draw_milling_svg(width, length, thickness, int(holes)))
        k1, k2 = st.columns(2)
        k1.metric("개당 예상 중량", f"{weight:,.3f} kg")
        k2.metric("예상 금액", money_text(estimate))
        st.caption("예상 금액은 재료비와 홀 가공 기준값입니다. 대표 관리자가 검토 후 최종 견적을 답변합니다.")
        if st.button("밀링 발주 접수", use_container_width=True):
            if require_customer_phone():
                order_id = create_order(
                    {
                        "username": st.session_state.username,
                        "category": "milling",
                        "material": material,
                        "details": f"가로 {width:g} × 세로 {length:g} × 두께 {thickness:g} mm, 내부 홀 {int(holes)}개",
                        "quantity": int(quantity),
                        "cost": estimate,
                        "width_mm": width,
                        "length_mm": length,
                        "thickness_mm": thickness,
                        "diameter_mm": None,
                        "hole_count": int(holes),
                        "unit_weight_kg": weight,
                        "request_note": note,
                        "attachment_name": "",
                        "attachment_mime": "",
                        "attachment_data": None,
                    }
                )
                st.success(f"발주 #{order_id}번이 접수되었습니다. 내 발주 내역에서 확인할 수 있습니다.")


def render_lathe_order() -> None:
    left, right = st.columns([0.86, 1.14], gap="large")
    with left:
        st.markdown('<div class="section-title">선반 규격 입력</div>', unsafe_allow_html=True)
        material = st.selectbox("재료", list(MATERIALS), key="l_material")
        c1, c2 = st.columns(2)
        with c1:
            diameter = st.number_input("지름 D (mm)", min_value=0.1, value=50.0, step=1.0)
            quantity = st.number_input("수량 (개)", min_value=1, value=1, step=1, key="l_qty")
        with c2:
            length = st.number_input("길이 L (mm)", min_value=0.1, value=150.0, step=1.0)
            kg_price = st.number_input(
                "재료 기준 단가 (원/kg)",
                min_value=0,
                value=int(MATERIALS[material]["default_price"]),
                step=500,
                help="예상 금액 계산용입니다. 최종 견적은 대표 관리자가 확정합니다.",
                key=f"l_price_{material}",
            )
        note = st.text_area("작업 요청 사항", placeholder="공차, 나사, 홈, 표면 처리, 납기 등을 입력하세요.", key="l_note")

    density = MATERIALS[material]["density"]
    weight = math.pi * (diameter / 2) ** 2 * length * density / 1_000_000
    estimate = weight * kg_price * int(quantity)
    with right:
        st.markdown('<div class="section-title">규격 미리보기</div>', unsafe_allow_html=True)
        st.caption("측면도는 길이×지름이며 정면도는 같은 지름의 원형 단면입니다. 두 그림은 같은 축척을 사용합니다.")
        show_svg(draw_lathe_svg(diameter, length))
        k1, k2 = st.columns(2)
        k1.metric("개당 예상 중량", f"{weight:,.3f} kg")
        k2.metric("예상 금액", money_text(estimate))
        st.caption("예상 금액은 재료비 기준값입니다. 대표 관리자가 검토 후 최종 견적을 답변합니다.")
        if st.button("선반 발주 접수", use_container_width=True):
            if require_customer_phone():
                order_id = create_order(
                    {
                        "username": st.session_state.username,
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
                        "request_note": note,
                        "attachment_name": "",
                        "attachment_mime": "",
                        "attachment_data": None,
                    }
                )
                st.success(f"발주 #{order_id}번이 접수되었습니다. 내 발주 내역에서 확인할 수 있습니다.")


def render_drawing_order() -> None:
    app_header_text = "도면을 올리면 대표 관리자가 검토 후 이 발주 내역에 견적과 답변을 남깁니다."
    st.markdown(f'<div class="notice-card">{app_header_text}</div>', unsafe_allow_html=True)
    with st.form("drawing_order_form"):
        c1, c2 = st.columns(2)
        with c1:
            material = st.selectbox("재료", ["도면에 표시", *MATERIALS.keys(), "협의 필요"])
            quantity = st.number_input("수량 (개)", min_value=1, value=1, step=1, key="d_qty")
        with c2:
            uploaded = st.file_uploader(
                "도면 파일",
                type=["jpg", "jpeg", "png", "pdf"],
                help="JPG, PNG, PDF 파일을 지원하며 최대 10MB까지 저장합니다.",
            )
            st.text_input("결제 방식", value="카드", disabled=True)
        note = st.text_area(
            "작업 요청 사항",
            placeholder="가공 부위, 공차, 재료, 납기 등 도면에서 바로 알기 어려운 내용을 적어 주세요.",
        )
        submitted = st.form_submit_button("도면 견적 요청", use_container_width=True)

    if submitted:
        if not require_customer_phone():
            return
        if uploaded is None:
            st.error("검토할 도면 파일을 첨부해 주세요.")
            return
        data = uploaded.getvalue()
        if len(data) > 10 * 1024 * 1024:
            st.error("도면 파일은 10MB 이하만 첨부할 수 있습니다.")
            return
        order_id = create_order(
            {
                "username": st.session_state.username,
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
                "request_note": note,
                "attachment_name": Path(uploaded.name).name,
                "attachment_mime": uploaded.type or "application/octet-stream",
                "attachment_data": data,
            }
        )
        st.success(f"도면 견적 요청 #{order_id}번이 접수되었습니다. 관리자 답변은 내 발주 내역에 표시됩니다.")


def render_my_orders() -> None:
    app_header("견적 답변과 가공 일정을 발주별로 확인할 수 있습니다.")
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
            st.markdown(f"**규격**  \n{order['details'] or '-'}")
            if order["request_note"]:
                st.markdown(f"**요청 사항**  \n{order['request_note']}")
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
        st.markdown("### 대표 관리자")
        st.caption(ADMIN_ID)
        page = st.radio("관리 메뉴", ["전체 발주 관리", "회원 연락처", "계정 설정"])
        st.divider()
        if st.button("로그아웃", use_container_width=True):
            logout()
    return page


def render_admin_home() -> None:
    page = admin_sidebar()
    if page == "전체 발주 관리":
        render_admin_orders()
    elif page == "회원 연락처":
        render_customer_contacts()
    else:
        render_account_settings(is_admin=True)


def render_admin_orders() -> None:
    app_header("모든 회원의 발주와 연락처를 확인하고 견적 답변 및 진행 상태를 저장합니다.")
    orders = get_orders()
    total = len(orders)
    waiting = sum(row["status"] in {"접수", "견적 검토"} for row in orders)
    drawing_waiting = sum(
        category_text(row["category"]) == "기타 도면 첨부" and not row["admin_reply"]
        for row in orders
    )
    shipped = sum(row["status"] == "출하" for row in orders)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("전체 발주", total)
    m2.metric("검토 필요", waiting)
    m3.metric("도면 답변 대기", drawing_waiting)
    m4.metric("출하 완료", shipped)

    st.markdown('<div class="section-title" style="margin-top:1.4rem">발주 검색</div>', unsafe_allow_html=True)
    f1, f2, f3 = st.columns([1, 1, 1.4])
    with f1:
        status_filter = st.selectbox("진행 상태", ["전체", *ORDER_STATUSES])
    with f2:
        category_filter = st.selectbox(
            "가공 방식", ["전체", "MCT(밀링)", "CNC(선반)", "기타 도면 첨부"]
        )
    with f3:
        keyword = st.text_input("아이디 / 휴대폰 / 발주번호 검색")

    normalized_keyword = keyword.strip().lower()
    filtered = []
    for row in orders:
        if status_filter != "전체" and row["status"] != status_filter:
            continue
        if category_filter != "전체" and category_text(row["category"]) != category_filter:
            continue
        haystack = f"{row['id']} {row['username']} {row['phone'] or ''}".lower()
        if normalized_keyword and normalized_keyword not in haystack:
            continue
        filtered.append(row)

    st.caption(f"검색 결과 {len(filtered)}건")
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

            st.markdown(f"**가공 / 재료 / 수량**  \n{category_text(order['category'])} / {order['material'] or '-'} / {order['quantity']}개")
            st.markdown(f"**규격**  \n{order['details'] or '-'}")
            if order["request_note"]:
                st.markdown(f"**고객 요청 사항**  \n{order['request_note']}")
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
                save = st.form_submit_button("답변과 진행 상태 저장", use_container_width=True)
            if save:
                update_order_by_admin(order["id"], new_status, quote, reply)
                st.success(f"발주 #{order['id']}번의 내용을 저장했습니다.")
                st.rerun()


def render_customer_contacts() -> None:
    app_header("발주 후 연락할 회원의 휴대폰 번호를 확인합니다.")
    with db_connection() as conn:
        users = conn.execute(
            """
            SELECT u.username, u.usertype, u.phone, u.created_at, COUNT(o.id) AS order_count
            FROM users u
            LEFT JOIN orders o ON o.username=u.username
            WHERE COALESCE(u.role, 'customer')='customer'
            GROUP BY u.username, u.usertype, u.phone, u.created_at
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
              <span class="muted">{html.escape(user['usertype'] or '-')} · {html.escape(user['phone'] or '휴대폰 미등록')} · 발주 {user['order_count']}건</span>
            </div>
            """,
            unsafe_allow_html=True,
        )


def main() -> None:
    st.set_page_config(
        page_title=APP_TITLE,
        layout="wide",
        initial_sidebar_state="expanded",
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
        render_auth()
    elif st.session_state.role == "admin":
        render_admin_home()
    else:
        render_customer_home()


if __name__ == "__main__":
    main()
