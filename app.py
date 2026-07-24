from __future__ import annotations

import argparse
import cgi
import io
import ipaddress
import json
import mimetypes
import os
import re
import sqlite3
import sys
import threading
import time
import traceback
import uuid
import warnings
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape
from PIL import Image, ImageOps, UnidentifiedImageError

from marketplace.db import (
    INITIAL_BALANCE,
    REPORT_THRESHOLD,
    allow_action,
    audit,
    connect,
    database_path,
    ensure_admin,
    has_private_permissions,
    init_database,
    seed_demo,
    set_private_permissions,
    utc_now,
)
from marketplace.security import (
    hash_password,
    new_token,
    normalize_username,
    token_digest,
    validate_password,
    validate_totp_secret,
    validate_username,
    verify_password,
    verify_totp,
)


ROOT = Path(__file__).resolve().parent
TEMPLATE_DIR = ROOT / "templates"
STATIC_DIR = ROOT / "static"
DEFAULT_UPLOAD_DIR = ROOT / "instance" / "uploads"
MAX_FORM_BYTES = 6 * 1024 * 1024
MAX_IMAGE_BYTES = 4 * 1024 * 1024
MAX_IMAGE_DIMENSION = 6_000
MAX_IMAGE_PIXELS = 20_000_000
MAX_PRODUCTS_PER_USER = 30
SIGNUP_LIMIT_PER_HOUR = 2
LOGIN_IP_LIMIT = 30
LOGIN_ACCOUNT_LIMIT = 7
REPORT_LIMIT_PER_DAY = 10
REPORT_MIN_ACCOUNT_AGE_SECONDS = 60 * 60
SESSION_SECONDS = 12 * 60 * 60


def is_production() -> bool:
    return os.environ.get("APP_ENV", "development").strip().lower() == "production"


def resolve_client_ip(
    peer_ip: str,
    forwarded_for: str,
    trusted_proxy_ips: str,
) -> str:
    trusted = {
        value.strip()
        for value in trusted_proxy_ips.split(",")
        if value.strip()
    }
    if peer_ip not in trusted or not forwarded_for:
        return peer_ip
    candidate = forwarded_for.split(",", 1)[0].strip()
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return peer_ip


class StreamConnectionLimiter:
    def __init__(self, total_limit: int = 50, per_ip_limit: int = 3) -> None:
        self.total_limit = total_limit
        self.per_ip_limit = per_ip_limit
        self.total = 0
        self.by_ip: dict[str, int] = {}
        self.lock = threading.Lock()

    def acquire(self, ip_address: str) -> bool:
        with self.lock:
            current = self.by_ip.get(ip_address, 0)
            if self.total >= self.total_limit or current >= self.per_ip_limit:
                return False
            self.total += 1
            self.by_ip[ip_address] = current + 1
            return True

    def release(self, ip_address: str) -> None:
        with self.lock:
            self.total = max(0, self.total - 1)
            current = self.by_ip.get(ip_address, 0)
            if current <= 1:
                self.by_ip.pop(ip_address, None)
            else:
                self.by_ip[ip_address] = current - 1


STREAM_LIMITER = StreamConnectionLimiter()


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class, max_workers: int = 64):
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(server_address, handler_class)

    def process_request(self, request, client_address) -> None:
        if not self._worker_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()

NOTICE_MESSAGES = {
    "signup": "가입이 완료되었습니다. 되살림에 오신 것을 환영해요.",
    "login": "안전하게 로그인했습니다.",
    "logout": "로그아웃했습니다.",
    "profile": "프로필을 저장했습니다.",
    "password": "비밀번호를 변경했습니다. 다른 로그인은 모두 종료했습니다.",
    "product-created": "상품을 등록했습니다.",
    "product-updated": "상품 정보를 수정했습니다.",
    "product-deleted": "상품을 삭제했습니다.",
    "report": "신고를 접수했습니다.",
    "transfer": "송금을 완료했습니다.",
    "admin": "관리 작업을 반영했습니다.",
}


class RequestError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def format_money(value: int) -> str:
    return f"{int(value):,}원"


def format_date(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y.%m.%d %H:%M")
    except (ValueError, TypeError):
        return value


JINJA = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(("html", "xml")),
    trim_blocks=True,
    lstrip_blocks=True,
)
JINJA.globals.update(
    format_money=format_money,
    format_date=format_date,
    report_threshold=REPORT_THRESHOLD,
)


def upload_directory() -> Path:
    return Path(os.environ.get("MARKET_UPLOAD_DIR", DEFAULT_UPLOAD_DIR)).resolve()


def normalize_image(data: bytes) -> tuple[str, bytes, int, int]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as probe:
                image_format = (probe.format or "").upper()
                width, height = probe.size
                probe.verify()

            if image_format not in {"PNG", "JPEG", "WEBP"}:
                raise RequestError(400, "PNG, JPEG, WebP 이미지만 등록할 수 있습니다.")
            if (
                width <= 0
                or height <= 0
                or width > MAX_IMAGE_DIMENSION
                or height > MAX_IMAGE_DIMENSION
                or width * height > MAX_IMAGE_PIXELS
            ):
                raise RequestError(400, "이미지 해상도가 허용 범위를 초과했습니다.")

            with Image.open(io.BytesIO(data)) as source:
                source.load()
                normalized = ImageOps.exif_transpose(source)
                width, height = normalized.size
                has_alpha = normalized.mode in {"RGBA", "LA"} or (
                    normalized.mode == "P" and "transparency" in normalized.info
                )
                if image_format == "JPEG":
                    extension = ".jpg"
                    prepared = normalized.convert("RGB")
                    save_options = {
                        "format": "JPEG",
                        "quality": 88,
                        "optimize": True,
                        "progressive": True,
                    }
                elif image_format == "PNG":
                    extension = ".png"
                    prepared = normalized.convert("RGBA" if has_alpha else "RGB")
                    save_options = {"format": "PNG", "optimize": True}
                else:
                    extension = ".webp"
                    prepared = normalized.convert("RGBA" if has_alpha else "RGB")
                    save_options = {
                        "format": "WEBP",
                        "quality": 88,
                        "method": 6,
                    }
                output = io.BytesIO()
                prepared.save(output, **save_options)
                prepared.close()
                normalized_bytes = output.getvalue()
    except RequestError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        SyntaxError,
        UnidentifiedImageError,
        ValueError,
    ) as error:
        raise RequestError(400, "손상되었거나 지원하지 않는 이미지입니다.") from error

    if len(normalized_bytes) > MAX_IMAGE_BYTES:
        raise RequestError(413, "재처리된 상품 사진은 4MB 이하여야 합니다.")
    return extension, normalized_bytes, width, height


def inspect_image(data: bytes) -> tuple[str, int, int]:
    extension, _, width, height = normalize_image(data)
    return extension, width, height


def delete_uploaded_image(image_path: str | None) -> None:
    if not image_path or not image_path.startswith("/uploads/"):
        return
    target_directory = upload_directory()
    candidate = (target_directory / image_path.removeprefix("/uploads/")).resolve()
    if candidate.is_relative_to(target_directory) and candidate.is_file():
        candidate.unlink()


def cleanup_orphan_uploads() -> int:
    target_directory = upload_directory()
    if not target_directory.is_dir():
        return 0
    connection = connect()
    try:
        referenced = {
            Path(row["image_path"]).name
            for row in connection.execute(
                """
                SELECT image_path FROM products
                WHERE image_path LIKE '/uploads/%' AND status <> 'deleted'
                """
            ).fetchall()
        }
    finally:
        connection.close()
    removed = 0
    for candidate in target_directory.iterdir():
        if (
            candidate.is_file()
            and candidate.name != ".gitkeep"
            and candidate.name not in referenced
        ):
            candidate.unlink()
            removed += 1
    return removed


class MarketplaceHandler(BaseHTTPRequestHandler):
    server_version = "ResalimMarket/1.0"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format_string: str, *args: object) -> None:
        sys.stderr.write(
            f"[{self.log_date_time_string()}] "
            f"{getattr(self, 'request_ip', self.client_address[0])} "
            f"{format_string % args}\n"
        )

    def do_GET(self) -> None:
        self._run(self._dispatch_get)

    def do_POST(self) -> None:
        self._run(self._dispatch_post)

    def do_HEAD(self) -> None:
        self._run(self._dispatch_get, head_only=True)

    def _run(self, action, head_only: bool = False) -> None:
        self.head_only = head_only
        self.pending_cookies: list[str] = []
        try:
            self._prepare_request()
            action()
        except RequestError as error:
            self._render_error(error.status, error.message)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            return
        except Exception:
            traceback.print_exc()
            self._render_error(500, "요청을 처리하는 중 문제가 발생했습니다.")

    def _prepare_request(self) -> None:
        parsed = urlparse(self.path)
        self.route_path = parsed.path
        if self.route_path != "/" and self.route_path.endswith("/"):
            self.route_path = self.route_path.rstrip("/")
        self.query = parse_qs(parsed.query, keep_blank_values=True)
        self.request_ip = resolve_client_ip(
            self.client_address[0],
            self.headers.get("X-Forwarded-For", ""),
            os.environ.get("TRUSTED_PROXY_IPS", ""),
        )
        self.cookies = SimpleCookie()
        try:
            self.cookies.load(self.headers.get("Cookie", ""))
        except Exception:
            self.cookies = SimpleCookie()

        csrf_cookie = self.cookies.get("csrf_token")
        if csrf_cookie and len(csrf_cookie.value) >= 32:
            self.csrf_token = csrf_cookie.value
        else:
            self.csrf_token = new_token()
            self._queue_cookie(
                "csrf_token",
                self.csrf_token,
                max_age=SESSION_SECONDS,
                http_only=True,
            )
        self.current_user = self._load_current_user()

    def _load_current_user(self):
        session_cookie = self.cookies.get("session")
        if not session_cookie:
            return None
        digest = token_digest(session_cookie.value)
        connection = connect()
        try:
            connection.execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (utc_now(),)
            )
            row = connection.execute(
                """
                SELECT u.*
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = ? AND s.expires_at > ?
                """,
                (digest, utc_now()),
            ).fetchone()
            if row and row["status"] == "active":
                connection.commit()
                return row
            if row:
                connection.execute(
                    "DELETE FROM sessions WHERE token_hash = ?", (digest,)
                )
            connection.commit()
            return None
        finally:
            connection.close()

    def _queue_cookie(
        self,
        name: str,
        value: str,
        *,
        max_age: int | None = None,
        http_only: bool = False,
    ) -> None:
        parts = [f"{name}={value}", "Path=/", "SameSite=Lax"]
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        if http_only:
            parts.append("HttpOnly")
        if is_production() or os.environ.get("COOKIE_SECURE") == "1":
            parts.append("Secure")
        self.pending_cookies.append("; ".join(parts))

    def _common_headers(self, *, cache: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; connect-src 'self'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
            "object-src 'none'",
        )
        if is_production():
            self.send_header(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        self.send_header(
            "Cache-Control",
            "public, max-age=3600" if cache else "no-store",
        )
        for cookie in self.pending_cookies:
            self.send_header("Set-Cookie", cookie)

    def _send(
        self,
        body: bytes,
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
        *,
        cache: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._common_headers(cache=cache)
        self.end_headers()
        if not self.head_only:
            self.wfile.write(body)

    def _render(self, template_name: str, status: int = 200, **context) -> None:
        notice_key = self._query_value("notice")
        base_context = {
            "current_user": self.current_user,
            "csrf_token": self.csrf_token,
            "current_path": self.route_path,
            "notice": NOTICE_MESSAGES.get(notice_key),
            "report_threshold": REPORT_THRESHOLD,
        }
        base_context.update(context)
        body = JINJA.get_template(template_name).render(**base_context).encode("utf-8")
        self._send(body, status)

    def _json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self._send(body, status, "application/json; charset=utf-8")

    def _redirect(self, path: str, status: int = 303) -> None:
        self.send_response(status)
        self.send_header("Location", path)
        self._common_headers()
        self.end_headers()

    def _render_error(self, status: int, message: str) -> None:
        if getattr(self, "wfile", None) is None:
            return
        title = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else "오류"
        try:
            self._render("error.html", status=status, error_title=title, error_message=message)
        except Exception:
            body = f"{status} {title}".encode("utf-8")
            self._send(body, status, "text/plain; charset=utf-8")

    def _query_value(self, name: str, default: str = "") -> str:
        values = self.query.get(name)
        return values[0] if values else default

    def _require_user(self):
        if not self.current_user:
            self._redirect("/login?notice=login-required")
            return None
        return self.current_user

    def _require_admin(self):
        user = self._require_user()
        if not user:
            return None
        if user["role"] != "admin":
            raise RequestError(403, "관리자만 접근할 수 있습니다.")
        return user

    def _read_form(self) -> tuple[dict[str, str], dict[str, cgi.FieldStorage]]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise RequestError(400, "잘못된 요청 크기입니다.") from error
        if length <= 0 or length > MAX_FORM_BYTES:
            status = 413 if length > MAX_FORM_BYTES else 400
            raise RequestError(status, "요청 본문 크기가 허용 범위를 벗어났습니다.")

        content_type = self.headers.get("Content-Type", "")
        body = self.rfile.read(length)
        fields: dict[str, str] = {}
        files: dict[str, cgi.FieldStorage] = {}
        if content_type.startswith("multipart/form-data"):
            environ = {
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": content_type,
                "CONTENT_LENGTH": str(length),
            }
            form = cgi.FieldStorage(
                fp=io.BytesIO(body),
                headers=self.headers,
                environ=environ,
                keep_blank_values=True,
            )
            if form.list:
                for item in form.list:
                    if item.filename:
                        files[item.name] = item
                    else:
                        fields[item.name] = item.value
        elif content_type.startswith("application/x-www-form-urlencoded"):
            decoded = body.decode("utf-8", "strict")
            fields = {
                key: values[-1]
                for key, values in parse_qs(
                    decoded, keep_blank_values=True, max_num_fields=100
                ).items()
            }
        else:
            raise RequestError(415, "지원하지 않는 요청 형식입니다.")
        return fields, files

    def _check_csrf(self, fields: dict[str, str]) -> None:
        supplied = fields.get("csrf_token") or self.headers.get("X-CSRF-Token", "")
        if not supplied or not hmac_compare(supplied, self.csrf_token):
            raise RequestError(403, "요청 검증에 실패했습니다. 페이지를 새로고침해 주세요.")

    def _dispatch_get(self) -> None:
        path = self.route_path
        if path.startswith("/static/"):
            self._serve_file(STATIC_DIR, path.removeprefix("/static/"), cache=True)
            return
        if path.startswith("/uploads/"):
            self._serve_upload(path.removeprefix("/uploads/"))
            return
        if path == "/":
            self._home()
        elif path == "/signup":
            self._render("auth.html", mode="signup")
        elif path == "/login":
            self._render("auth.html", mode="login")
        elif path == "/users":
            self._users()
        elif path == "/mypage":
            self._mypage()
        elif path == "/products/new":
            if self._require_user():
                self._render("product_form.html", product=None)
        elif path == "/transfers":
            self._transfers()
        elif path == "/admin":
            self._admin()
        elif path == "/api/chat/stream":
            self._chat_stream()
        else:
            product_edit = re.fullmatch(r"/products/(\d+)/edit", path)
            product_detail = re.fullmatch(r"/products/(\d+)", path)
            user_detail = re.fullmatch(r"/users/(\d+)", path)
            direct_chat = re.fullmatch(r"/messages/(\d+)", path)
            report = re.fullmatch(r"/reports/(user|product)/(\d+)", path)
            if product_edit:
                self._product_edit_page(int(product_edit.group(1)))
            elif product_detail:
                self._product_detail(int(product_detail.group(1)))
            elif user_detail:
                self._user_detail(int(user_detail.group(1)))
            elif direct_chat:
                self._direct_chat(int(direct_chat.group(1)))
            elif report:
                self._report_page(report.group(1), int(report.group(2)))
            else:
                raise RequestError(404, "페이지를 찾을 수 없습니다.")

    def _dispatch_post(self) -> None:
        fields, files = self._read_form()
        self._check_csrf(fields)
        path = self.route_path
        if path == "/signup":
            self._signup(fields)
        elif path == "/login":
            self._login(fields)
        elif path == "/logout":
            self._logout()
        elif path == "/mypage":
            self._update_profile(fields)
        elif path == "/mypage/password":
            self._update_password(fields)
        elif path == "/products/new":
            self._create_product(fields, files)
        elif path == "/transfers":
            self._create_transfer(fields)
        elif path == "/api/chat/global":
            self._send_global_message(fields)
        else:
            product_edit = re.fullmatch(r"/products/(\d+)/edit", path)
            product_delete = re.fullmatch(r"/products/(\d+)/delete", path)
            direct_chat = re.fullmatch(r"/messages/(\d+)", path)
            report = re.fullmatch(r"/reports/(user|product)/(\d+)", path)
            admin_user = re.fullmatch(r"/admin/users/(\d+)/(suspend|activate)", path)
            admin_balance = re.fullmatch(r"/admin/users/(\d+)/balance", path)
            admin_product = re.fullmatch(
                r"/admin/products/(\d+)/(delete|activate)", path
            )
            admin_report = re.fullmatch(
                r"/admin/reports/(\d+)/(resolve|restore)", path
            )
            admin_message = re.fullmatch(r"/admin/messages/(\d+)/delete", path)
            if product_edit:
                self._update_product(int(product_edit.group(1)), fields, files)
            elif product_delete:
                self._delete_product(int(product_delete.group(1)))
            elif direct_chat:
                self._send_direct_message(int(direct_chat.group(1)), fields)
            elif report:
                self._create_report(report.group(1), int(report.group(2)), fields)
            elif admin_user:
                self._admin_user_action(
                    int(admin_user.group(1)), admin_user.group(2)
                )
            elif admin_balance:
                self._admin_grant_balance(int(admin_balance.group(1)), fields)
            elif admin_product:
                self._admin_product_action(
                    int(admin_product.group(1)), admin_product.group(2)
                )
            elif admin_report:
                self._admin_resolve_report(
                    int(admin_report.group(1)), admin_report.group(2)
                )
            elif admin_message:
                self._admin_delete_message(int(admin_message.group(1)))
            else:
                raise RequestError(404, "페이지를 찾을 수 없습니다.")

    def _serve_file(self, base: Path, relative: str, *, cache: bool) -> None:
        candidate = (base / relative).resolve()
        base_resolved = base.resolve()
        if not candidate.is_relative_to(base_resolved) or not candidate.is_file():
            raise RequestError(404, "파일을 찾을 수 없습니다.")
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self._send(candidate.read_bytes(), content_type=content_type, cache=cache)

    def _serve_upload(self, relative: str) -> None:
        image_path = f"/uploads/{relative}"
        connection = connect()
        try:
            product = connection.execute(
                """
                SELECT p.seller_id, p.status, u.status AS seller_status
                FROM products p
                JOIN users u ON u.id = p.seller_id
                WHERE p.image_path = ?
                LIMIT 1
                """,
                (image_path,),
            ).fetchone()
        finally:
            connection.close()
        if not product:
            raise RequestError(404, "파일을 찾을 수 없습니다.")
        privileged = self.current_user and (
            self.current_user["role"] == "admin"
            or self.current_user["id"] == product["seller_id"]
        )
        if (
            product["status"] != "active"
            or product["seller_status"] != "active"
        ) and not privileged:
            raise RequestError(404, "파일을 찾을 수 없습니다.")
        self._serve_file(upload_directory(), relative, cache=False)

    def _home(self) -> None:
        search = self._query_value("q").strip()[:80]
        connection = connect()
        try:
            parameters: list[object] = []
            condition = "p.status = 'active' AND u.status = 'active'"
            if search:
                escaped = (
                    search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                )
                condition += (
                    " AND (p.name LIKE ? ESCAPE '\\' OR "
                    "p.description LIKE ? ESCAPE '\\')"
                )
                needle = f"%{escaped}%"
                parameters.extend([needle, needle])
            products = connection.execute(
                f"""
                SELECT p.*, u.display_name AS seller_name
                FROM products p
                JOIN users u ON u.id = p.seller_id
                WHERE {condition}
                ORDER BY p.created_at DESC
                LIMIT 60
                """,
                parameters,
            ).fetchall()
            counts = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM products WHERE status = 'active') AS products,
                    (SELECT COUNT(*) FROM users WHERE status = 'active') AS users,
                    (SELECT COUNT(*) FROM transfers) AS transfers
                """
            ).fetchone()
            messages = connection.execute(
                """
                SELECT m.id, m.body, m.created_at, u.display_name, u.id AS sender_id
                FROM messages m
                JOIN users u ON u.id = m.sender_id
                WHERE m.recipient_id IS NULL AND u.status = 'active'
                ORDER BY m.id DESC
                LIMIT 25
                """
            ).fetchall()
        finally:
            connection.close()
        self._render(
            "home.html",
            products=products,
            counts=counts,
            messages=list(reversed(messages)),
            search=search,
        )

    def _signup(self, fields: dict[str, str]) -> None:
        username = normalize_username(fields.get("username", ""))
        display_name = fields.get("display_name", "").strip()
        password = fields.get("password", "")
        password_confirm = fields.get("password_confirm", "")
        error = validate_username(username)
        if not error and not 2 <= len(display_name) <= 30:
            error = "계정명은 2~30자로 입력해주세요."
        if not error:
            error = validate_password(password, username)
        if not error and password != password_confirm:
            error = "비밀번호 확인이 일치하지 않습니다."
        if error:
            self._render(
                "auth.html",
                status=400,
                mode="signup",
                error=error,
                values={"username": username, "display_name": display_name},
            )
            return
        if not allow_action(
            "signup_ip",
            self.request_ip,
            SIGNUP_LIMIT_PER_HOUR,
            60 * 60,
        ):
            self._render(
                "auth.html",
                status=429,
                mode="signup",
                error="회원가입 요청이 너무 많습니다. 한 시간 후 다시 시도해주세요.",
                values={"username": username, "display_name": display_name},
            )
            return
        connection = connect()
        try:
            cursor = connection.execute(
                """
                INSERT INTO users(
                    username, display_name, password_hash, balance, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    username,
                    display_name,
                    hash_password(password),
                    INITIAL_BALANCE,
                    utc_now(),
                ),
            )
            user_id = cursor.lastrowid
            audit(connection, user_id, "signup", "user", user_id)
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            self._render(
                "auth.html",
                status=409,
                mode="signup",
                error="이미 사용 중인 아이디입니다.",
                values={"username": username, "display_name": display_name},
            )
            return
        finally:
            connection.close()
        self._start_session(int(user_id))
        self._redirect("/?notice=signup")

    def _login(self, fields: dict[str, str]) -> None:
        username = normalize_username(fields.get("username", ""))
        password = fields.get("password", "")
        ip_allowed = allow_action(
            "login_ip", self.request_ip, LOGIN_IP_LIMIT, 5 * 60
        )
        account_allowed = ip_allowed and allow_action(
            "login_account", username or "-", LOGIN_ACCOUNT_LIMIT, 5 * 60
        )
        if not account_allowed:
            self._render(
                "auth.html",
                status=429,
                mode="login",
                error="로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.",
                values={"username": username},
            )
            return
        connection = connect()
        try:
            user = connection.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        finally:
            connection.close()
        if (
            not user
            or user["status"] != "active"
            or not verify_password(password, user["password_hash"])
        ):
            self._render(
                "auth.html",
                status=401,
                mode="login",
                error="아이디 또는 비밀번호를 확인해주세요.",
                values={"username": username},
            )
            return
        if user["role"] == "admin":
            totp_secret = os.environ.get("ADMIN_TOTP_SECRET", "")
            if totp_secret and not verify_totp(
                totp_secret,
                fields.get("otp_code", ""),
            ):
                self._render(
                    "auth.html",
                    status=401,
                    mode="login",
                    error="관리자 2차 인증코드를 확인해주세요.",
                    values={"username": username},
                )
                return
        self._start_session(user["id"])
        self._redirect("/?notice=login")

    def _start_session(self, user_id: int) -> None:
        raw_token = new_token(36)
        expires = datetime.now(UTC) + timedelta(seconds=SESSION_SECONDS)
        connection = connect()
        try:
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            connection.execute(
                """
                INSERT INTO sessions(token_hash, user_id, expires_at, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    token_digest(raw_token),
                    user_id,
                    expires.isoformat(timespec="seconds"),
                    utc_now(),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        self._queue_cookie(
            "session", raw_token, max_age=SESSION_SECONDS, http_only=True
        )

    def _logout(self) -> None:
        session_cookie = self.cookies.get("session")
        if session_cookie:
            connection = connect()
            try:
                connection.execute(
                    "DELETE FROM sessions WHERE token_hash = ?",
                    (token_digest(session_cookie.value),),
                )
                connection.commit()
            finally:
                connection.close()
        self._queue_cookie("session", "", max_age=0, http_only=True)
        self._redirect("/?notice=logout")

    def _users(self) -> None:
        if not self._require_user():
            return
        search = self._query_value("q").strip()[:50]
        connection = connect()
        try:
            if search:
                escaped = (
                    search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                )
                users = connection.execute(
                    """
                    SELECT id, username, display_name, bio, role, created_at
                    FROM users
                    WHERE status = 'active'
                      AND (username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\')
                    ORDER BY display_name
                    LIMIT 50
                    """,
                    (f"%{escaped}%", f"%{escaped}%"),
                ).fetchall()
            else:
                users = connection.execute(
                    """
                    SELECT id, username, display_name, bio, role, created_at
                    FROM users
                    WHERE status = 'active'
                    ORDER BY created_at DESC
                    LIMIT 50
                    """
                ).fetchall()
        finally:
            connection.close()
        self._render("users.html", users=users, search=search)

    def _user_detail(self, user_id: int) -> None:
        if not self._require_user():
            return
        connection = connect()
        try:
            user = connection.execute(
                """
                SELECT id, username, display_name, bio, role, status, created_at
                FROM users WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
            if not user or (user["status"] != "active" and self.current_user["role"] != "admin"):
                raise RequestError(404, "사용자를 찾을 수 없습니다.")
            products = connection.execute(
                """
                SELECT * FROM products
                WHERE seller_id = ? AND status = 'active'
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()
        finally:
            connection.close()
        self._render("user_detail.html", profile=user, products=products)

    def _mypage(self) -> None:
        user = self._require_user()
        if not user:
            return
        connection = connect()
        try:
            products = connection.execute(
                """
                SELECT * FROM products
                WHERE seller_id = ? AND status <> 'deleted'
                ORDER BY created_at DESC
                """,
                (user["id"],),
            ).fetchall()
            sent = connection.execute(
                """
                SELECT t.*, u.display_name AS other_name
                FROM transfers t JOIN users u ON u.id = t.recipient_id
                WHERE t.sender_id = ? ORDER BY t.id DESC LIMIT 5
                """,
                (user["id"],),
            ).fetchall()
            received = connection.execute(
                """
                SELECT t.*, u.display_name AS other_name
                FROM transfers t JOIN users u ON u.id = t.sender_id
                WHERE t.recipient_id = ? ORDER BY t.id DESC LIMIT 5
                """,
                (user["id"],),
            ).fetchall()
        finally:
            connection.close()
        self._render(
            "mypage.html", products=products, sent=sent, received=received
        )

    def _update_profile(self, fields: dict[str, str]) -> None:
        user = self._require_user()
        if not user:
            return
        display_name = fields.get("display_name", "").strip()
        bio = fields.get("bio", "").strip()
        if not 2 <= len(display_name) <= 30:
            raise RequestError(400, "계정명은 2~30자로 입력해주세요.")
        if len(bio) > 300:
            raise RequestError(400, "소개글은 300자 이하여야 합니다.")
        connection = connect()
        try:
            connection.execute(
                "UPDATE users SET display_name = ?, bio = ? WHERE id = ?",
                (display_name, bio, user["id"]),
            )
            audit(connection, user["id"], "update_profile", "user", user["id"])
            connection.commit()
        finally:
            connection.close()
        self._redirect("/mypage?notice=profile")

    def _update_password(self, fields: dict[str, str]) -> None:
        user = self._require_user()
        if not user:
            return
        current = fields.get("current_password", "")
        password = fields.get("new_password", "")
        confirm = fields.get("new_password_confirm", "")
        if not verify_password(current, user["password_hash"]):
            raise RequestError(400, "현재 비밀번호가 올바르지 않습니다.")
        error = validate_password(password, user["username"])
        if error:
            raise RequestError(400, error)
        if password != confirm:
            raise RequestError(400, "새 비밀번호 확인이 일치하지 않습니다.")
        connection = connect()
        try:
            connection.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(password), user["id"]),
            )
            connection.execute(
                "DELETE FROM sessions WHERE user_id = ?",
                (user["id"],),
            )
            audit(connection, user["id"], "change_password", "user", user["id"])
            connection.commit()
        finally:
            connection.close()
        self._start_session(user["id"])
        self._redirect("/mypage?notice=password")

    def _product_detail(self, product_id: int) -> None:
        connection = connect()
        try:
            product = connection.execute(
                """
                SELECT p.*, u.display_name AS seller_name, u.username AS seller_username,
                       u.status AS seller_status
                FROM products p JOIN users u ON u.id = p.seller_id
                WHERE p.id = ?
                """,
                (product_id,),
            ).fetchone()
        finally:
            connection.close()
        if not product:
            raise RequestError(404, "상품을 찾을 수 없습니다.")
        privileged = self.current_user and (
            self.current_user["id"] == product["seller_id"]
            or self.current_user["role"] == "admin"
        )
        if (
            product["status"] != "active"
            or product["seller_status"] != "active"
        ) and not privileged:
            raise RequestError(404, "상품을 찾을 수 없습니다.")
        self._render("product_detail.html", product=product)

    def _product_edit_page(self, product_id: int) -> None:
        user = self._require_user()
        if not user:
            return
        product = self._owned_product(product_id, user["id"])
        self._render("product_form.html", product=product)

    def _owned_product(self, product_id: int, user_id: int):
        connection = connect()
        try:
            product = connection.execute(
                "SELECT * FROM products WHERE id = ? AND seller_id = ?",
                (product_id, user_id),
            ).fetchone()
        finally:
            connection.close()
        if not product or product["status"] == "deleted":
            raise RequestError(404, "관리할 수 있는 상품을 찾지 못했습니다.")
        return product

    def _validate_product(self, fields: dict[str, str]) -> tuple[str, str, int]:
        name = fields.get("name", "").strip()
        description = fields.get("description", "").strip()
        price_text = fields.get("price", "").replace(",", "").strip()
        if not 2 <= len(name) <= 80:
            raise RequestError(400, "상품명은 2~80자로 입력해주세요.")
        if not 10 <= len(description) <= 2000:
            raise RequestError(400, "상품 설명은 10~2,000자로 입력해주세요.")
        if not price_text.isdigit():
            raise RequestError(400, "가격은 0 이상의 숫자로 입력해주세요.")
        price = int(price_text)
        if price > 100_000_000:
            raise RequestError(400, "가격은 1억 원 이하여야 합니다.")
        return name, description, price

    def _save_image(
        self, files: dict[str, cgi.FieldStorage], previous: str | None = None
    ) -> str | None:
        upload = files.get("image")
        if upload is None or not upload.filename:
            return previous
        data = upload.file.read(MAX_IMAGE_BYTES + 1)
        if len(data) > MAX_IMAGE_BYTES:
            raise RequestError(413, "상품 사진은 4MB 이하여야 합니다.")
        extension, normalized_data, _, _ = normalize_image(data)
        target_directory = upload_directory()
        directory_created = not target_directory.exists()
        target_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory_created:
            set_private_permissions(target_directory, 0o700)
        filename = f"{uuid.uuid4().hex}{extension}"
        target = target_directory / filename
        with target.open("xb") as file:
            file.write(normalized_data)
        set_private_permissions(target, 0o600)
        return f"/uploads/{filename}"

    def _create_product(
        self,
        fields: dict[str, str],
        files: dict[str, cgi.FieldStorage],
    ) -> None:
        user = self._require_user()
        if not user:
            return
        connection = connect()
        try:
            product_count = connection.execute(
                """
                SELECT COUNT(*) AS count FROM products
                WHERE seller_id = ? AND status <> 'deleted'
                """,
                (user["id"],),
            ).fetchone()["count"]
        finally:
            connection.close()
        if product_count >= MAX_PRODUCTS_PER_USER:
            raise RequestError(
                429, f"사용자당 최대 {MAX_PRODUCTS_PER_USER}개의 상품을 등록할 수 있습니다."
            )
        if not allow_action(
            "product_create", str(user["id"]), MAX_PRODUCTS_PER_USER, 24 * 60 * 60
        ):
            raise RequestError(429, "하루 상품 등록 가능 횟수를 초과했습니다.")
        name, description, price = self._validate_product(fields)
        image_path = self._save_image(files)
        if image_path is None:
            raise RequestError(400, "상품 사진을 등록해주세요.")
        now = utc_now()
        connection = connect()
        try:
            product_id = connection.execute(
                """
                INSERT INTO products(
                    name, description, price, image_path, seller_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (name, description, price, image_path, user["id"], now, now),
            ).lastrowid
            audit(connection, user["id"], "create_product", "product", product_id)
            connection.commit()
        except Exception:
            connection.rollback()
            delete_uploaded_image(image_path)
            raise
        finally:
            connection.close()
        self._redirect(f"/products/{product_id}?notice=product-created")

    def _update_product(
        self,
        product_id: int,
        fields: dict[str, str],
        files: dict[str, cgi.FieldStorage],
    ) -> None:
        user = self._require_user()
        if not user:
            return
        product = self._owned_product(product_id, user["id"])
        name, description, price = self._validate_product(fields)
        image_path = self._save_image(files, product["image_path"])
        changed_image = image_path != product["image_path"]
        connection = connect()
        try:
            connection.execute(
                """
                UPDATE products
                SET name = ?, description = ?, price = ?, image_path = ?, updated_at = ?
                WHERE id = ? AND seller_id = ?
                """,
                (
                    name,
                    description,
                    price,
                    image_path,
                    utc_now(),
                    product_id,
                    user["id"],
                ),
            )
            audit(connection, user["id"], "update_product", "product", product_id)
            connection.commit()
        except Exception:
            connection.rollback()
            if changed_image:
                delete_uploaded_image(image_path)
            raise
        finally:
            connection.close()
        if changed_image:
            delete_uploaded_image(product["image_path"])
        self._redirect(f"/products/{product_id}?notice=product-updated")

    def _delete_product(self, product_id: int) -> None:
        user = self._require_user()
        if not user:
            return
        product = self._owned_product(product_id, user["id"])
        connection = connect()
        try:
            connection.execute(
                """
                UPDATE products SET status = 'deleted', image_path = NULL, updated_at = ?
                WHERE id = ? AND seller_id = ?
                """,
                (utc_now(), product_id, user["id"]),
            )
            audit(connection, user["id"], "delete_product", "product", product_id)
            connection.commit()
        finally:
            connection.close()
        delete_uploaded_image(product["image_path"])
        self._redirect("/mypage?notice=product-deleted")

    def _chat_stream(self) -> None:
        user = self._require_user()
        if not user:
            return
        ip_address = self.request_ip
        if not STREAM_LIMITER.acquire(ip_address):
            raise RequestError(429, "동시에 연결할 수 있는 채팅 수를 초과했습니다.")
        try:
            after = max(0, int(self._query_value("after", "0")))
        except ValueError:
            after = 0
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Connection", "keep-alive")
            self._common_headers()
            self.end_headers()
            if self.head_only:
                return
            for _ in range(25):
                connection = connect()
                try:
                    rows = connection.execute(
                        """
                        SELECT m.id, m.body, m.created_at, u.display_name, u.id AS sender_id
                        FROM messages m JOIN users u ON u.id = m.sender_id
                        WHERE m.recipient_id IS NULL AND m.id > ? AND u.status = 'active'
                        ORDER BY m.id LIMIT 50
                        """,
                        (after,),
                    ).fetchall()
                finally:
                    connection.close()
                for row in rows:
                    after = row["id"]
                    payload = json.dumps(dict(row), ensure_ascii=False)
                    self.wfile.write(
                        f"id: {after}\ndata: {payload}\n\n".encode("utf-8")
                    )
                if not rows:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
                time.sleep(1)
        finally:
            STREAM_LIMITER.release(ip_address)

    def _send_global_message(self, fields: dict[str, str]) -> None:
        user = self._require_user()
        if not user:
            return
        if not allow_action(
            "global_message", str(user["id"]), 20, 60
        ):
            raise RequestError(429, "메시지를 너무 빠르게 보내고 있습니다.")
        body = fields.get("body", "").strip()
        if not 1 <= len(body) <= 500:
            raise RequestError(400, "메시지는 1~500자로 입력해주세요.")
        connection = connect()
        try:
            message_id = connection.execute(
                """
                INSERT INTO messages(sender_id, recipient_id, body, created_at)
                VALUES (?, NULL, ?, ?)
                """,
                (user["id"], body, utc_now()),
            ).lastrowid
            connection.commit()
        finally:
            connection.close()
        self._json({"ok": True, "id": message_id}, 201)

    def _direct_chat(self, other_id: int) -> None:
        user = self._require_user()
        if not user:
            return
        if other_id == user["id"]:
            raise RequestError(400, "자기 자신과는 1대1 채팅을 시작할 수 없습니다.")
        connection = connect()
        try:
            other = connection.execute(
                """
                SELECT id, username, display_name, bio
                FROM users WHERE id = ? AND status = 'active'
                """,
                (other_id,),
            ).fetchone()
            if not other:
                raise RequestError(404, "대화 상대를 찾을 수 없습니다.")
            messages = connection.execute(
                """
                SELECT m.*, u.display_name AS sender_name
                FROM messages m JOIN users u ON u.id = m.sender_id
                WHERE m.recipient_id IS NOT NULL
                  AND ((m.sender_id = ? AND m.recipient_id = ?)
                    OR (m.sender_id = ? AND m.recipient_id = ?))
                ORDER BY m.id ASC
                LIMIT 200
                """,
                (user["id"], other_id, other_id, user["id"]),
            ).fetchall()
        finally:
            connection.close()
        self._render("direct_chat.html", other=other, messages=messages)

    def _send_direct_message(
        self, other_id: int, fields: dict[str, str]
    ) -> None:
        user = self._require_user()
        if not user:
            return
        if other_id == user["id"]:
            raise RequestError(400, "자기 자신에게 메시지를 보낼 수 없습니다.")
        if not allow_action("direct_message", str(user["id"]), 20, 60):
            raise RequestError(429, "메시지를 너무 빠르게 보내고 있습니다.")
        body = fields.get("body", "").strip()
        if not 1 <= len(body) <= 500:
            raise RequestError(400, "메시지는 1~500자로 입력해주세요.")
        connection = connect()
        try:
            other = connection.execute(
                "SELECT id FROM users WHERE id = ? AND status = 'active'", (other_id,)
            ).fetchone()
            if not other:
                raise RequestError(404, "대화 상대를 찾을 수 없습니다.")
            connection.execute(
                """
                INSERT INTO messages(sender_id, recipient_id, body, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (user["id"], other_id, body, utc_now()),
            )
            connection.commit()
        finally:
            connection.close()
        self._redirect(f"/messages/{other_id}")

    def _report_page(self, target_type: str, target_id: int) -> None:
        user = self._require_user()
        if not user:
            return
        target = self._report_target(target_type, target_id)
        self._render(
            "report.html",
            target_type=target_type,
            target_id=target_id,
            target=target,
        )

    def _report_target(self, target_type: str, target_id: int):
        connection = connect()
        try:
            if target_type == "user":
                target = connection.execute(
                    """
                    SELECT id, display_name AS target_name, role, status
                    FROM users WHERE id = ?
                    """,
                    (target_id,),
                ).fetchone()
            else:
                target = connection.execute(
                    """
                    SELECT id, name AS target_name, seller_id, status
                    FROM products WHERE id = ?
                    """,
                    (target_id,),
                ).fetchone()
        finally:
            connection.close()
        if not target:
            raise RequestError(404, "신고 대상을 찾을 수 없습니다.")
        return target

    def _create_report(
        self, target_type: str, target_id: int, fields: dict[str, str]
    ) -> None:
        user = self._require_user()
        if not user:
            return
        target = self._report_target(target_type, target_id)
        if target_type == "user":
            if target_id == user["id"]:
                raise RequestError(400, "자기 자신을 신고할 수 없습니다.")
            if target["role"] == "admin":
                raise RequestError(400, "관리자 계정은 이 경로에서 신고할 수 없습니다.")
        elif target["seller_id"] == user["id"]:
            raise RequestError(400, "자신의 상품을 신고할 수 없습니다.")
        reason = fields.get("reason", "").strip()
        if not 10 <= len(reason) <= 500:
            raise RequestError(400, "신고 사유는 10~500자로 입력해주세요.")
        created_at = datetime.fromisoformat(user["created_at"])
        account_age = (datetime.now(UTC) - created_at).total_seconds()
        if (
            user["role"] != "admin"
            and account_age < REPORT_MIN_ACCOUNT_AGE_SECONDS
        ):
            raise RequestError(
                403,
                "가입 후 1시간이 지난 계정부터 신고할 수 있습니다.",
            )
        if not allow_action(
            "report_user", str(user["id"]), REPORT_LIMIT_PER_DAY, 24 * 60 * 60
        ) or not allow_action(
            "report_ip", self.request_ip, 30, 24 * 60 * 60
        ):
            raise RequestError(429, "하루 신고 가능 횟수를 초과했습니다.")
        connection = connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO reports(
                    reporter_id, target_type, target_id, reason, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (user["id"], target_type, target_id, reason, utc_now()),
            )
            count = connection.execute(
                """
                SELECT COUNT(*) AS count FROM reports
                WHERE target_type = ? AND target_id = ? AND status = 'open'
                """,
                (target_type, target_id),
            ).fetchone()["count"]
            if target_type == "product":
                connection.execute(
                    """
                    UPDATE products
                    SET report_count = ?,
                        status = CASE WHEN ? >= ? THEN 'blocked' ELSE status END,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (count, count, REPORT_THRESHOLD, utc_now(), target_id),
                )
            elif count >= REPORT_THRESHOLD:
                connection.execute(
                    "UPDATE users SET status = 'suspended' WHERE id = ? AND role <> 'admin'",
                    (target_id,),
                )
                connection.execute(
                    "DELETE FROM sessions WHERE user_id = ?", (target_id,)
                )
            audit(
                connection,
                user["id"],
                "create_report",
                target_type,
                target_id,
                "temporary_restriction" if count >= REPORT_THRESHOLD else "",
            )
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            raise RequestError(409, "같은 대상을 이미 신고했습니다.")
        finally:
            connection.close()
        self._redirect("/?notice=report")

    def _transfers(self) -> None:
        user = self._require_user()
        if not user:
            return
        connection = connect()
        try:
            recipients = connection.execute(
                """
                SELECT id, username, display_name
                FROM users
                WHERE status = 'active' AND id <> ?
                ORDER BY display_name
                """,
                (user["id"],),
            ).fetchall()
            history = connection.execute(
                """
                SELECT t.*,
                       sender.display_name AS sender_name,
                       recipient.display_name AS recipient_name
                FROM transfers t
                JOIN users sender ON sender.id = t.sender_id
                JOIN users recipient ON recipient.id = t.recipient_id
                WHERE t.sender_id = ? OR t.recipient_id = ?
                ORDER BY t.id DESC LIMIT 30
                """,
                (user["id"], user["id"]),
            ).fetchall()
        finally:
            connection.close()
        self._render(
            "transfers.html",
            recipients=recipients,
            history=history,
            transfer_token=new_token(24),
        )

    def _create_transfer(self, fields: dict[str, str]) -> None:
        user = self._require_user()
        if not user:
            return
        try:
            recipient_id = int(fields.get("recipient_id", ""))
            amount = int(fields.get("amount", ""))
        except ValueError as error:
            raise RequestError(400, "받는 사람과 금액을 확인해주세요.") from error
        memo = fields.get("memo", "").strip()
        transfer_token = fields.get("transfer_token", "").strip()
        password = fields.get("password", "")
        if recipient_id == user["id"]:
            raise RequestError(400, "자기 자신에게 송금할 수 없습니다.")
        if amount <= 0 or amount > 10_000_000:
            raise RequestError(400, "송금액은 1원 이상 1천만 원 이하여야 합니다.")
        if len(memo) > 100:
            raise RequestError(400, "송금 메모는 100자 이하여야 합니다.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", transfer_token):
            raise RequestError(400, "송금 요청 정보가 올바르지 않습니다.")
        if not allow_action(
            "transfer_auth",
            str(user["id"]),
            5,
            5 * 60,
        ):
            raise RequestError(429, "송금 인증 시도가 너무 많습니다.")
        if len(password) > 128 or not verify_password(
            password,
            user["password_hash"],
        ):
            raise RequestError(403, "송금 비밀번호가 올바르지 않습니다.")
        request_token_hash = token_digest(transfer_token)
        connection = connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT id FROM transfers
                WHERE request_token_hash = ?
                """,
                (request_token_hash,),
            ).fetchone()
            if existing:
                raise RequestError(409, "이미 처리된 송금 요청입니다.")
            sender = connection.execute(
                "SELECT id, balance, status FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
            recipient = connection.execute(
                "SELECT id, status FROM users WHERE id = ?", (recipient_id,)
            ).fetchone()
            if not sender or sender["status"] != "active":
                raise RequestError(403, "송금할 수 없는 계정입니다.")
            if not recipient or recipient["status"] != "active":
                raise RequestError(404, "받는 사람을 찾을 수 없습니다.")
            if sender["balance"] < amount:
                raise RequestError(400, "잔액이 부족합니다.")
            debited = connection.execute(
                """
                UPDATE users SET balance = balance - ?
                WHERE id = ? AND balance >= ? AND status = 'active'
                """,
                (amount, user["id"], amount),
            )
            if debited.rowcount != 1:
                raise RequestError(409, "잔액이 변경되었습니다. 다시 시도해주세요.")
            connection.execute(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (amount, recipient_id),
            )
            transfer_id = connection.execute(
                """
                INSERT INTO transfers(
                    sender_id, recipient_id, amount, memo,
                    request_token_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user["id"],
                    recipient_id,
                    amount,
                    memo,
                    request_token_hash,
                    utc_now(),
                ),
            ).lastrowid
            audit(
                connection,
                user["id"],
                "transfer",
                "transfer",
                transfer_id,
                f"amount={amount}",
            )
            connection.commit()
        except RequestError:
            connection.rollback()
            raise
        finally:
            connection.close()
        self._redirect("/transfers?notice=transfer")

    def _admin(self) -> None:
        if not self._require_admin():
            return
        connection = connect()
        try:
            counts = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM users) AS users,
                    (SELECT COUNT(*) FROM products WHERE status <> 'deleted') AS products,
                    (SELECT COUNT(*) FROM reports WHERE status = 'open') AS reports,
                    (SELECT COUNT(*) FROM transfers) AS transfers,
                    (SELECT COUNT(*) FROM messages) AS messages
                """
            ).fetchone()
            users = connection.execute(
                """
                SELECT id, username, display_name, role, status, balance, created_at
                FROM users ORDER BY created_at DESC LIMIT 100
                """
            ).fetchall()
            products = connection.execute(
                """
                SELECT p.*, u.display_name AS seller_name
                FROM products p JOIN users u ON u.id = p.seller_id
                WHERE p.status <> 'deleted'
                ORDER BY p.created_at DESC LIMIT 100
                """
            ).fetchall()
            reports = connection.execute(
                """
                SELECT r.*, u.display_name AS reporter_name
                FROM reports r JOIN users u ON u.id = r.reporter_id
                ORDER BY (r.status = 'open') DESC, r.id DESC LIMIT 100
                """
            ).fetchall()
            transfers = connection.execute(
                """
                SELECT t.*, s.display_name AS sender_name, r.display_name AS recipient_name
                FROM transfers t
                JOIN users s ON s.id = t.sender_id
                JOIN users r ON r.id = t.recipient_id
                ORDER BY t.id DESC LIMIT 30
                """
            ).fetchall()
            messages = connection.execute(
                """
                SELECT m.*, s.display_name AS sender_name,
                       r.display_name AS recipient_name
                FROM messages m
                JOIN users s ON s.id = m.sender_id
                LEFT JOIN users r ON r.id = m.recipient_id
                ORDER BY m.id DESC LIMIT 100
                """
            ).fetchall()
        finally:
            connection.close()
        self._render(
            "admin.html",
            counts=counts,
            users=users,
            products=products,
            reports=reports,
            transfers=transfers,
            messages=messages,
        )

    def _admin_user_action(self, user_id: int, action: str) -> None:
        admin = self._require_admin()
        if not admin:
            return
        if user_id == admin["id"]:
            raise RequestError(400, "현재 로그인한 관리자 계정은 정지할 수 없습니다.")
        new_status = "suspended" if action == "suspend" else "active"
        connection = connect()
        try:
            target = connection.execute(
                "SELECT id, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if not target:
                raise RequestError(404, "사용자를 찾을 수 없습니다.")
            if target["role"] == "admin":
                raise RequestError(400, "다른 관리자 계정은 이 화면에서 변경할 수 없습니다.")
            connection.execute(
                "UPDATE users SET status = ? WHERE id = ?", (new_status, user_id)
            )
            if new_status == "suspended":
                connection.execute(
                    "DELETE FROM sessions WHERE user_id = ?", (user_id,)
                )
            audit(
                connection,
                admin["id"],
                f"admin_{action}_user",
                "user",
                user_id,
            )
            connection.commit()
        finally:
            connection.close()
        self._redirect("/admin?notice=admin")

    def _admin_grant_balance(
        self, user_id: int, fields: dict[str, str]
    ) -> None:
        admin = self._require_admin()
        if not admin:
            return
        try:
            amount = int(fields.get("amount", ""))
        except ValueError as error:
            raise RequestError(400, "지급 금액을 확인해주세요.") from error
        if amount <= 0 or amount > 1_000_000:
            raise RequestError(400, "한 번에 1원 이상 100만 원 이하로 지급할 수 있습니다.")
        connection = connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (amount, user_id),
            )
            if changed.rowcount != 1:
                raise RequestError(404, "사용자를 찾을 수 없습니다.")
            audit(
                connection,
                admin["id"],
                "admin_grant_balance",
                "user",
                user_id,
                f"amount={amount}",
            )
            connection.commit()
        except RequestError:
            connection.rollback()
            raise
        finally:
            connection.close()
        self._redirect("/admin?notice=admin")

    def _admin_product_action(self, product_id: int, action: str) -> None:
        admin = self._require_admin()
        if not admin:
            return
        new_status = "deleted" if action == "delete" else "active"
        connection = connect()
        image_path = None
        try:
            product = connection.execute(
                "SELECT image_path FROM products WHERE id = ?", (product_id,)
            ).fetchone()
            if not product:
                raise RequestError(404, "상품을 찾을 수 없습니다.")
            image_path = product["image_path"]
            if action == "delete":
                changed = connection.execute(
                    """
                    UPDATE products
                    SET status = ?, image_path = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (new_status, utc_now(), product_id),
                )
            else:
                changed = connection.execute(
                    "UPDATE products SET status = ?, updated_at = ? WHERE id = ?",
                    (new_status, utc_now(), product_id),
                )
            if changed.rowcount != 1:
                raise RequestError(404, "상품을 찾을 수 없습니다.")
            audit(
                connection,
                admin["id"],
                f"admin_{action}_product",
                "product",
                product_id,
            )
            connection.commit()
        finally:
            connection.close()
        if action == "delete":
            delete_uploaded_image(image_path)
        self._redirect("/admin?notice=admin")

    def _admin_resolve_report(self, report_id: int, action: str) -> None:
        admin = self._require_admin()
        if not admin:
            return
        connection = connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            report = connection.execute(
                """
                SELECT id, target_type, target_id
                FROM reports WHERE id = ?
                """,
                (report_id,),
            ).fetchone()
            if not report:
                raise RequestError(404, "신고를 찾을 수 없습니다.")
            connection.execute(
                """
                UPDATE reports SET status = 'resolved'
                WHERE target_type = ? AND target_id = ? AND status = 'open'
                """,
                (report["target_type"], report["target_id"]),
            )
            if action == "restore":
                if report["target_type"] == "user":
                    connection.execute(
                        """
                        UPDATE users SET status = 'active'
                        WHERE id = ? AND role <> 'admin'
                        """,
                        (report["target_id"],),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE products
                        SET status = 'active', report_count = 0, updated_at = ?
                        WHERE id = ? AND status = 'blocked'
                        """,
                        (utc_now(), report["target_id"]),
                    )
            audit(
                connection,
                admin["id"],
                f"admin_report_{action}",
                "report",
                report_id,
            )
            connection.commit()
        except RequestError:
            connection.rollback()
            raise
        finally:
            connection.close()
        self._redirect("/admin?notice=admin")

    def _admin_delete_message(self, message_id: int) -> None:
        admin = self._require_admin()
        if not admin:
            return
        connection = connect()
        try:
            changed = connection.execute(
                "DELETE FROM messages WHERE id = ?", (message_id,)
            )
            if changed.rowcount != 1:
                raise RequestError(404, "메시지를 찾을 수 없습니다.")
            audit(
                connection,
                admin["id"],
                "admin_delete_message",
                "message",
                message_id,
            )
            connection.commit()
        finally:
            connection.close()
        self._redirect("/admin?notice=admin")


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="되살림 중고거래 플랫폼")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("PORT", "8000"))
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        default=os.environ.get("SEED_DEMO_DATA") == "1",
        help="데모 사용자와 상품을 추가합니다.",
    )
    parser.add_argument(
        "--init-only",
        action="store_true",
        help="데이터베이스와 관리자 계정만 준비하고 종료합니다.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if is_production():
        if os.environ.get("COOKIE_SECURE") != "1":
            raise SystemExit(
                "운영 모드에서는 COOKIE_SECURE=1 설정이 필요합니다."
            )
        if args.seed:
            raise SystemExit("운영 모드에서는 데모 데이터를 생성할 수 없습니다.")
        if not validate_totp_secret(os.environ.get("ADMIN_TOTP_SECRET", "")):
            raise SystemExit(
                "운영 모드에서는 160비트 이상의 ADMIN_TOTP_SECRET이 필요합니다."
            )
    init_database()
    upload_path = upload_directory()
    upload_created = not upload_path.exists()
    upload_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    upload_private = (
        set_private_permissions(upload_path, 0o700)
        if upload_created
        else has_private_permissions(upload_path)
    )
    database_private = set_private_permissions(database_path(), 0o600)
    database_parent_private = has_private_permissions(database_path().parent)
    if is_production() and (
        not upload_private
        or not database_private
        or not database_parent_private
    ):
        raise SystemExit(
            "운영 데이터 경로의 권한을 제한할 수 없습니다. "
            "데이터베이스는 600, 데이터 폴더와 업로드 폴더는 "
            "700 권한이 필요합니다."
        )
    try:
        credentials = ensure_admin(require_configured=is_production())
    except ValueError as error:
        raise SystemExit(str(error)) from error
    demo_credentials = None
    if args.seed:
        demo_credentials = seed_demo()
    removed_uploads = cleanup_orphan_uploads()
    if credentials and not is_production():
        print("\n최초 관리자 계정이 생성되었습니다.")
        print(f"  아이디: {credentials[0]}")
        print(f"  비밀번호: {credentials[1]}")
        print("  로그인 후 안전한 비밀번호로 변경하세요.\n")
    if demo_credentials:
        print("\n데모 계정이 생성되었습니다.")
        print(f"  아이디: {demo_credentials[0]}")
        print(f"  비밀번호: {demo_credentials[1]}")
        print("  이 비밀번호는 터미널에 한 번만 출력됩니다.\n")
    if removed_uploads:
        print(f"참조되지 않는 업로드 파일 {removed_uploads}개를 정리했습니다.")
    if args.init_only:
        return
    server = BoundedThreadingHTTPServer((args.host, args.port), MarketplaceHandler)
    print(f"되살림 마켓 실행 중: http://{args.host}:{args.port}")
    print("종료하려면 Ctrl+C를 누르세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n서버를 종료합니다.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
