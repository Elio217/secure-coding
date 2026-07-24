import http.cookiejar
import base64
import os
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import app as app_module
from app import BoundedThreadingHTTPServer, MarketplaceHandler
from marketplace.db import connect, ensure_admin, init_database, seed_demo
from marketplace.security import token_digest, totp_code


class MarketplaceIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.previous_db = os.environ.get("MARKET_DB_PATH")
        cls.previous_upload_dir = os.environ.get("MARKET_UPLOAD_DIR")
        cls.previous_admin_password = os.environ.get("ADMIN_PASSWORD")
        os.environ["MARKET_DB_PATH"] = str(
            Path(cls.temporary_directory.name) / "integration.db"
        )
        os.environ["ADMIN_PASSWORD"] = "SecureRoot2026!"
        os.environ["MARKET_UPLOAD_DIR"] = str(
            Path(cls.temporary_directory.name) / "uploads"
        )
        init_database()
        ensure_admin()
        seed_demo()
        cls.previous_signup_limit = app_module.SIGNUP_LIMIT_PER_HOUR
        cls.previous_report_age = app_module.REPORT_MIN_ACCOUNT_AGE_SECONDS
        app_module.SIGNUP_LIMIT_PER_HOUR = 100
        app_module.REPORT_MIN_ACCOUNT_AGE_SECONDS = 0
        cls.server = BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), MarketplaceHandler
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        app_module.SIGNUP_LIMIT_PER_HOUR = cls.previous_signup_limit
        app_module.REPORT_MIN_ACCOUNT_AGE_SECONDS = cls.previous_report_age
        if cls.previous_db is None:
            os.environ.pop("MARKET_DB_PATH", None)
        else:
            os.environ["MARKET_DB_PATH"] = cls.previous_db
        if cls.previous_admin_password is None:
            os.environ.pop("ADMIN_PASSWORD", None)
        else:
            os.environ["ADMIN_PASSWORD"] = cls.previous_admin_password
        if cls.previous_upload_dir is None:
            os.environ.pop("MARKET_UPLOAD_DIR", None)
        else:
            os.environ["MARKET_UPLOAD_DIR"] = cls.previous_upload_dir
        cls.temporary_directory.cleanup()

    def browser(self):
        jar = http.cookiejar.CookieJar()
        browser = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )
        browser.cookie_jar = jar
        return browser

    def get(self, browser, path):
        response = browser.open(self.base_url + path, timeout=5)
        return response, response.read().decode("utf-8")

    def post(self, browser, path, values):
        request = urllib.request.Request(
            self.base_url + path,
            data=urllib.parse.urlencode(values).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response = browser.open(request, timeout=5)
        return response, response.read().decode("utf-8")

    def post_multipart(self, browser, path, values, file_field, filename, content):
        boundary = f"----ResalimTest{uuid.uuid4().hex}"
        chunks = []
        for name, value in values.items():
            chunks.extend(
                [
                    f"--{boundary}\r\n".encode(),
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                    str(value).encode("utf-8"),
                    b"\r\n",
                ]
            )
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{file_field}"; '
                    f'filename="{filename}"\r\n'
                ).encode(),
                b"Content-Type: image/png\r\n\r\n",
                content,
                b"\r\n",
                f"--{boundary}--\r\n".encode(),
            ]
        )
        request = urllib.request.Request(
            self.base_url + path,
            data=b"".join(chunks),
            method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        response = browser.open(request, timeout=5)
        return response, response.read().decode("utf-8")

    def csrf(self, html):
        match = re.search(r'name="csrf-token" content="([^"]+)"', html)
        self.assertIsNotNone(match)
        return match.group(1)

    def hidden_value(self, html, name):
        match = re.search(
            rf'name="{re.escape(name)}" value="([^"]+)"',
            html,
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def session_cookie(self, browser):
        for cookie in browser.cookie_jar:
            if cookie.name == "session":
                return cookie.value
        return None

    def signup(self, browser, prefix="neighbor"):
        _, home = self.get(browser, "/")
        username = f"{prefix}_{uuid.uuid4().hex[:8]}"
        response, html = self.post(
            browser,
            "/signup",
            {
                "csrf_token": self.csrf(home),
                "username": username,
                "display_name": f"테스트 {username[-4:]}",
                "password": "SafeMarket2026!",
                "password_confirm": "SafeMarket2026!",
            },
        )
        self.assertEqual(response.status, 200)
        self.assertIn("가입이 완료", html)
        return username, html

    def test_public_home_has_products_and_security_headers(self):
        browser = self.browser()
        response, html = self.get(browser, "/")
        self.assertEqual(response.status, 200)
        self.assertIn("필름 카메라", html)
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_signup_product_transfer_chat_and_report_workflow(self):
        browser = self.browser()
        username, html = self.signup(browser)
        csrf = self.csrf(html)

        one_pixel_png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
            "+A8AAQUBAScY42YAAAAASUVORK5CYII="
        )
        response, product_html = self.post_multipart(
            browser,
            "/products/new",
            {
                "csrf_token": csrf,
                "name": "통합 테스트 상품",
                "price": "12000",
                "description": "정상적인 상품 등록 흐름을 확인하는 상세 설명입니다.",
            },
            "image",
            "item.png",
            one_pixel_png,
        )
        self.assertEqual(response.status, 200)
        self.assertIn("통합 테스트 상품", product_html)

        connection = connect()
        try:
            created_user = connection.execute(
                "SELECT id, balance FROM users WHERE username = ?", (username,)
            ).fetchone()
            self.assertEqual(created_user["balance"], 0)
            created_user_id = created_user["id"]
        finally:
            connection.close()

        admin_browser = self.browser()
        _, admin_login_page = self.get(admin_browser, "/login")
        _, admin_home = self.post(
            admin_browser,
            "/login",
            {
                "csrf_token": self.csrf(admin_login_page),
                "username": "admin",
                "password": "SecureRoot2026!",
            },
        )
        response, _ = self.post(
            admin_browser,
            f"/admin/users/{created_user_id}/balance",
            {
                "csrf_token": self.csrf(admin_home),
                "amount": "100000",
            },
        )
        self.assertEqual(response.status, 200)

        _, transfer_page = self.get(browser, "/transfers")
        transfer_values = {
            "csrf_token": self.csrf(transfer_page),
            "transfer_token": self.hidden_value(
                transfer_page,
                "transfer_token",
            ),
            "recipient_id": "2",
            "amount": "1500",
            "memo": "통합 테스트",
            "password": "SafeMarket2026!",
        }
        response, transfer_html = self.post(
            browser,
            "/transfers",
            transfer_values,
        )
        self.assertEqual(response.status, 200)
        self.assertIn("송금을 완료", transfer_html)
        with self.assertRaises(urllib.error.HTTPError) as duplicate:
            self.post(browser, "/transfers", transfer_values)
        self.assertEqual(duplicate.exception.code, 409)

        response, payload = self.post(
            browser,
            "/api/chat/global",
            {
                "csrf_token": self.csrf(transfer_html),
                "body": "자동 테스트 채팅 메시지",
            },
        )
        self.assertEqual(response.status, 201)
        self.assertIn('"ok":true', payload)

        _, report_page = self.get(browser, "/reports/product/1")
        response, report_result = self.post(
            browser,
            "/reports/product/1",
            {
                "csrf_token": self.csrf(report_page),
                "reason": "자동 테스트에서 확인하는 구체적인 신고 사유입니다.",
            },
        )
        self.assertEqual(response.status, 200)
        self.assertIn("신고를 접수", report_result)

        connection = connect()
        try:
            user = connection.execute(
                "SELECT balance FROM users WHERE username = ?", (username,)
            ).fetchone()
            self.assertEqual(user["balance"], 98_500)
        finally:
            connection.close()

    def test_csrf_and_authorization_fail_closed(self):
        browser = self.browser()
        with self.assertRaises(urllib.error.HTTPError) as csrf_error:
            self.post(
                browser,
                "/login",
                {
                    "csrf_token": "invalid",
                    "username": "admin",
                    "password": "SecureRoot2026!",
                },
            )
        self.assertEqual(csrf_error.exception.code, 403)

        _, home = self.get(browser, "/")
        response, login_html = self.post(
            browser,
            "/products/1/delete",
            {"csrf_token": self.csrf(home)},
        )
        self.assertEqual(response.status, 200)
        self.assertTrue(response.geturl().endswith("/login?notice=login-required"))
        self.assertIn("로그인", login_html)
        connection = connect()
        try:
            product = connection.execute(
                "SELECT status FROM products WHERE id = 1"
            ).fetchone()
            self.assertEqual(product["status"], "active")
        finally:
            connection.close()

    def test_admin_can_manage_messages(self):
        browser = self.browser()
        _, login_page = self.get(browser, "/login")
        response, admin_html = self.post(
            browser,
            "/login",
            {
                "csrf_token": self.csrf(login_page),
                "username": "admin",
                "password": "SecureRoot2026!",
            },
        )
        self.assertEqual(response.status, 200)
        response, admin_page = self.get(browser, "/admin")
        self.assertEqual(response.status, 200)
        self.assertIn("플랫폼 관리", admin_page)
        self.assertIn("채팅 관리", admin_page)

    def test_admin_totp_is_required_when_configured(self):
        previous_secret = os.environ.get("ADMIN_TOTP_SECRET")
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        os.environ["ADMIN_TOTP_SECRET"] = secret
        try:
            browser = self.browser()
            _, login_page = self.get(browser, "/login")
            with self.assertRaises(urllib.error.HTTPError) as missing_code:
                self.post(
                    browser,
                    "/login",
                    {
                        "csrf_token": self.csrf(login_page),
                        "username": "admin",
                        "password": "SecureRoot2026!",
                    },
                )
            self.assertEqual(missing_code.exception.code, 401)

            _, login_page = self.get(browser, "/login")
            response, result = self.post(
                browser,
                "/login",
                {
                    "csrf_token": self.csrf(login_page),
                    "username": "admin",
                    "password": "SecureRoot2026!",
                    "otp_code": totp_code(secret),
                },
            )
            self.assertEqual(response.status, 200)
            self.assertIn("안전하게 로그인", result)
        finally:
            if previous_secret is None:
                os.environ.pop("ADMIN_TOTP_SECRET", None)
            else:
                os.environ["ADMIN_TOTP_SECRET"] = previous_secret

    def test_password_change_rotates_current_session(self):
        browser = self.browser()
        self.signup(browser, prefix="rotate")
        old_session = self.session_cookie(browser)
        self.assertIsNotNone(old_session)
        _, mypage = self.get(browser, "/mypage")
        response, result = self.post(
            browser,
            "/mypage/password",
            {
                "csrf_token": self.csrf(mypage),
                "current_password": "SafeMarket2026!",
                "new_password": "ChangedPass2027!",
                "new_password_confirm": "ChangedPass2027!",
            },
        )
        self.assertEqual(response.status, 200)
        self.assertIn("비밀번호를 변경", result)
        new_session = self.session_cookie(browser)
        self.assertIsNotNone(new_session)
        self.assertNotEqual(old_session, new_session)

        connection = connect()
        try:
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sessions WHERE token_hash = ?",
                    (token_digest(old_session),),
                ).fetchone()
            )
            self.assertIsNotNone(
                connection.execute(
                    "SELECT 1 FROM sessions WHERE token_hash = ?",
                    (token_digest(new_session),),
                ).fetchone()
            )
        finally:
            connection.close()

    def test_suspended_seller_product_and_upload_are_not_public(self):
        seller_browser = self.browser()
        username, home = self.signup(seller_browser, prefix="suspend")
        one_pixel_png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
            "+A8AAQUBAScY42YAAAAASUVORK5CYII="
        )
        response, _ = self.post_multipart(
            seller_browser,
            "/products/new",
            {
                "csrf_token": self.csrf(home),
                "name": "차단 접근 테스트 상품",
                "price": "1000",
                "description": "판매자 휴면 시 공개 접근이 차단되는 상품입니다.",
            },
            "image",
            "blocked.png",
            one_pixel_png,
        )
        self.assertEqual(response.status, 200)
        connection = connect()
        try:
            product = connection.execute(
                """
                SELECT p.id, p.image_path, p.seller_id
                FROM products p
                JOIN users u ON u.id = p.seller_id
                WHERE u.username = ?
                ORDER BY p.id DESC LIMIT 1
                """,
                (username,),
            ).fetchone()
        finally:
            connection.close()

        admin_browser = self.browser()
        _, login_page = self.get(admin_browser, "/login")
        _, admin_home = self.post(
            admin_browser,
            "/login",
            {
                "csrf_token": self.csrf(login_page),
                "username": "admin",
                "password": "SecureRoot2026!",
            },
        )
        self.post(
            admin_browser,
            f"/admin/users/{product['seller_id']}/suspend",
            {"csrf_token": self.csrf(admin_home)},
        )

        public_browser = self.browser()
        with self.assertRaises(urllib.error.HTTPError) as product_error:
            self.get(public_browser, f"/products/{product['id']}")
        self.assertEqual(product_error.exception.code, 404)
        with self.assertRaises(urllib.error.HTTPError) as image_error:
            self.get(public_browser, product["image_path"])
        self.assertEqual(image_error.exception.code, 404)

        product_response, _ = self.get(
            admin_browser,
            f"/products/{product['id']}",
        )
        image_response = admin_browser.open(
            self.base_url + product["image_path"],
            timeout=5,
        )
        self.assertEqual(product_response.status, 200)
        self.assertEqual(image_response.status, 200)

    def test_three_reports_block_and_admin_restore_resets_open_count(self):
        for index in range(3):
            browser = self.browser()
            self.signup(browser, prefix=f"reporter{index}")
            _, report_page = self.get(browser, "/reports/product/2")
            response, _ = self.post(
                browser,
                "/reports/product/2",
                {
                    "csrf_token": self.csrf(report_page),
                    "reason": f"{index + 1}번째 사용자가 확인한 구체적인 상품 신고 사유입니다.",
                },
            )
            self.assertEqual(response.status, 200)

        connection = connect()
        try:
            product = connection.execute(
                "SELECT status, report_count FROM products WHERE id = 2"
            ).fetchone()
            self.assertEqual(product["report_count"], 3)
            self.assertEqual(product["status"], "blocked")
            report_id = connection.execute(
                """
                SELECT id FROM reports
                WHERE target_type = 'product' AND target_id = 2
                ORDER BY id DESC LIMIT 1
                """
            ).fetchone()["id"]
        finally:
            connection.close()

        admin_browser = self.browser()
        _, login_page = self.get(admin_browser, "/login")
        _, admin_home = self.post(
            admin_browser,
            "/login",
            {
                "csrf_token": self.csrf(login_page),
                "username": "admin",
                "password": "SecureRoot2026!",
            },
        )
        response, _ = self.post(
            admin_browser,
            f"/admin/reports/{report_id}/restore",
            {"csrf_token": self.csrf(admin_home)},
        )
        self.assertEqual(response.status, 200)
        connection = connect()
        try:
            restored = connection.execute(
                "SELECT status, report_count FROM products WHERE id = 2"
            ).fetchone()
            self.assertEqual(restored["status"], "active")
            self.assertEqual(restored["report_count"], 0)
        finally:
            connection.close()

        new_reporter = self.browser()
        self.signup(new_reporter, prefix="reporter4")
        _, report_page = self.get(new_reporter, "/reports/product/2")
        response, _ = self.post(
            new_reporter,
            "/reports/product/2",
            {
                "csrf_token": self.csrf(report_page),
                "reason": "관리자 복구 후 새 신고만 다시 집계되는지 확인합니다.",
            },
        )
        self.assertEqual(response.status, 200)
        connection = connect()
        try:
            product_after_new_report = connection.execute(
                "SELECT status, report_count FROM products WHERE id = 2"
            ).fetchone()
            self.assertEqual(product_after_new_report["status"], "active")
            self.assertEqual(product_after_new_report["report_count"], 1)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
