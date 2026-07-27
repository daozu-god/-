import io
import json
import os
import re
import runpy
import secrets
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from flask import Flask
from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app


CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')
RETIRED_SESSION_KEY = "retired-session-key-used-only-for-regression-testing"


def write_password_store(path, admin_password, alice_password):
    payload = {
        "version": 1,
        "password_hashes": {
            "admin": generate_password_hash(admin_password, method="scrypt"),
            "alice": generate_password_hash(alice_password, method="scrypt"),
        },
    }
    Path(path).write_text(json.dumps(payload), encoding="utf-8")


def valid_config(user_store_path):
    return {
        "TESTING": True,
        "SECRET_KEY": secrets.token_urlsafe(48),
        "USER_STORE_PATH": str(user_store_path),
        "SESSION_COOKIE_SECURE": True,
        "TRUSTED_HOSTS": ["localhost"],
        "RATELIMIT_STORAGE_URI": "memory://",
        "WTF_CSRF_SSL_STRICT": False,
    }


def csrf_token(client, path="/login"):
    response = client.get(path, base_url="https://localhost")
    match = CSRF_PATTERN.search(response.get_data(as_text=True))
    if match is None:
        raise AssertionError("CSRF token not found")
    return match.group(1)


def set_authenticated_session(app, client, username):
    with client.session_transaction(base_url="https://localhost") as session_data:
        session_data["username"] = username
        session_data["credential_version"] = app.extensions["credential_version_for"](
            username
        )


class SecurityConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        cls.store_path = Path(cls.temp_dir.name) / "users.json"
        cls.admin_password = secrets.token_urlsafe(24)
        cls.alice_password = secrets.token_urlsafe(24)
        write_password_store(cls.store_path, cls.admin_password, cls.alice_password)

    def test_required_secrets_cannot_be_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                create_app()

    def test_secret_key_must_be_at_least_32_characters(self):
        config = valid_config(self.store_path)
        config["SECRET_KEY"] = "short"
        with self.assertRaises(RuntimeError):
            create_app(config)

    def test_initializer_rejects_short_initial_passwords(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "users.json"
            env = os.environ.copy()
            env.update(
                {
                    "USER_STORE_PATH": str(store_path),
                    "ADMIN_INITIAL_PASSWORD": "short",
                    "ALICE_INITIAL_PASSWORD": secrets.token_urlsafe(24),
                }
            )
            result = subprocess.run(
                [sys.executable, "init_users.py"],
                capture_output=True,
                check=False,
                env=env,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("at least 12 characters", result.stderr)
            self.assertFalse(store_path.exists())

    def test_passwords_are_hashed_and_removed_from_config(self):
        config = valid_config(self.store_path)
        app = create_app(config)
        users = app.extensions["users"]
        self.assertNotEqual(users["admin"]["password_hash"], self.admin_password)
        self.assertTrue(
            check_password_hash(users["admin"]["password_hash"], self.admin_password)
        )
        self.assertNotIn("ADMIN_PASSWORD", app.config)
        self.assertNotIn("ALICE_PASSWORD", app.config)
        self.assertNotIn("ADMIN_INITIAL_PASSWORD", app.config)
        self.assertNotIn("ALICE_INITIAL_PASSWORD", app.config)

    def test_runtime_loads_persisted_hashes_without_plaintext_passwords(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "users.json"
            admin_password = secrets.token_urlsafe(24)
            alice_password = secrets.token_urlsafe(24)
            write_password_store(store_path, admin_password, alice_password)
            config = valid_config(store_path)

            try:
                app = create_app(config)
            except RuntimeError as error:
                self.fail(f"runtime should load persisted hashes: {error}")
            users = app.extensions["users"]

            self.assertTrue(
                check_password_hash(users["admin"]["password_hash"], admin_password)
            )
            self.assertTrue(
                check_password_hash(users["alice"]["password_hash"], alice_password)
            )
            self.assertNotIn("ADMIN_PASSWORD", app.config)
            self.assertNotIn("ALICE_PASSWORD", app.config)

    def test_one_time_initializer_persists_only_hashes_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "users.json"
            admin_password = secrets.token_urlsafe(24)
            alice_password = secrets.token_urlsafe(24)
            env = os.environ.copy()
            env.update(
                {
                    "USER_STORE_PATH": str(store_path),
                    "ADMIN_INITIAL_PASSWORD": admin_password,
                    "ALICE_INITIAL_PASSWORD": alice_password,
                }
            )

            first = subprocess.run(
                [sys.executable, "init_users.py"],
                capture_output=True,
                check=False,
                env=env,
                text=True,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            raw_store = store_path.read_text(encoding="utf-8")
            stored = json.loads(raw_store)
            self.assertEqual(set(stored), {"version", "password_hashes"})
            self.assertEqual(stored["version"], 1)
            self.assertNotIn(admin_password, raw_store)
            self.assertNotIn(alice_password, raw_store)
            if os.name == "posix":
                self.assertEqual(
                    stat.S_IMODE(store_path.stat().st_mode),
                    0o600,
                )
            self.assertTrue(
                check_password_hash(stored["password_hashes"]["admin"], admin_password)
            )
            self.assertTrue(
                check_password_hash(stored["password_hashes"]["alice"], alice_password)
            )

            original_store = raw_store
            second = subprocess.run(
                [sys.executable, "init_users.py"],
                capture_output=True,
                check=False,
                env=env,
                text=True,
            )
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(store_path.read_text(encoding="utf-8"), original_store)

    def test_runtime_refuses_to_start_without_initialized_hash_store(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = valid_config(Path(temp_dir) / "missing.json")

            with self.assertRaisesRegex(RuntimeError, "init_users.py"):
                create_app(config)

    def test_runtime_rejects_non_object_password_store(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "users.json"
            store_path.write_text('[{"unexpected": true}]', encoding="utf-8")
            config = valid_config(store_path)

            try:
                create_app(config)
            except RuntimeError as error:
                self.assertRegex(str(error), "invalid schema")
            except Exception as error:
                self.fail(f"expected a controlled RuntimeError, got {error!r}")
            else:
                self.fail("non-object password store was accepted")

    def test_debug_mode_is_disabled(self):
        self.assertFalse(create_app(valid_config(self.store_path)).debug)

    def test_security_sensitive_defaults_are_production_safe(self):
        config = valid_config(self.store_path)
        config.pop("SESSION_COOKIE_SECURE")
        config.pop("WTF_CSRF_SSL_STRICT")
        with patch.dict(os.environ, {}, clear=True):
            app = create_app(config)

        self.assertTrue(app.config["SESSION_COOKIE_SECURE"])
        self.assertTrue(app.config["WTF_CSRF_SSL_STRICT"])
        self.assertEqual(app.config["PREFERRED_URL_SCHEME"], "https")

    def test_gunicorn_defaults_match_in_memory_rate_limit(self):
        config = runpy.run_path("gunicorn.conf.py")
        self.assertEqual(config["bind"], "127.0.0.1:5000")
        self.assertEqual(config["workers"], 1)

    def test_nginx_config_terminates_https_and_proxies_to_loopback(self):
        config_path = Path("deploy/nginx/class01.conf.example")
        self.assertTrue(config_path.is_file(), "Nginx HTTPS config is missing")
        config = config_path.read_text(encoding="utf-8")
        self.assertIn("listen 80", config)
        self.assertIn("return 308 https://$host$request_uri", config)
        self.assertIn("listen 443 ssl", config)
        self.assertIn("ssl_certificate ", config)
        self.assertIn("ssl_certificate_key ", config)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3", config)
        self.assertIn("proxy_pass http://127.0.0.1:5000", config)
        self.assertIn("proxy_set_header X-Forwarded-Proto https", config)
        self.assertIn("client_max_body_size 6m", config)


class AuthenticationSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        cls.store_path = Path(cls.temp_dir.name) / "users.json"
        cls.admin_password = secrets.token_urlsafe(24)
        cls.alice_password = secrets.token_urlsafe(24)
        write_password_store(cls.store_path, cls.admin_password, cls.alice_password)

    def setUp(self):
        self.config = valid_config(self.store_path)
        self.app = create_app(self.config)
        self.app.logger.disabled = True
        self.client = self.app.test_client()

    def login(self, username, password):
        token = csrf_token(self.client)
        return self.client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": token,
            },
            base_url="https://localhost",
        )

    def test_login_page_does_not_disclose_default_credentials(self):
        page = self.client.get("/login", base_url="https://localhost")
        text = page.get_data(as_text=True)
        self.assertNotIn("调试信息", text)
        self.assertNotIn("默认管理员账号", text)

    def test_login_redirects_and_public_page_excludes_password(self):
        response = self.login("alice", self.alice_password)
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/", base_url="https://localhost")
        text = page.get_data(as_text=True)
        self.assertIn("alice@example.invalid", text)
        self.assertNotIn(self.alice_password, text)
        self.assertNotIn("密码：", text)

    def test_missing_csrf_token_is_rejected(self):
        response = self.client.post(
            "/login",
            data={"username": "alice", "password": self.alice_password},
            base_url="https://localhost",
        )
        self.assertEqual(response.status_code, 400)

    def test_logout_is_post_only_and_requires_csrf(self):
        self.login("alice", self.alice_password)
        self.assertEqual(
            self.client.get("/logout", base_url="https://localhost").status_code,
            405,
        )
        token = csrf_token(self.client, "/")
        response = self.client.post(
            "/logout",
            data={"csrf_token": token},
            base_url="https://localhost",
        )
        self.assertEqual(response.status_code, 302)

    def test_sixth_matching_login_attempt_is_rate_limited(self):
        token = csrf_token(self.client)
        data = {"username": "admin", "password": "wrong", "csrf_token": token}
        for _ in range(5):
            self.assertEqual(
                self.client.post(
                    "/login", data=data, base_url="https://localhost"
                ).status_code,
                401,
            )
        self.assertEqual(
            self.client.post(
                "/login", data=data, base_url="https://localhost"
            ).status_code,
            429,
        )

    def test_session_cookie_has_required_flags(self):
        response = self.login("alice", self.alice_password)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_dynamic_responses_have_security_headers_and_no_store(self):
        response = self.client.get("/login", base_url="https://localhost")
        self.assertEqual(response.headers["Cache-Control"], "no-store, private")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertIn("max-age=31536000", response.headers["Strict-Transport-Security"])

    def test_oversized_credentials_are_rejected(self):
        token = csrf_token(self.client)
        response = self.client.post(
            "/login",
            data={"username": "u" * 65, "password": "p", "csrf_token": token},
            base_url="https://localhost",
        )
        self.assertEqual(response.status_code, 400)

    def test_oversized_request_body_is_rejected(self):
        response = self.client.post(
            "/login",
            data={"username": "u" * 20 * 1024 * 1024},
            base_url="https://localhost",
        )
        self.assertEqual(response.status_code, 413)

    def test_tampered_session_cookie_is_rejected(self):
        self.login("admin", self.admin_password)
        cookie_name = self.app.config["SESSION_COOKIE_NAME"]
        cookie = self.client.get_cookie(cookie_name, domain="localhost")
        self.assertIsNotNone(cookie)
        value = cookie.value
        tampered = ("A" if value[0] != "A" else "B") + value[1:]
        self.client.set_cookie(cookie_name, tampered, domain="localhost")
        page = self.client.get("/", base_url="https://localhost")
        self.assertIn("请先登录", page.get_data(as_text=True))

    def test_admin_session_signed_with_retired_key_is_rejected(self):
        retired_app = Flask("retired-session-signer")
        retired_app.config["SECRET_KEY"] = RETIRED_SESSION_KEY
        serializer = retired_app.session_interface.get_signing_serializer(retired_app)
        retired_cookie = serializer.dumps({"username": "admin"})

        cookie_name = self.app.config["SESSION_COOKIE_NAME"]
        self.client.set_cookie(cookie_name, retired_cookie, domain="localhost")
        page = self.client.get("/", base_url="https://localhost")
        text = page.get_data(as_text=True)

        self.assertIn("请先登录", text)
        self.assertNotIn("admin@example.invalid", text)


class RegistrationAndSearchTests(unittest.TestCase):
    """注册和搜索功能的专项安全测试"""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        cls.store_path = Path(cls.temp_dir.name) / "users.json"
        cls.admin_password = secrets.token_urlsafe(24)
        cls.alice_password = secrets.token_urlsafe(24)
        write_password_store(cls.store_path, cls.admin_password, cls.alice_password)

    def setUp(self):
        self.clean_db()
        self.config = valid_config(self.store_path)
        self.app = create_app(self.config)
        self.app.logger.disabled = True
        self.client = self.app.test_client()
        self._test_counter = 0

    def tearDown(self):
        self.clean_db()

    @staticmethod
    def clean_db():
        db_path = Path("data/users.db")
        if db_path.exists():
            db_path.unlink()
        pycache = Path("data/__pycache__")
        if pycache.exists():
            import shutil

            shutil.rmtree(pycache, ignore_errors=True)

    def unique_username(self, prefix="reguser"):
        self._test_counter += 1
        return f"{prefix}_{self._test_counter}_{secrets.token_hex(4)}"

    def login(self, username, password):
        token = csrf_token(self.client)
        return self.client.post(
            "/login",
            data={"username": username, "password": password, "csrf_token": token},
            base_url="https://localhost",
        )

    def register(
        self,
        client=None,
        username="reguser",
        password="regpass123",
        email="reg@test.com",
        phone="13800138001",
        csrf_token_val=None,
    ):
        if client is None:
            client = self.client
        if csrf_token_val is None:
            csrf_token_val = csrf_token(client, "/register")
        return client.post(
            "/register",
            data={
                "username": username,
                "password": password,
                "email": email,
                "phone": phone,
                "csrf_token": csrf_token_val,
            },
            base_url="https://localhost",
        )

    # --- 注册功能测试 ---

    def test_register_page_contains_csrf_token(self):
        """注册页面必须包含 CSRF Token"""
        page = self.client.get("/register", base_url="https://localhost")
        self.assertIn("csrf_token", page.get_data(as_text=True))

    def test_register_without_csrf_is_rejected(self):
        """无 CSRF Token 的注册请求被拒绝"""
        response = self.client.post(
            "/register",
            data={"username": "u", "password": "p123456"},
            base_url="https://localhost",
        )
        self.assertEqual(response.status_code, 400)

    def test_register_success_creates_user_and_redirects(self):
        """注册成功后跳转到登录页并提示"""
        username = self.unique_username("success")
        response = self.register(username=username)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login?registered=success", response.location)

    def test_register_short_password_is_rejected(self):
        """短密码（<6位）被拒绝"""
        token = csrf_token(self.client, "/register")
        response = self.client.post(
            "/register",
            data={
                "username": self.unique_username("shortpwd"),
                "password": "12345",
                "csrf_token": token,
            },
            base_url="https://localhost",
        )
        self.assertIn("密码长度", response.get_data(as_text=True))

    def test_register_duplicate_username_is_rejected(self):
        """重复用户名注册被拒绝"""
        username = self.unique_username("dupe")
        token1 = csrf_token(self.client, "/register")
        self.register(username=username, csrf_token_val=token1)

        token2 = csrf_token(self.client, "/register")
        response = self.register(username=username, csrf_token_val=token2)
        self.assertIn("用户名已存在", response.get_data(as_text=True))

    def test_registered_user_can_login(self):
        """注册的用户可以正常登录"""
        username = self.unique_username("login")
        password = "loginpass123"
        reg_token = csrf_token(self.client, "/register")
        self.register(username=username, password=password, csrf_token_val=reg_token)

        login_token = csrf_token(self.client)
        response = self.client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": login_token,
            },
            base_url="https://localhost",
        )
        self.assertEqual(response.status_code, 302)

    def test_register_error_does_not_leak_sql_details(self):
        """注册错误不泄露 SQL 细节（通用错误信息）"""
        username = self.unique_username("noleak")
        token1 = csrf_token(self.client, "/register")
        # 先注册一个用户
        self.register(username=username, csrf_token_val=token1)
        # 再注册相同用户名（用新token）
        token2 = csrf_token(self.client, "/register")
        response = self.register(username=username, csrf_token_val=token2)
        text = response.get_data(as_text=True)
        self.assertNotIn("UNIQUE", text)
        self.assertNotIn("constraint", text)
        self.assertNotIn("sqlite3", text)
        self.assertNotIn("IntegrityError", text)
        self.assertIn("用户名已存在", text)

    # --- 搜索功能测试 ---

    def test_search_requires_login(self):
        """未登录用户搜索被重定向到登录页"""
        response = self.client.get(
            "/search?keyword=admin", base_url="https://localhost"
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_search_returns_results_for_logged_in_user(self):
        """已登录用户可以搜索"""
        self.login("admin", self.admin_password)
        response = self.client.get(
            "/search?keyword=admin", base_url="https://localhost"
        )
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("搜索结果", text)

    def test_search_sql_injection_does_not_return_all_users(self):
        """SQL 注入攻击不会返回全部用户数据（参数化查询生效）"""
        self.login("admin", self.admin_password)

        response = self.client.get(
            "/search?keyword=' OR 1=1--", base_url="https://localhost"
        )
        text = response.get_data(as_text=True)
        # 参数化查询应拦截注入，搜索结果应为空或仅有匹配用户
        # ' OR 1=1-- 作为字面字符串搜索，不应匹配任何用户
        self.assertIn("无搜索结果", text)

    def test_search_with_empty_keyword_returns_nothing(self):
        """空关键词搜索返回无结果"""
        self.login("admin", self.admin_password)
        response = self.client.get("/search?keyword=", base_url="https://localhost")
        text = response.get_data(as_text=True)
        self.assertIn("无搜索结果", text)


class UploadSecurityTests(unittest.TestCase):
    """文件上传功能的专项安全测试"""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        cls.store_path = Path(cls.temp_dir.name) / "users.json"
        cls.admin_password = secrets.token_urlsafe(24)
        cls.alice_password = secrets.token_urlsafe(24)
        write_password_store(cls.store_path, cls.admin_password, cls.alice_password)

    def setUp(self):
        self.clean_uploads()
        self.config = valid_config(self.store_path)
        self.app = create_app(self.config)
        self.app.logger.disabled = True
        self.client = self.app.test_client()

    def tearDown(self):
        self.clean_uploads()

    @staticmethod
    def clean_uploads():
        upload_dir = Path("static/uploads")
        if upload_dir.exists():
            import shutil

            shutil.rmtree(upload_dir, ignore_errors=True)

    def login(self):
        token = csrf_token(self.client)
        self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": self.admin_password,
                "csrf_token": token,
            },
            base_url="https://localhost",
        )

    def test_upload_requires_login(self):
        """未登录用户访问上传页面被重定向"""
        response = self.client.get("/upload", base_url="https://localhost")
        self.assertEqual(response.status_code, 302)

    def test_upload_page_has_csrf_token(self):
        """上传页面包含 CSRF Token"""
        self.login()
        page = self.client.get("/upload", base_url="https://localhost")
        self.assertIn("csrf_token", page.get_data(as_text=True))

    def test_upload_png_succeeds(self):
        """上传合法 PNG 文件成功"""
        self.login()
        token = csrf_token(self.client, "/upload")
        data = {
            "file": (io.BytesIO(self._minimal_png()), "avatar.png"),
            "csrf_token": token,
        }
        response = self.client.post(
            "/upload",
            data=data,
            base_url="https://localhost",
            content_type="multipart/form-data",
        )
        self.assertIn("上传成功", response.get_data(as_text=True))

    def test_upload_php_is_rejected(self):
        """上传 PHP 文件被拒绝"""
        self.login()
        token = csrf_token(self.client, "/upload")
        data = {
            "file": (io.BytesIO(b"<?php phpinfo(); ?>"), "shell.php"),
            "csrf_token": token,
        }
        response = self.client.post(
            "/upload",
            data=data,
            base_url="https://localhost",
            content_type="multipart/form-data",
        )
        self.assertIn("不支持", response.get_data(as_text=True))

    def test_upload_html_is_rejected(self):
        """上传 HTML 文件被拒绝"""
        self.login()
        token = csrf_token(self.client, "/upload")
        data = {
            "file": (io.BytesIO(b"<script>alert(1)</script>"), "xss.html"),
            "csrf_token": token,
        }
        response = self.client.post(
            "/upload",
            data=data,
            base_url="https://localhost",
            content_type="multipart/form-data",
        )
        self.assertIn("不支持", response.get_data(as_text=True))

    def test_upload_fake_webp_is_rejected(self):
        """仅修改扩展名不能绕过图片内容校验"""
        self.login()
        token = csrf_token(self.client, "/upload")
        data = {
            "file": (io.BytesIO(b"<script>alert(1)</script>"), "avatar.webp"),
            "csrf_token": token,
        }

        response = self.client.post(
            "/upload",
            data=data,
            base_url="https://localhost",
            content_type="multipart/form-data",
        )

        self.assertIn("文件内容与扩展名不匹配", response.get_data(as_text=True))

    def test_upload_exe_is_rejected(self):
        """上传 EXE 文件被拒绝"""
        self.login()
        token = csrf_token(self.client, "/upload")
        data = {
            "file": (io.BytesIO(b"MZ\x90\x00"), "virus.exe"),
            "csrf_token": token,
        }
        response = self.client.post(
            "/upload",
            data=data,
            base_url="https://localhost",
            content_type="multipart/form-data",
        )
        self.assertIn("不支持", response.get_data(as_text=True))

    def test_upload_without_csrf_is_rejected(self):
        """无 CSRF Token 的上传被拒绝"""
        self.login()
        data = {
            "file": (io.BytesIO(self._minimal_png()), "avatar.png"),
        }
        response = self.client.post(
            "/upload",
            data=data,
            base_url="https://localhost",
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_upload_overwrite_protection(self):
        """同名文件不会被覆盖（文件名加随机后缀）"""
        self.login()
        token = csrf_token(self.client, "/upload")
        data1 = {
            "file": (io.BytesIO(self._minimal_png()), "avatar.png"),
            "csrf_token": token,
        }
        r1 = self.client.post(
            "/upload",
            data=data1,
            base_url="https://localhost",
            content_type="multipart/form-data",
        )
        token2 = csrf_token(self.client, "/upload")
        data2 = {
            "file": (io.BytesIO(self._minimal_png()), "avatar.png"),
            "csrf_token": token2,
        }
        r2 = self.client.post(
            "/upload",
            data=data2,
            base_url="https://localhost",
            content_type="multipart/form-data",
        )
        url1 = (
            r1.get_data(as_text=True).split("uploads/")[1].split('"')[0]
            if "uploads/" in r1.get_data(as_text=True)
            else ""
        )
        url2 = (
            r2.get_data(as_text=True).split("uploads/")[1].split('"')[0]
            if "uploads/" in r2.get_data(as_text=True)
            else ""
        )
        self.assertNotEqual(url1, url2, "两次上传应生成不同文件名")

    def test_upload_never_overwrites_preexisting_storage_target(self):
        """随机名发生冲突时也不能覆盖已有文件或符号链接目标"""
        self.login()
        user_dir = Path("static/uploads/admin")
        user_dir.mkdir(parents=True, exist_ok=True)
        existing_path = user_dir / "avatar_fixed.png"
        existing_path.write_bytes(b"do-not-overwrite")
        token = csrf_token(self.client, "/upload")

        with patch("app.secrets.token_hex", return_value="fixed"):
            response = self.client.post(
                "/upload",
                data={
                    "file": (io.BytesIO(self._minimal_png()), "avatar.png"),
                    "csrf_token": token,
                },
                base_url="https://localhost",
                content_type="multipart/form-data",
            )

        self.assertEqual(existing_path.read_bytes(), b"do-not-overwrite")
        self.assertIn("文件名冲突", response.get_data(as_text=True))

    def test_uploaded_file_under_user_directory(self):
        """上传文件保存在对应用户目录下"""
        self.login()
        token = csrf_token(self.client, "/upload")
        data = {
            "file": (io.BytesIO(self._minimal_png()), "test.png"),
            "csrf_token": token,
        }
        self.client.post(
            "/upload",
            data=data,
            base_url="https://localhost",
            content_type="multipart/form-data",
        )
        user_dir = Path("static/uploads/admin")
        self.assertTrue(user_dir.exists(), "用户目录应存在")
        self.assertTrue(any(user_dir.iterdir()), "用户目录应有文件")

    @staticmethod
    def _minimal_png():
        """生成 1x1 红色像素 PNG"""
        import struct
        import zlib

        def chunk(t, d):
            p = t + d
            return (
                struct.pack(">I", len(d))
                + p
                + struct.pack(">I", zlib.crc32(p) & 0xFFFFFFFF)
            )

        sig = b"\x89PNG\r\n\x1a\n"
        ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        raw = b"\x00\xff\x00\x00"  # filter byte + red pixel
        idat = chunk(b"IDAT", zlib.compress(raw))
        iend = chunk(b"IEND", b"")
        return sig + ihdr + idat + iend


class PersonalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        cls.store_path = Path(cls.temp_dir.name) / "users.json"
        write_password_store(
            cls.store_path,
            secrets.token_urlsafe(24),
            secrets.token_urlsafe(24),
        )

    def setUp(self):
        self.app = create_app(valid_config(self.store_path))
        self.app.logger.disabled = True
        self.client = self.app.test_client()

    def test_welcome_renders_name_and_navigation(self):
        response = self.client.get(
            "/welcome?name=%E5%BC%A0%E4%B8%89", base_url="https://localhost"
        )
        text = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("欢迎你，张三！", text)
        self.assertIn('href="/welcome"', text)
        self.assertIn('href="/feedback"', text)

    def test_welcome_uses_default_greeting_for_empty_name(self):
        response = self.client.get("/welcome", base_url="https://localhost")

        self.assertEqual(response.status_code, 200)
        self.assertIn("亲爱的用户，欢迎你！", response.get_data(as_text=True))

    def test_welcome_does_not_evaluate_template_syntax_from_query(self):
        response = self.client.get(
            "/welcome?name={{7*7}}", base_url="https://localhost"
        )
        text = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("{{7*7}}", text)
        self.assertNotIn("欢迎你，49！", text)

    def test_feedback_form_and_submission_escape_untrusted_input(self):
        form = self.client.get("/feedback", base_url="https://localhost")
        token = CSRF_PATTERN.search(form.get_data(as_text=True)).group(1)
        response = self.client.post(
            "/feedback",
            data={
                "name": "{{7*7}}",
                "message": "<script>alert(1)</script>",
                "csrf_token": token,
            },
            base_url="https://localhost",
        )
        text = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("{{7*7}}", text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)
        self.assertNotIn("<script>alert(1)</script>", text)

    def test_feedback_rejects_oversized_message(self):
        form = self.client.get("/feedback", base_url="https://localhost")
        token = CSRF_PATTERN.search(form.get_data(as_text=True)).group(1)
        response = self.client.post(
            "/feedback",
            data={
                "name": "tester",
                "message": "x" * 2001,
                "csrf_token": token,
            },
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("反馈内容过长", response.get_data(as_text=True))

    def test_welcome_rejects_oversized_name(self):
        response = self.client.get(
            "/welcome?name=" + "x" * 65,
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 400)


class AccessControlAndExternalFetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        cls.store_path = Path(cls.temp_dir.name) / "users.json"
        write_password_store(
            cls.store_path,
            secrets.token_urlsafe(24),
            secrets.token_urlsafe(24),
        )

    def setUp(self):
        self.app = create_app(valid_config(self.store_path))
        self.app.logger.disabled = True
        self.client = self.app.test_client()

    def login_as(self, username):
        set_authenticated_session(self.app, self.client, username)

    def test_profile_rejects_client_selected_user_id(self):
        self.login_as("alice")

        response = self.client.get("/profile?user_id=0", base_url="https://localhost")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/profile")

    def test_recharge_cannot_change_another_users_balance(self):
        self.login_as("alice")
        token = csrf_token(self.client, "/profile")
        original_balance = self.app.extensions["users"]["admin"]["balance"]

        response = self.client.post(
            "/recharge",
            data={"user_id": "0", "amount": "100", "csrf_token": token},
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            self.app.extensions["users"]["admin"]["balance"], original_balance
        )

    def test_fetch_page_requires_login(self):
        response = self.client.get(
            "/fetch-page?url=https://example.com", base_url="https://localhost"
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    @patch("app._fetch_https_once")
    @patch(
        "app.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]
    )
    def test_fetch_page_denies_hosts_not_explicitly_allowed(self, _dns, pinned_fetch):
        self.login_as("admin")

        response = self.client.get(
            "/fetch-page?url=https://example.com", base_url="https://localhost"
        )

        self.assertEqual(response.status_code, 403)
        pinned_fetch.assert_not_called()

    @patch("app._fetch_https_once")
    @patch(
        "app.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]
    )
    def test_fetch_page_sandboxes_external_content(self, _dns, pinned_fetch):
        config = valid_config(self.store_path)
        config["FETCH_ALLOWED_HOSTS"] = ("example.com",)
        app = create_app(config)
        app.logger.disabled = True
        client = app.test_client()
        response_mock = Mock(
            status_code=200,
            headers={},
            text="<script>alert(1)</script>",
        )
        pinned_fetch.return_value = response_mock
        set_authenticated_session(app, client, "admin")

        response = client.get(
            "/fetch-page?url=https://example.com", base_url="https://localhost"
        )
        text = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("<iframe", text)
        self.assertIn("sandbox", text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)
        self.assertNotIn("<script>alert(1)</script>", text)


class PingDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        cls.store_path = Path(cls.temp_dir.name) / "users.json"
        write_password_store(
            cls.store_path,
            secrets.token_urlsafe(24),
            secrets.token_urlsafe(24),
        )

    def setUp(self):
        self.app = create_app(valid_config(self.store_path))
        self.app.logger.disabled = True
        self.client = self.app.test_client()

    def login_as(self, username="alice"):
        set_authenticated_session(self.app, self.client, username)

    def test_ping_requires_login(self):
        response = self.client.get("/ping", base_url="https://localhost")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_ping_page_renders_for_authenticated_user(self):
        self.login_as()

        response = self.client.get("/ping", base_url="https://localhost")
        text = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('name="ip"', text)
        self.assertIn('name="csrf_token"', text)
        self.assertIn('href="/ping"', text)

    @patch("app.subprocess.run")
    def test_ping_rejects_non_global_or_injection_like_input(self, run):
        self.login_as()
        token = csrf_token(self.client, "/ping")

        response = self.client.post(
            "/ping",
            data={"ip": "127.0.0.1; id", "csrf_token": token},
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("有效的公网 IP", response.get_data(as_text=True))
        run.assert_not_called()

    @patch("app.platform.system", return_value="Linux")
    @patch("app.subprocess.run")
    def test_ping_uses_argument_array_and_renders_output(self, run, _platform):
        self.login_as()
        run.return_value = Mock(returncode=0, stdout="3 packets transmitted", stderr="")
        token = csrf_token(self.client, "/ping")

        response = self.client.post(
            "/ping",
            data={"ip": "8.8.8.8", "csrf_token": token},
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("3 packets transmitted", response.get_data(as_text=True))
        run.assert_called_once_with(
            [self.app.config["PING_EXECUTABLE"], "-c", "3", "8.8.8.8"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )

    @patch("app.platform.system", return_value="Windows")
    @patch("app.subprocess.run")
    def test_ping_renders_bounded_command_failure_output(self, run, _platform):
        self.login_as()
        run.return_value = Mock(returncode=1, stdout="", stderr="Request timed out")
        token = csrf_token(self.client, "/ping")

        response = self.client.post(
            "/ping",
            data={"ip": "1.1.1.1", "csrf_token": token},
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Request timed out", response.get_data(as_text=True))
        run.assert_called_once_with(
            [self.app.config["PING_EXECUTABLE"], "-n", "3", "1.1.1.1"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )


class CredentialChangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        cls.store_path = Path(cls.temp_dir.name) / "users.json"
        cls.alice_password = secrets.token_urlsafe(24)
        write_password_store(
            cls.store_path,
            secrets.token_urlsafe(24),
            cls.alice_password,
        )

    def setUp(self):
        self.app = create_app(valid_config(self.store_path))
        self.app.logger.disabled = True
        self.client = self.app.test_client()
        set_authenticated_session(self.app, self.client, "alice")

    def test_profile_requires_login(self):
        anonymous_client = self.app.test_client()

        response = anonymous_client.get("/profile", base_url="https://localhost")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_profile_does_not_offer_unverified_direct_recharge(self):
        response = self.client.get("/profile", base_url="https://localhost")
        text = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('action="/recharge"', text)
        self.assertIn("支付服务暂未启用", text)

    def test_change_password_rejects_incorrect_current_password(self):
        original_hash = self.app.extensions["users"]["alice"]["password_hash"]
        token = csrf_token(self.client, "/profile")

        response = self.client.post(
            "/change-password",
            data={
                "username": "alice",
                "current_password": "incorrect",
                "new_password": "new-password-123",
                "confirm_password": "new-password-123",
                "csrf_token": token,
            },
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.app.extensions["users"]["alice"]["password_hash"], original_hash
        )

    def test_change_password_requires_confirmation_and_current_password(self):
        token = csrf_token(self.client, "/profile")

        response = self.client.post(
            "/change-password",
            data={
                "username": "alice",
                "current_password": self.alice_password,
                "new_password": "new-password-123",
                "confirm_password": "different-password-456",
                "csrf_token": token,
            },
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            check_password_hash(
                self.app.extensions["users"]["alice"]["password_hash"],
                self.alice_password,
            )
        )

    def test_change_password_updates_only_after_reauthentication(self):
        token = csrf_token(self.client, "/profile")

        response = self.client.post(
            "/change-password",
            data={
                "username": "alice",
                "current_password": self.alice_password,
                "new_password": "new-password-123",
                "confirm_password": "new-password-123",
                "csrf_token": token,
            },
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            check_password_hash(
                self.app.extensions["users"]["alice"]["password_hash"],
                "new-password-123",
            )
        )


class DynamicPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        cls.store_path = Path(cls.temp_dir.name) / "users.json"
        write_password_store(
            cls.store_path,
            secrets.token_urlsafe(24),
            secrets.token_urlsafe(24),
        )

    def setUp(self):
        self.app = create_app(valid_config(self.store_path))
        self.app.logger.disabled = True
        self.client = self.app.test_client()

    def test_help_page_is_available_from_dynamic_page_route(self):
        response = self.client.get("/page?name=help", base_url="https://localhost")

        self.assertEqual(response.status_code, 200)
        self.assertIn("帮助中心", response.get_data(as_text=True))

    def test_dynamic_page_rejects_path_traversal_without_disclosing_source(self):
        response = self.client.get("/page?name=../app.py", base_url="https://localhost")
        text = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("def create_app", text)
        self.assertIn("页面不存在", text)


if __name__ == "__main__":
    unittest.main()
