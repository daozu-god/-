import hashlib
import hmac
import http.client
import ipaddress
import os
import platform
import secrets
import socket
import sqlite3
import ssl
import subprocess
from contextlib import closing
from datetime import timedelta
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

from flask import (
    Flask,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from credential_store import (
    DEFAULT_USER_STORE_PATH,
    load_password_hashes,
    update_password_hash,
)


PUBLIC_USER_FIELDS = ("username", "email", "phone", "role", "balance")
USER_PROFILES = {
    "admin": {
        "username": "admin",
        "role": "admin",
        "email": "admin@example.invalid",
        "phone": "未公开",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "role": "user",
        "email": "alice@example.invalid",
        "phone": "未公开",
        "balance": 100,
    },
}
SECURITY_POLICY = (
    "default-src 'self'; style-src 'self'; img-src 'self'; base-uri 'self'; "
    "frame-ancestors 'none'; form-action 'self'"
)

# 允许上传的图片文件扩展名
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "ico"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB 单文件限制
MAX_PING_OUTPUT = 8 * 1024
MAX_FETCH_BYTES = 256 * 1024
DATABASE_PATH = Path(__file__).resolve().parent / "data" / "users.db"
PAGES_DIRECTORY = Path(__file__).resolve().parent / "pages"

# 图片文件魔数签名验证（轻量级 Content-Type 校验）
# 仅校验特征明显的格式，避免误判
IMAGE_MAGIC_MAP = {
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"],
    "bmp": [b"BM"],
    "ico": [b"\x00\x00\x01\x00"],
}


def _trusted_hosts(raw_value):
    return [host.strip() for host in raw_value.split(",") if host.strip()]


def _matches_image_signature(extension, header):
    if extension == "webp":
        return (
            len(header) >= 12 and header.startswith(b"RIFF") and header[8:12] == b"WEBP"
        )
    return any(
        header.startswith(signature) for signature in IMAGE_MAGIC_MAP.get(extension, ())
    )


def _safe_log_value(value, max_length=160):
    text = str(value)
    escaped = "".join(
        character
        if character.isprintable() and character not in "\r\n"
        else f"\\x{ord(character):02x}"
        for character in text
    )
    return escaped[:max_length]


def _default_ping_executable():
    if platform.system() == "Windows":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        return str((system_root / "System32" / "PING.EXE").resolve())

    for candidate in (Path("/usr/bin/ping"), Path("/bin/ping")):
        if candidate.is_file():
            return str(candidate)
    return "/usr/bin/ping"


def _load_static_pages():
    pages = {}
    try:
        entries = tuple(PAGES_DIRECTORY.iterdir())
    except OSError as error:
        raise RuntimeError("pages directory cannot be read") from error

    for entry in entries:
        if (
            entry.suffix.lower() != ".html"
            or entry.is_symlink()
            or not entry.is_file()
            or len(entry.name) > 100
        ):
            continue
        try:
            pages[entry.name] = entry.read_text(encoding="utf-8")
        except OSError as error:
            raise RuntimeError(f"page cannot be read: {entry.name}") from error
    return pages


class FetchResponseTooLarge(RuntimeError):
    pass


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, ip_address, server_hostname, timeout=5):
        super().__init__(
            ip_address,
            port=443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._verified_server_hostname = server_hostname

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=self._verified_server_hostname,
        )


class _HTTPSFetchResult:
    def __init__(self, status_code, headers, text):
        self.status_code = status_code
        self.headers = headers
        self.text = text


def _fetch_https_once(url, hostname, ip_address):
    parsed = urlsplit(url)
    request_target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    connection = _PinnedHTTPSConnection(ip_address, hostname, timeout=5)
    try:
        connection.request(
            "GET",
            request_target,
            headers={
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Connection": "close",
                "Host": hostname,
                "User-Agent": "Class01-SafeFetcher/1.0",
            },
        )
        response = connection.getresponse()
        body = response.read(MAX_FETCH_BYTES + 1)
        if len(body) > MAX_FETCH_BYTES:
            raise FetchResponseTooLarge("响应内容过大")
        charset = response.headers.get_content_charset() or "utf-8"
        try:
            text = body.decode(charset, errors="replace")
        except LookupError:
            text = body.decode("utf-8", errors="replace")
        return _HTTPSFetchResult(
            response.status,
            {key.lower(): value for key, value in response.getheaders()},
            text,
        )
    finally:
        connection.close()


def _validate_runtime_config(config):
    secret_key = config.get("SECRET_KEY")
    if not isinstance(secret_key, str) or len(secret_key) < 32:
        raise RuntimeError("SECRET_KEY must contain at least 32 characters")
    ping_executable = config.get("PING_EXECUTABLE")
    is_absolute = ping_executable and (
        PurePosixPath(ping_executable).is_absolute()
        or PureWindowsPath(ping_executable).is_absolute()
    )
    if not is_absolute:
        raise RuntimeError("PING_EXECUTABLE must be an absolute path")


def _build_users(password_hashes):
    return {
        username: {**profile, "password_hash": password_hashes[username]}
        for username, profile in USER_PROFILES.items()
    }


def init_db():
    """初始化 SQLite 数据库——创建用户表（供注册和搜索使用）"""
    data_directory = DATABASE_PATH.parent
    data_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if data_directory.is_symlink():
        raise RuntimeError("database directory must not be a symbolic link")
    os.chmod(data_directory, 0o700)

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            DATABASE_PATH,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | no_follow,
            0o600,
        )
    except FileExistsError:
        if DATABASE_PATH.is_symlink():
            raise RuntimeError("database file must not be a symbolic link")
    else:
        os.close(descriptor)
    os.chmod(DATABASE_PATH, 0o600)

    with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as conn:
        cursor = conn.cursor()
        # 启用 WAL 模式，提高并发写入性能
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                balance REAL DEFAULT 0.0
            )
        """)
        # 确保 balance 列存在（兼容旧表）
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0.0")
        except sqlite3.OperationalError:
            pass  # 列已存在
        cursor.executemany(
            "DELETE FROM users WHERE username = ?",
            [(username,) for username in USER_PROFILES],
        )
        conn.commit()
    print(f"[OK] SQLite database initialized ({DATABASE_PATH})")


def create_app(test_config=None):
    app = Flask(__name__)
    development_mode = os.getenv("APP_ENV", "production").casefold() == "development"
    app.config.from_mapping(
        SECRET_KEY=os.getenv("APP_SECRET_KEY"),
        USER_STORE_PATH=os.getenv("USER_STORE_PATH", str(DEFAULT_USER_STORE_PATH)),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=16 * 1024 * 1024,
        MAX_FORM_PARTS=10,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        PREFERRED_URL_SCHEME="http" if development_mode else "https",
        RATELIMIT_HEADERS_ENABLED=True,
        RATELIMIT_STORAGE_URI=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=not development_mode,
        TRUSTED_HOSTS=_trusted_hosts(
            os.getenv("APP_TRUSTED_HOSTS", "localhost,127.0.0.1")
        ),
        WTF_CSRF_SSL_STRICT=not development_mode,
        WTF_CSRF_TIME_LIMIT=1800,
        FETCH_ALLOWED_HOSTS=tuple(
            host.lower()
            for host in _trusted_hosts(os.getenv("FETCH_ALLOWED_HOSTS", ""))
        ),
        PING_EXECUTABLE=_default_ping_executable(),
    )
    if test_config:
        app.config.update(test_config)

    _validate_runtime_config(app.config)
    users = _build_users(load_password_hashes(app.config["USER_STORE_PATH"]))
    static_pages = _load_static_pages()
    app.extensions["users"] = users

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    CSRFProtect(app)

    # 初始化 SQLite 数据库
    init_db()

    def credential_version_for(username):
        password_hash = None
        user = users.get(username)
        if user:
            password_hash = user["password_hash"]
        else:
            try:
                with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                    row = conn.execute(
                        "SELECT password_hash FROM users WHERE username = ?",
                        (username,),
                    ).fetchone()
                if row:
                    password_hash = row[0]
            except sqlite3.Error:
                return None

        if not password_hash:
            return None
        return hmac.new(
            app.secret_key.encode("utf-8"),
            password_hash.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    app.extensions["credential_version_for"] = credential_version_for

    @app.before_request
    def reject_stale_authenticated_session():
        username = session.get("username")
        if not username:
            return None
        expected_version = credential_version_for(username)
        presented_version = session.get("credential_version", "")
        if (
            not expected_version
            or not presented_version
            or not hmac.compare_digest(expected_version, presented_version)
        ):
            session.clear()
        return None

    def login_rate_limit_key():
        username = request.form.get("username", "")[:64].casefold()
        return f"{get_remote_address()}:{username}"

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[],
        storage_uri=app.config["RATELIMIT_STORAGE_URI"],
        headers_enabled=True,
    )

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = SECURITY_POLICY
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        app.logger.warning(
            "csrf_rejected remote_addr=%s reason=%s",
            request.remote_addr,
            error.description,
        )
        return render_template("login.html", error="请求无效，请刷新页面后重试"), 400

    @app.errorhandler(413)
    def handle_request_too_large(error):
        app.logger.warning("request_too_large remote_addr=%s", request.remote_addr)
        return render_template("login.html", error="请求内容过大"), 413

    @app.errorhandler(429)
    def handle_rate_limit(error):
        app.logger.warning("rate_limited remote_addr=%s", request.remote_addr)
        return render_template("login.html", error="请求过于频繁，请稍后再试"), 429

    @app.get("/")
    def index():
        username = session.get("username")
        user = users.get(username) if username else None
        is_sqlite_user = False

        # 如果在 JSON 中找不到，检查 SQLite（注册用户）
        if username and user is None:
            try:
                with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT 1 FROM users WHERE username = ?", (username,)
                    )
                    is_sqlite_user = cursor.fetchone() is not None
            except sqlite3.Error:
                pass

        if username and user is None and not is_sqlite_user:
            session.clear()
            username = None
        elif is_sqlite_user:
            # SQLite 注册用户——读取全部公开字段（含 balance）
            try:
                with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT email, phone, balance FROM users WHERE username = ?",
                        (username,),
                    )
                    row = cursor.fetchone()
                if row:
                    user = {
                        "username": username,
                        "email": row[0] or "",
                        "phone": row[1] or "",
                        "balance": row[2] or 0,
                    }
                else:
                    is_sqlite_user = False
            except sqlite3.Error:
                is_sqlite_user = False

        public_user = (
            {field: user[field] for field in PUBLIC_USER_FIELDS if field in user}
            if user
            else None
        )
        return render_template(
            "index.html",
            username=username,
            user=public_user,
            search_results=None,
            keyword="",
            page_content=None,
            page_error=None,
        )

    @app.get("/welcome")
    def welcome():
        name = request.args.get("name", "").strip()
        if len(name) > 64:
            return render_template_string(
                """
                {% extends "base.html" %}
                {% block content %}
                <section class="card"><p class="error-message">姓名过长</p></section>
                {% endblock %}
                """
            ), 400
        greeting = f"欢迎你，{name}！" if name else "亲爱的用户，欢迎你！"
        return render_template_string(
            """
            {% extends "base.html" %}
            {% block content %}
            <section class="card">
                <h1>{{ greeting }}</h1>
            </section>
            {% endblock %}
            """,
            greeting=greeting,
        )

    @app.route("/feedback", methods=["GET", "POST"])
    def feedback():
        if request.method == "POST":
            name = request.form.get("name", "").strip() or "匿名用户"
            message = request.form.get("message", "").strip()
            if len(name) > 64 or len(message) > 2000:
                return render_template_string(
                    """
                    {% extends "base.html" %}
                    {% block content %}
                    <section class="card">
                        <p class="error-message">反馈内容过长</p>
                        <a href="{{ url_for('feedback') }}">返回反馈表单</a>
                    </section>
                    {% endblock %}
                    """
                ), 400
            return render_template_string(
                """
                {% extends "base.html" %}
                {% block content %}
                <section class="card">
                    <h2>{{ name }} 的反馈：</h2>
                    <p>{{ message }}</p>
                </section>
                {% endblock %}
                """,
                name=name,
                message=message,
            )

        return render_template_string(
            """
            {% extends "base.html" %}
            {% block content %}
            <section class="card">
                <h1>反馈</h1>
                <form method="POST" action="{{ url_for('feedback') }}">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <label for="feedback-name">姓名</label>
                    <input id="feedback-name" name="name" type="text" maxlength="64">
                    <label for="feedback-message">留言</label>
                    <textarea id="feedback-message" name="message" rows="5" maxlength="2000"></textarea>
                    <button type="submit">提交</button>
                </form>
            </section>
            {% endblock %}
            """
        )

    @app.route("/ping", methods=["GET", "POST"])
    @limiter.limit("5 per minute", key_func=get_remote_address, methods=["POST"])
    def ping():
        if not session.get("username"):
            return redirect(url_for("login"))

        target = ""
        output = None
        error = None
        status_code = 200

        if request.method == "POST":
            target = request.form.get("ip", "").strip()
            try:
                parsed_ip = ipaddress.ip_address(target)
            except ValueError:
                error = "请输入有效的公网 IP 地址"
                status_code = 400
            else:
                if not parsed_ip.is_global:
                    error = "仅允许测试公网 IP 地址"
                    status_code = 400
                else:
                    count_flag = "-n" if platform.system() == "Windows" else "-c"
                    try:
                        completed = subprocess.run(
                            [
                                app.config["PING_EXECUTABLE"],
                                count_flag,
                                "3",
                                str(parsed_ip),
                            ],
                            capture_output=True,
                            check=False,
                            text=True,
                            timeout=5,
                        )
                        output = (
                            "\n".join(
                                part
                                for part in (
                                    completed.stdout.strip(),
                                    completed.stderr.strip(),
                                )
                                if part
                            )
                            or "Ping 未返回输出"
                        )
                        if len(output) > MAX_PING_OUTPUT:
                            output = output[:MAX_PING_OUTPUT] + "\n[输出已被截断]"
                    except subprocess.TimeoutExpired:
                        error = "Ping 请求超时"
                        status_code = 504
                    except OSError:
                        error = "Ping 命令不可用"
                        status_code = 503

        return render_template(
            "ping.html",
            ip=target,
            output=output,
            error=error,
        ), status_code

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit(
        "5 per minute",
        key_func=login_rate_limit_key,
        methods=["POST"],
    )
    def login():
        if request.method == "GET":
            registered = request.args.get("registered")
            if registered == "success":
                return render_template("login.html", error="注册成功，请登录")
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not 1 <= len(username) <= 64 or not 1 <= len(password) <= 128:
            return render_template("login.html", error="用户名或密码错误"), 400

        dummy_hash = "scrypt:32768:8:1$v9rxyEKSqdscRuVv$f8ccc711c9f3046f159cc3d53c1190f6f9329b1dd20e104bea826174892f95176b69db4a881339d4965c1b0b1edb90747a18f45846c9b28811a20f03dd9d2a8c"
        json_match = False
        sqlite_match = False

        # 第一步：JSON 凭据（admin/alice）
        user = users.get(username)
        json_hash = user["password_hash"] if user else dummy_hash
        json_match = user is not None and check_password_hash(json_hash, password)
        if user is None:
            check_password_hash(json_hash, password)

        # 第二步：SQLite 凭据（注册用户）
        try:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password_hash FROM users WHERE username = ?",
                    (username,),
                )
                row = cursor.fetchone()
            sqlite_hash = row[0] if row and user is None else dummy_hash
            sqlite_candidate_match = check_password_hash(sqlite_hash, password)
            sqlite_match = user is None and row is not None and sqlite_candidate_match
        except sqlite3.Error:
            check_password_hash(dummy_hash, password)  # 异常时也归一化

        # 两个存储都检查完毕后，再判断登录结果
        # 每条路径都执行了恰好 2 次 check_password_hash，时序一致
        if json_match or sqlite_match:
            session.clear()
            session["username"] = username
            session["credential_version"] = credential_version_for(username)
            session.permanent = True
            app.logger.info("login_success username=%s", _safe_log_value(username))
            return redirect(url_for("index"))

        app.logger.warning(
            "login_failed remote_addr=%s username=%s",
            request.remote_addr,
            _safe_log_value(username),
        )
        return render_template("login.html", error="用户名或密码错误"), 401

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("10 per minute", key_func=get_remote_address, methods=["POST"])
    def register():
        """注册新用户"""
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()

            # 服务端输入校验
            if not 1 <= len(username) <= 64:
                return render_template(
                    "register.html", error="用户名长度须为 1-64 个字符"
                )
            if "/" in username or chr(92) in username:
                return render_template("register.html", error="用户名包含非法字符")
            if username in users:
                return render_template("register.html", error="用户名已存在")
            if not 6 <= len(password) <= 128:
                return render_template(
                    "register.html", error="密码长度须为 6-128 个字符"
                )
            if len(email) > 128:
                return render_template("register.html", error="邮箱地址过长")
            if len(phone) > 32:
                return render_template("register.html", error="手机号格式不正确")

            # 生成密码哈希
            password_hash = generate_password_hash(password, method="scrypt")

            try:
                with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO users (username, password_hash, email, phone) "
                        "VALUES (?, ?, ?, ?)",
                        (username, password_hash, email, phone),
                    )
                    conn.commit()
                app.logger.info(
                    "register_success username=%s", _safe_log_value(username)
                )
                return redirect(url_for("login", registered="success"))
            except sqlite3.IntegrityError:
                return render_template("register.html", error="用户名已存在")
            except sqlite3.Error as e:
                app.logger.error(
                    "register_error username=%s error=%s",
                    _safe_log_value(username),
                    e,
                )
                return render_template("register.html", error="注册失败，请稍后重试")

        return render_template("register.html")

    @app.route("/search")
    @limiter.limit("30 per minute", key_func=get_remote_address)
    def search():
        """搜索用户——需要登录"""
        username = session.get("username")
        if not username:
            return redirect(url_for("login"))

        keyword = request.args.get("keyword", "").strip()
        results = []

        if keyword:
            try:
                escaped_keyword = (
                    keyword.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                search_pattern = f"%{escaped_keyword}%"
                with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT id, username FROM users "
                        "WHERE username LIKE ? ESCAPE '\\' "
                        "OR email LIKE ? ESCAPE '\\' "
                        "ORDER BY username LIMIT 50",
                        (search_pattern, search_pattern),
                    )
                    rows = cursor.fetchall()
                for row in rows:
                    results.append(
                        {
                            "id": row[0],
                            "username": row[1],
                        }
                    )
                app.logger.info(
                    "search keyword=%s results=%d",
                    _safe_log_value(keyword),
                    len(results),
                )
            except sqlite3.Error as e:
                app.logger.error(
                    "search_error keyword=%s error=%s",
                    _safe_log_value(keyword),
                    e,
                )

        user = users.get(username) if username else None
        public_user = (
            {field: user[field] for field in PUBLIC_USER_FIELDS} if user else None
        )
        return render_template(
            "index.html",
            username=username,
            user=public_user,
            search_results=results,
            keyword=keyword,
            page_content=None,
            page_error=None,
        )

    @app.route("/upload", methods=["GET", "POST"])
    @limiter.limit("10 per minute", key_func=get_remote_address, methods=["POST"])
    def upload():
        """上传头像——需要登录，仅允许图片格式"""
        username = session.get("username")
        if not username:
            return redirect(url_for("login"))

        uploaded_url = None
        error = None

        if request.method == "POST":
            file = request.files.get("file")
            if not file or not file.filename:
                error = "请选择要上传的文件"
            else:
                original_filename = file.filename
                safe_name = secure_filename(original_filename)
                if not safe_name or "." not in safe_name:
                    error = "文件名不合法"
                else:
                    safe_ext = safe_name.rsplit(".", 1)[-1].lower()
                    if safe_ext not in ALLOWED_EXTENSIONS:
                        error = f"不支持的文件格式 (.{safe_ext})，仅允许图片文件"
                    else:
                        file.seek(0)
                        header = file.read(16)
                        file.seek(0)
                        magic_ok = _matches_image_signature(safe_ext, header)
                        if not magic_ok:
                            error = f"文件内容与扩展名不匹配，请上传真实{safe_ext.upper()}文件"
                        else:
                            name_part = safe_name.rsplit(".", 1)[0]
                            unique_name = (
                                f"{name_part}_{secrets.token_hex(16)}.{safe_ext}"
                            )
                            safe_username = (
                                secure_filename(username)
                                or f"user_{secrets.token_hex(16)}"
                            )
                            user_dir = os.path.join(
                                app.root_path, "static", "uploads", safe_username
                            )
                            os.makedirs(user_dir, exist_ok=True)
                            save_path = os.path.join(user_dir, unique_name)
                            file.seek(0, os.SEEK_END)
                            file_size = file.tell()
                            file.seek(0)
                            if file_size > MAX_FILE_SIZE:
                                error = f"文件过大（{file_size / 1024 / 1024:.1f}MB），最大允许 5MB"
                            else:
                                open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                open_flags |= getattr(os, "O_NOFOLLOW", 0)
                                try:
                                    descriptor = os.open(save_path, open_flags, 0o644)
                                except FileExistsError:
                                    error = "文件名冲突，请重试"
                                except OSError:
                                    error = "文件保存失败"
                                else:
                                    try:
                                        with os.fdopen(descriptor, "wb") as output_file:
                                            file.save(output_file)
                                    except OSError:
                                        try:
                                            os.unlink(save_path)
                                        except OSError:
                                            pass
                                        error = "文件保存失败"
                                    else:
                                        os.chmod(save_path, 0o644)
                                        uploaded_url = url_for(
                                            "static",
                                            filename=(
                                                f"uploads/{safe_username}/{unique_name}"
                                            ),
                                        )
                                        app.logger.info(
                                            "upload_success username=%s original=%s saved=%s size=%d",
                                            username,
                                            _safe_log_value(safe_name),
                                            unique_name,
                                            file_size,
                                        )

        return render_template("upload.html", uploaded_url=uploaded_url, error=error)

    # ════════════════════════════════════════
    #  个人中心 /profile
    # ════════════════════════════════════════

    @app.route("/profile")
    def profile():
        """个人中心——从 URL 参数获取 user_id，参数化查询"""
        if not session.get("username"):
            return redirect(url_for("login"))

        user_id = request.args.get("user_id", "").strip()
        error = None
        user_data = None

        if user_id:
            return redirect(url_for("profile"))

        # 未提供 user_id 时从 session 推断
        username = session.get("username")
        if username:
            # 检查 JSON 用户
            if username in users:
                for idx, (uname, u) in enumerate(users.items()):
                    if uname == username:
                        user_data = {
                            "id": idx,
                            "username": username,
                            "email": u.get("email", ""),
                            "phone": u.get("phone", ""),
                            "balance": u.get("balance", 0),
                        }
                        break
            else:
                # 检查 SQLite 用户
                try:
                    with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT id, username, email, phone, balance "
                            "FROM users WHERE username = ?",
                            (username,),
                        )
                        row = cursor.fetchone()
                    if row:
                        user_data = {
                            "id": row[0],
                            "username": row[1],
                            "email": row[2] or "",
                            "phone": row[3] or "",
                            "balance": row[4] if len(row) > 4 else 0,
                        }
                except sqlite3.Error as e:
                    app.logger.error("profile_lookup error=%s", e)

        if not user_data:
            error = "请先登录后查看个人中心"

        return render_template("profile.html", user=user_data, error=error)

    # ════════════════════════════════════════
    #  充值 /recharge
    # ════════════════════════════════════════

    @app.route("/recharge", methods=["POST"])
    @limiter.limit("10 per minute", key_func=get_remote_address, methods=["POST"])
    def recharge():
        """充值——需要登录"""
        if not session.get("username"):
            return redirect(url_for("login"))

        # 余额变更必须由已验证的支付回调完成，不能信任浏览器提交的金额或用户 ID。
        return render_template(
            "profile.html",
            user=None,
            error="直接充值功能未启用",
        ), 403

    # ════════════════════════════════════════
    #  动态页面加载 /page
    # ════════════════════════════════════════

    @app.route("/page")
    @limiter.limit("30 per minute", key_func=get_remote_address)
    def page():
        """动态页面加载——仅允许访问启动时加载的 pages/*.html 文件"""
        name = request.args.get("name", "")
        page_content = None
        error = None

        if name:
            # 日志用安全化后的文件名防注入
            safe_name = secure_filename(name)
            if not safe_name:
                error = "页面名称不合法"
            else:
                # 限制文件名长度
                if len(safe_name) > 100:
                    safe_name = safe_name[:100]
                # 只允许 .html 文件
                if not safe_name.endswith(".html"):
                    safe_name += ".html"
                page_content = static_pages.get(safe_name)
                if page_content is None:
                    error = "页面不存在"
                else:
                    app.logger.info(
                        "page_load success name=%s", _safe_log_value(safe_name)
                    )

        username = session.get("username")
        user = users.get(username) if username else None
        is_sqlite_user = False
        if username and user is None:
            try:
                with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT 1 FROM users WHERE username = ?", (username,)
                    )
                    is_sqlite_user = cursor.fetchone() is not None
            except sqlite3.Error:
                pass
        if username and user is None and not is_sqlite_user:
            session.clear()
            username = None
        elif is_sqlite_user:
            try:
                with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT email, phone, balance FROM users WHERE username = ?",
                        (username,),
                    )
                    row = cursor.fetchone()
                if row:
                    user = {
                        "username": username,
                        "email": row[0] or "",
                        "phone": row[1] or "",
                        "balance": row[2] or 0,
                    }
                else:
                    is_sqlite_user = False
            except sqlite3.Error:
                is_sqlite_user = False
        public_user = (
            {field: user[field] for field in PUBLIC_USER_FIELDS if field in user}
            if user
            else None
        )

        return render_template(
            "index.html",
            username=username,
            user=public_user,
            page_content=page_content,
            page_error=error,
            search_results=None,
            keyword="",
        )

    # ════════════════════════════════════════
    #  修改密码 /change-password
    # ════════════════════════════════════════

    @app.route("/change-password", methods=["POST"])
    @limiter.limit("5 per minute", key_func=get_remote_address, methods=["POST"])
    def change_password():
        """修改密码——需要登录、需要CSRF、仅限修改当前用户的密码"""
        if not session.get("username"):
            return redirect(url_for("login"))

        username = request.form.get("username", "").strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        current_user = session.get("username")

        # 仅允许修改当前登录用户的密码——防止越权
        if username != current_user:
            return redirect(url_for("profile"))

        if not 6 <= len(new_password) <= 128 or new_password != confirm_password:
            return redirect(url_for("profile"))

        # 更新 JSON 用户
        if username in users:
            if not check_password_hash(
                users[username]["password_hash"], current_password
            ):
                return redirect(url_for("profile"))
            new_password_hash = generate_password_hash(new_password, method="scrypt")
            try:
                update_password_hash(
                    app.config["USER_STORE_PATH"],
                    username,
                    new_password_hash,
                )
            except (OSError, RuntimeError) as error:
                app.logger.error(
                    "change_password_error username=%s error=%s",
                    _safe_log_value(username),
                    error,
                )
                return redirect(url_for("profile"))
            users[username]["password_hash"] = new_password_hash
            app.logger.info(
                "change_password_success username=%s (JSON)",
                _safe_log_value(username),
            )
            session.clear()
            return redirect(url_for("login"))

        # 更新 SQLite 用户
        try:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=5)) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password_hash FROM users WHERE username = ?",
                    (username,),
                )
                row = cursor.fetchone()
                if not row or not check_password_hash(row[0], current_password):
                    return redirect(url_for("profile"))
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    (generate_password_hash(new_password, method="scrypt"), username),
                )
                if cursor.rowcount > 0:
                    conn.commit()
                    app.logger.info(
                        "change_password_success username=%s (SQLite)",
                        _safe_log_value(username),
                    )
        except sqlite3.Error as e:
            app.logger.error(
                "change_password_error username=%s error=%s",
                _safe_log_value(username),
                e,
            )

        return redirect(url_for("profile"))

    # ════════════════════════════════════════
    #  外部页面加载 /fetch-page
    # ════════════════════════════════════════

    @app.route("/fetch-page")
    @limiter.limit("15 per minute", key_func=get_remote_address)
    def fetch_page():
        """外部页面加载——使用每跳IP校验防SSRF绕过"""
        if not session.get("username"):
            return redirect(url_for("login"))

        url = request.args.get("url", "")
        content = None
        error = None
        status_code = 200
        allowed_hosts = set(app.config["FETCH_ALLOWED_HOSTS"])

        def _resolve_public_addresses(hostname):
            try:
                addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
                if not addresses:
                    return ()
                resolved = []
                for info in addresses:
                    ip = ipaddress.ip_address(info[4][0])
                    if ip.version == 6 and ip.ipv4_mapped:
                        ip = ip.ipv4_mapped
                    if not ip.is_global:
                        return ()
                    canonical_ip = str(ip)
                    if canonical_ip not in resolved:
                        resolved.append(canonical_ip)
                return tuple(resolved)
            except (OSError, ValueError):
                return ()

        def _validate_fetch_url(candidate):
            parsed = urlparse(candidate)
            try:
                port = parsed.port
            except ValueError as error:
                raise ValueError("URL 端口无效") from error

            hostname = (parsed.hostname or "").rstrip(".").lower()
            if (
                parsed.scheme != "https"
                or not hostname
                or parsed.username
                or parsed.password
                or port not in (None, 443)
            ):
                raise ValueError("仅支持标准 HTTPS URL")
            if hostname not in allowed_hosts:
                raise PermissionError("目标主机未获允许")
            resolved_addresses = _resolve_public_addresses(hostname)
            if not resolved_addresses:
                raise PermissionError("不允许访问内网地址")
            return candidate, hostname, resolved_addresses

        if not allowed_hosts:
            error = "外部页面加载未配置允许的主机"
            status_code = 403
        elif url:
            try:
                current_url, hostname, resolved_addresses = _validate_fetch_url(url)
                for _ in range(5):
                    response = _fetch_https_once(
                        current_url,
                        hostname,
                        resolved_addresses[0],
                    )
                    if response.status_code in (301, 302, 303, 307, 308):
                        target = response.headers.get(
                            "location"
                        ) or response.headers.get("Location")
                        if not target:
                            break
                        current_url, hostname, resolved_addresses = _validate_fetch_url(
                            urljoin(current_url, target)
                        )
                        continue
                    if len(response.text.encode("utf-8")) > MAX_FETCH_BYTES:
                        raise FetchResponseTooLarge("响应内容过大")
                    content = response.text
                    break
                app.logger.info(
                    "fetch_page_success host=%s", urlparse(current_url).hostname
                )
            except PermissionError as request_error:
                error = str(request_error)
                status_code = 403
            except ValueError as request_error:
                error = str(request_error)
                status_code = 400
            except FetchResponseTooLarge as request_error:
                error = str(request_error)
                status_code = 502
            except (OSError, ssl.SSLError, http.client.HTTPException):
                error = "获取页面失败"
                status_code = 502

        return render_template(
            "index.html",
            username=session.get("username"),
            user=None,
            page_content=content,
            page_error=error,
            page_is_external=True,
            search_results=None,
            keyword="",
        ), status_code

    return app
