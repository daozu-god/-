import io
import json
import os
import secrets
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
from werkzeug.security import check_password_hash, generate_password_hash

import app as app_module
import credential_store
import hunter_fetcher
from tests.test_security import (
    csrf_token,
    set_authenticated_session,
    valid_config,
    write_password_store,
)


class CrossStoreIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.store_path = Path(self.temp_dir.name) / "users.json"
        self.admin_password = secrets.token_urlsafe(24)
        self.alice_password = secrets.token_urlsafe(24)
        write_password_store(
            self.store_path,
            self.admin_password,
            self.alice_password,
        )
        self.app = app_module.create_app(valid_config(self.store_path))
        self.app.logger.disabled = True
        self.client = self.app.test_client()
        self.db_path = Path(
            getattr(app_module, "DATABASE_PATH", Path("data") / "users.db")
        )
        self._delete_registered_admin()
        self.addCleanup(self._delete_registered_admin)

    def _delete_registered_admin(self):
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("DELETE FROM users WHERE username = ?", ("admin",))
            connection.commit()

    def test_registration_rejects_builtin_account_name(self):
        token = csrf_token(self.client, "/register")

        response = self.client.post(
            "/register",
            data={
                "username": "admin",
                "password": "attacker-password-123",
                "email": "",
                "phone": "",
                "csrf_token": token,
            },
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("用户名已存在", response.get_data(as_text=True))
        with closing(sqlite3.connect(self.db_path)) as connection:
            row = connection.execute(
                "SELECT 1 FROM users WHERE username = ?", ("admin",)
            ).fetchone()
        self.assertIsNone(row)

    def test_builtin_login_ignores_conflicting_sqlite_credential(self):
        collision_password = "attacker-password-123"
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, email, phone) "
                "VALUES (?, ?, ?, ?)",
                (
                    "admin",
                    generate_password_hash(collision_password, method="scrypt"),
                    "",
                    "",
                ),
            )
            connection.commit()
        token = csrf_token(self.client)

        response = self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": collision_password,
                "csrf_token": token,
            },
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 401)

    def test_database_initialization_removes_builtin_name_collisions(self):
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, email, phone) "
                "VALUES (?, ?, ?, ?)",
                (
                    "admin",
                    generate_password_hash(
                        "attacker-password-123",
                        method="scrypt",
                    ),
                    "",
                    "",
                ),
            )
            connection.commit()

        app_module.init_db()

        with closing(sqlite3.connect(self.db_path)) as connection:
            row = connection.execute(
                "SELECT 1 FROM users WHERE username = ?", ("admin",)
            ).fetchone()
        self.assertIsNone(row)


class CredentialPersistenceTests(unittest.TestCase):
    def test_builtin_password_change_survives_app_restart(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "users.json"
            old_password = secrets.token_urlsafe(24)
            new_password = secrets.token_urlsafe(24)
            write_password_store(store_path, secrets.token_urlsafe(24), old_password)
            config = valid_config(store_path)
            app = app_module.create_app(config)
            app.logger.disabled = True
            client = app.test_client()
            set_authenticated_session(app, client, "alice")
            token = csrf_token(client, "/profile")

            response = client.post(
                "/change-password",
                data={
                    "username": "alice",
                    "current_password": old_password,
                    "new_password": new_password,
                    "confirm_password": new_password,
                    "csrf_token": token,
                },
                base_url="https://localhost",
            )

            self.assertEqual(response.status_code, 302)
            restarted = app_module.create_app(config)
            persisted_hash = restarted.extensions["users"]["alice"]["password_hash"]
            self.assertTrue(check_password_hash(persisted_hash, new_password))
            self.assertFalse(check_password_hash(persisted_hash, old_password))

    def test_preexisting_app_instance_rejects_old_builtin_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "users.json"
            old_password = secrets.token_urlsafe(24)
            new_password = secrets.token_urlsafe(24)
            write_password_store(store_path, secrets.token_urlsafe(24), old_password)
            config = valid_config(store_path)
            first_app = app_module.create_app(config)
            second_app = app_module.create_app(config)
            first_app.logger.disabled = True
            second_app.logger.disabled = True
            first_client = first_app.test_client()
            second_client = second_app.test_client()
            set_authenticated_session(first_app, first_client, "alice")
            token = csrf_token(first_client, "/profile")

            first_client.post(
                "/change-password",
                data={
                    "username": "alice",
                    "current_password": old_password,
                    "new_password": new_password,
                    "confirm_password": new_password,
                    "csrf_token": token,
                },
                base_url="https://localhost",
            )

            login_token = csrf_token(second_client)
            old_login = second_client.post(
                "/login",
                data={
                    "username": "alice",
                    "password": old_password,
                    "csrf_token": login_token,
                },
                base_url="https://localhost",
            )

        self.assertEqual(old_login.status_code, 401)

    def test_concurrent_builtin_password_updates_preserve_both_changes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "users.json"
            credential_store.initialize_password_store(
                store_path,
                "InitialAdminPassword!",
                "InitialAlicePassword!",
            )
            original_load = credential_store.load_password_hashes
            start = threading.Barrier(2)
            errors = []
            admin_hash = generate_password_hash(
                "UpdatedAdminPassword!", method="scrypt"
            )
            alice_hash = generate_password_hash(
                "UpdatedAlicePassword!", method="scrypt"
            )

            def slow_load(path):
                password_hashes = original_load(path)
                time.sleep(0.1)
                return password_hashes

            def update(username, password_hash):
                try:
                    start.wait(timeout=5)
                    credential_store.update_password_hash(
                        store_path, username, password_hash
                    )
                except BaseException as error:
                    errors.append(error)

            with patch("credential_store.load_password_hashes", slow_load):
                threads = (
                    threading.Thread(target=update, args=("admin", admin_hash)),
                    threading.Thread(target=update, args=("alice", alice_hash)),
                )
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=10)

            final_hashes = original_load(store_path)

        self.assertEqual(errors, [])
        self.assertEqual(final_hashes["admin"], admin_hash)
        self.assertEqual(final_hashes["alice"], alice_hash)


class SessionInvalidationTests(unittest.TestCase):
    def test_password_change_invalidates_other_authenticated_sessions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "users.json"
            admin_password = secrets.token_urlsafe(24)
            alice_password = secrets.token_urlsafe(24)
            write_password_store(store_path, admin_password, alice_password)
            app = app_module.create_app(valid_config(store_path))
            app.logger.disabled = True
            first_client = app.test_client()
            second_client = app.test_client()

            for client in (first_client, second_client):
                token = csrf_token(client, "/login")
                response = client.post(
                    "/login",
                    data={
                        "username": "alice",
                        "password": alice_password,
                        "csrf_token": token,
                    },
                    base_url="https://localhost",
                )
                self.assertEqual(response.status_code, 302)

            token = csrf_token(first_client, "/profile")
            response = first_client.post(
                "/change-password",
                data={
                    "username": "alice",
                    "current_password": alice_password,
                    "new_password": "replacement-password-2026",
                    "confirm_password": "replacement-password-2026",
                    "csrf_token": token,
                },
                base_url="https://localhost",
            )
            self.assertEqual(response.status_code, 302)

            stale_response = second_client.get(
                "/profile",
                base_url="https://localhost",
            )

        self.assertEqual(stale_response.status_code, 302)
        self.assertIn("/login", stale_response.location)


class BoundaryHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.store_path = Path(self.temp_dir.name) / "users.json"
        write_password_store(
            self.store_path,
            secrets.token_urlsafe(24),
            secrets.token_urlsafe(24),
        )
        self.app = app_module.create_app(valid_config(self.store_path))
        self.app.logger.disabled = True
        self.client = self.app.test_client()

    def login_as(self, username="alice"):
        set_authenticated_session(self.app, self.client, username)

    def test_search_log_value_cannot_inject_new_record(self):
        self.login_as()
        with patch.object(self.app.logger, "info") as log_info:
            response = self.client.get(
                "/search?keyword=alice%0aFORGED_LOG_ENTRY",
                base_url="https://localhost",
            )

        self.assertEqual(response.status_code, 200)
        search_call = next(
            call
            for call in log_info.call_args_list
            if call.args[0].startswith("search ")
        )
        self.assertNotIn("\n", search_call.args[1])
        self.assertNotIn("\r", search_call.args[1])

    def test_search_treats_sql_wildcards_as_literal_text(self):
        self.login_as()
        usernames = ("wildcard_probe_one", "wildcard_probe_two")
        with closing(sqlite3.connect(app_module.DATABASE_PATH)) as connection:
            connection.executemany(
                "INSERT OR REPLACE INTO users "
                "(username, password_hash, email, phone) VALUES (?, ?, ?, ?)",
                [
                    (
                        username,
                        generate_password_hash("unused-password", method="scrypt"),
                        "",
                        "",
                    )
                    for username in usernames
                ],
            )
            connection.commit()
        self.addCleanup(self._delete_users, usernames)

        response = self.client.get(
            "/search?keyword=%25",
            base_url="https://localhost",
        )
        text = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        for username in usernames:
            self.assertNotIn(username, text)

    @staticmethod
    def _delete_users(usernames):
        with closing(sqlite3.connect(app_module.DATABASE_PATH)) as connection:
            connection.executemany(
                "DELETE FROM users WHERE username = ?",
                [(username,) for username in usernames],
            )
            connection.commit()

    def test_login_closes_database_when_query_fails(self):
        token = csrf_token(self.client)
        connection = Mock()
        cursor = connection.cursor.return_value
        cursor.execute.side_effect = sqlite3.Error("simulated query failure")

        with patch("app.sqlite3.connect", return_value=connection):
            response = self.client.post(
                "/login",
                data={
                    "username": "unknown-user",
                    "password": "unknown-password",
                    "csrf_token": token,
                },
                base_url="https://localhost",
            )

        self.assertEqual(response.status_code, 401)
        connection.close.assert_called_once()

    def test_help_page_does_not_open_request_selected_file(self):
        with patch(
            "app.open",
            create=True,
            side_effect=AssertionError("request-time file access"),
        ):
            response = self.client.get(
                "/page?name=help",
                base_url="https://localhost",
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("帮助中心", response.get_data(as_text=True))

    def test_fetch_page_connects_to_the_validated_ip(self):
        config = valid_config(self.store_path)
        config["FETCH_ALLOWED_HOSTS"] = ("example.com",)
        app = app_module.create_app(config)
        app.logger.disabled = True
        client = app.test_client()
        set_authenticated_session(app, client, "alice")
        pinned_response = SimpleNamespace(status_code=200, headers={}, text="safe")
        legacy_response = Mock(status_code=200, headers={}, text="legacy")
        with (
            patch(
                "app.socket.getaddrinfo",
                return_value=[
                    (
                        app_module.socket.AF_INET,
                        app_module.socket.SOCK_STREAM,
                        6,
                        "",
                        ("93.184.216.34", 443),
                    )
                ],
            ),
            patch(
                "app._fetch_https_once",
                create=True,
                return_value=pinned_response,
            ) as pinned_fetch,
            patch(
                "requests.sessions.Session.get",
                return_value=legacy_response,
            ) as legacy_fetch,
        ):
            response = client.get(
                "/fetch-page?url=https://example.com/",
                base_url="https://localhost",
            )

        self.assertEqual(response.status_code, 200)
        pinned_fetch.assert_called_once_with(
            "https://example.com/",
            "example.com",
            "93.184.216.34",
        )
        legacy_fetch.assert_not_called()

    def test_fetch_page_rejects_oversized_response(self):
        config = valid_config(self.store_path)
        config["FETCH_ALLOWED_HOSTS"] = ("example.com",)
        app = app_module.create_app(config)
        app.logger.disabled = True
        client = app.test_client()
        set_authenticated_session(app, client, "alice")
        oversized = "x" * (getattr(app_module, "MAX_FETCH_BYTES", 256 * 1024) + 1)
        response_mock = SimpleNamespace(status_code=200, headers={}, text=oversized)
        with (
            patch(
                "app.socket.getaddrinfo",
                return_value=[
                    (
                        app_module.socket.AF_INET,
                        app_module.socket.SOCK_STREAM,
                        6,
                        "",
                        ("93.184.216.34", 443),
                    )
                ],
            ),
            patch(
                "app._fetch_https_once",
                create=True,
                return_value=response_mock,
            ),
            patch(
                "requests.sessions.Session.get",
                return_value=response_mock,
            ),
        ):
            response = client.get(
                "/fetch-page?url=https://example.com/",
                base_url="https://localhost",
            )

        self.assertEqual(response.status_code, 502)
        self.assertIn("响应内容过大", response.get_data(as_text=True))

    @patch("app.platform.system", return_value="Linux")
    @patch("app.subprocess.run")
    def test_ping_uses_configured_absolute_executable(self, run, _platform):
        config = valid_config(self.store_path)
        config["PING_EXECUTABLE"] = "/usr/bin/ping"
        app = app_module.create_app(config)
        app.logger.disabled = True
        client = app.test_client()
        set_authenticated_session(app, client, "alice")
        run.return_value = Mock(returncode=0, stdout="ok", stderr="")
        token = csrf_token(client, "/ping")

        response = client.post(
            "/ping",
            data={"ip": "8.8.8.8", "csrf_token": token},
            base_url="https://localhost",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/ping")


class LocalDataPrivacyTests(unittest.TestCase):
    def test_database_path_is_anchored_and_created_privately(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "private-data" / "users.db"
            with patch.object(app_module, "DATABASE_PATH", database_path, create=True):
                app_module.init_db()

            self.assertTrue(database_path.is_file())
            if os.name == "posix":
                self.assertEqual(
                    stat.S_IMODE(database_path.parent.stat().st_mode),
                    0o700,
                )
                self.assertEqual(stat.S_IMODE(database_path.stat().st_mode), 0o600)


class HunterFetcherSecurityTests(unittest.TestCase):
    def test_request_failure_does_not_reveal_api_key(self):
        sensitive_key = "SENSITIVE-HUNTER-KEY"
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = str(Path(temp_dir) / "state.json")
            with (
                patch.object(hunter_fetcher, "STATE_FILE", state_path),
                patch(
                    "hunter_fetcher._request_hunter",
                    create=True,
                    side_effect=requests.RequestException(
                        "request failed for https://example.invalid/?api-key="
                        + sensitive_key
                    ),
                ),
                patch(
                    "hunter_fetcher.requests.get",
                    side_effect=requests.RequestException(
                        "request failed for https://example.invalid/?api-key="
                        + sensitive_key
                    ),
                ),
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    result = hunter_fetcher.HunterFetcher(sensitive_key).search(
                        "domain=example.com"
                    )

        combined = output.getvalue() + json.dumps(result, ensure_ascii=False)
        self.assertNotIn(sensitive_key, combined)

    def test_csv_export_neutralizes_spreadsheet_formulas(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "results.csv"
            with patch.object(
                hunter_fetcher,
                "STATE_FILE",
                str(Path(temp_dir) / "state.json"),
            ):
                fetcher = hunter_fetcher.HunterFetcher("unused")
                with redirect_stdout(io.StringIO()):
                    fetcher.export_csv(
                        [{"host": '=HYPERLINK("https://example.invalid","open")'}],
                        str(output_path),
                    )

            exported = output_path.read_text(encoding="utf-8-sig")

        self.assertIn("'=HYPERLINK", exported)
        self.assertNotIn('\n"=HYPERLINK', exported)

    def test_exports_are_forced_to_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "results.json"
            csv_path = Path(temp_dir) / "results.csv"
            fetcher = hunter_fetcher.HunterFetcher("unused")
            with (
                patch("hunter_fetcher.os.chmod", wraps=os.chmod) as chmod,
                redirect_stdout(io.StringIO()),
            ):
                fetcher.export_json([{"host": "example.invalid"}], str(json_path))
                fetcher.export_csv([{"host": "example.invalid"}], str(csv_path))

        private_destinations = {
            Path(call.args[0])
            for call in chmod.call_args_list
            if len(call.args) == 2 and call.args[1] == 0o600
        }
        self.assertIn(json_path, private_destinations)
        self.assertIn(csv_path, private_destinations)

    def test_concurrent_searches_preserve_quota_and_history(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.json"
            start = threading.Barrier(2)
            errors = []

            def fake_request(*_args, **_kwargs):
                time.sleep(0.1)
                response = Mock()
                response.raise_for_status.return_value = None
                response.json.return_value = {
                    "code": 200,
                    "data": {"arr": [{"host": index} for index in range(10)]},
                }
                return response

            def search(fetcher):
                try:
                    start.wait(timeout=5)
                    with redirect_stdout(io.StringIO()):
                        fetcher.search("domain=example.invalid")
                except BaseException as error:
                    errors.append(error)

            with (
                patch.object(hunter_fetcher, "STATE_FILE", str(state_path)),
                patch("hunter_fetcher._request_hunter", side_effect=fake_request),
            ):
                fetchers = (
                    hunter_fetcher.HunterFetcher("unused"),
                    hunter_fetcher.HunterFetcher("unused"),
                )
                threads = tuple(
                    threading.Thread(target=search, args=(fetcher,))
                    for fetcher in fetchers
                )
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=10)

            state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(errors, [])
        self.assertEqual(state["used_quota"], 20)
        self.assertEqual(len(state["search_history"]), 2)

    def test_api_key_options_do_not_accept_command_line_secrets(self):
        with patch.object(
            __import__("sys"),
            "argv",
            ["hunter_fetcher.py", "--key", "secret-value", "--search", "test"],
        ):
            with self.assertRaises(SystemExit):
                hunter_fetcher.parse_args()

        with patch.object(
            __import__("sys"),
            "argv",
            ["hunter_fetcher.py", "--key", "--search", "test"],
        ):
            args = hunter_fetcher.parse_args()

        self.assertTrue(args.key)


if __name__ == "__main__":
    unittest.main()
