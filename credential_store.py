import json
import os
import tempfile
from pathlib import Path

from werkzeug.security import generate_password_hash


ACCOUNT_NAMES = ("admin", "alice")
DEFAULT_USER_STORE_PATH = Path(__file__).resolve().parent / "instance" / "users.json"
STORE_VERSION = 1


def _validate_initial_password(name, value):
    if not isinstance(value, str) or len(value) < 12:
        raise RuntimeError(f"{name} must contain at least 12 characters")
    if len(value) > 128:
        raise RuntimeError(f"{name} must contain at most 128 characters")


def initialize_password_store(path, admin_password, alice_password):
    _validate_initial_password("ADMIN_INITIAL_PASSWORD", admin_password)
    _validate_initial_password("ALICE_INITIAL_PASSWORD", alice_password)

    store_path = Path(path)
    store_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {
        "version": STORE_VERSION,
        "password_hashes": {
            "admin": generate_password_hash(admin_password, method="scrypt"),
            "alice": generate_password_hash(alice_password, method="scrypt"),
        },
    }

    try:
        descriptor = os.open(
            store_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError as error:
        raise RuntimeError(
            f"password store already exists: {store_path}; refusing to overwrite"
        ) from error

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as store_file:
            json.dump(payload, store_file, indent=2, sort_keys=True)
            store_file.write("\n")
            store_file.flush()
            os.fsync(store_file.fileno())
    except BaseException:
        store_path.unlink(missing_ok=True)
        raise

    return store_path


def load_password_hashes(path):
    store_path = Path(path)
    try:
        payload = json.loads(store_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RuntimeError(
            f"password store is missing: {store_path}; run init_users.py once"
        ) from error
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"password store cannot be read: {store_path}") from error

    if not isinstance(payload, dict) or set(payload) != {
        "version",
        "password_hashes",
    }:
        raise RuntimeError("password store has an invalid schema")
    if payload["version"] != STORE_VERSION:
        raise RuntimeError("password store version is unsupported")

    password_hashes = payload["password_hashes"]
    if not isinstance(password_hashes, dict) or set(password_hashes) != set(
        ACCOUNT_NAMES
    ):
        raise RuntimeError("password store must contain admin and alice hashes")
    if any(
        not isinstance(value, str) or not value.startswith("scrypt:")
        for value in password_hashes.values()
    ):
        raise RuntimeError("password store contains an invalid password hash")

    return password_hashes


def update_password_hash(path, username, password_hash):
    if username not in ACCOUNT_NAMES:
        raise RuntimeError("password store account is unsupported")
    if not isinstance(password_hash, str) or not password_hash.startswith("scrypt:"):
        raise RuntimeError("password hash is invalid")

    store_path = Path(path)
    password_hashes = load_password_hashes(store_path)
    payload = {
        "version": STORE_VERSION,
        "password_hashes": {**password_hashes, username: password_hash},
    }
    store_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{store_path.name}.",
        suffix=".tmp",
        dir=store_path.parent,
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as store_file:
            json.dump(payload, store_file, indent=2, sort_keys=True)
            store_file.write("\n")
            store_file.flush()
            os.fsync(store_file.fileno())
        os.replace(temporary_path, store_path)
        os.chmod(store_path, 0o600)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise
