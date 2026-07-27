import json
import os
import stat
from pathlib import Path

from werkzeug.security import generate_password_hash

from secure_files import atomic_private_text_writer, exclusive_file_lock


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
    if store_path.parent.is_symlink():
        raise RuntimeError("password store directory must not be a symbolic link")
    os.chmod(store_path.parent, 0o700)
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
    if store_path.is_symlink():
        raise RuntimeError("password store must not be a symbolic link")
    try:
        store_stat = store_path.stat()
        if os.name == "posix":
            if store_stat.st_uid != os.geteuid():
                raise RuntimeError("password store must be owned by the service user")
            if stat.S_IMODE(store_stat.st_mode) & 0o077:
                raise RuntimeError("password store permissions must be 0600")
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
    lock_path = store_path.with_name(f".{store_path.name}.lock")
    with exclusive_file_lock(lock_path):
        password_hashes = load_password_hashes(store_path)
        payload = {
            "version": STORE_VERSION,
            "password_hashes": {**password_hashes, username: password_hash},
        }
        with atomic_private_text_writer(store_path) as store_file:
            json.dump(payload, store_file, indent=2, sort_keys=True)
            store_file.write("\n")
