import os
import sys

from credential_store import DEFAULT_USER_STORE_PATH, initialize_password_store


def main():
    store_path = os.getenv("USER_STORE_PATH", str(DEFAULT_USER_STORE_PATH))
    admin_password = os.environ.pop("ADMIN_INITIAL_PASSWORD", None)
    alice_password = os.environ.pop("ALICE_INITIAL_PASSWORD", None)

    try:
        initialized_path = initialize_password_store(
            store_path,
            admin_password,
            alice_password,
        )
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1

    print(f"Password hashes initialized at {initialized_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
