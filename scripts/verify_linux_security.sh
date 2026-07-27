#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
WORK_DIR="$TMP_DIR/repo"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR"
git -C "$ROOT_DIR" ls-files -co --exclude-standard -z \
    | tar -C "$ROOT_DIR" --null --files-from=- -cf - \
    | tar -C "$WORK_DIR" -xf -

python3 -m venv "$TMP_DIR/venv"
"$TMP_DIR/venv/bin/pip" install --quiet --requirement "$WORK_DIR/requirements.txt"

ADMIN_INITIAL_PASSWORD="$($TMP_DIR/venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(24))')"
ALICE_INITIAL_PASSWORD="$($TMP_DIR/venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(24))')"
export ADMIN_INITIAL_PASSWORD ALICE_INITIAL_PASSWORD
export USER_STORE_PATH="$TMP_DIR/users.json"

cd "$WORK_DIR"
"$TMP_DIR/venv/bin/python" init_users.py >/dev/null

STORE_MODE="$(stat -c '%a' "$USER_STORE_PATH")"
echo "CREDENTIAL_STORE_MODE=$STORE_MODE"
[[ "$STORE_MODE" == "600" ]]
if grep -Fq "$ADMIN_INITIAL_PASSWORD" "$USER_STORE_PATH" || \
    grep -Fq "$ALICE_INITIAL_PASSWORD" "$USER_STORE_PATH"; then
    echo "plaintext initial password found in credential store" >&2
    exit 1
fi

unset ADMIN_INITIAL_PASSWORD ALICE_INITIAL_PASSWORD

echo "CREDENTIAL_STORE_PLAINTEXT_MATCHES=0"
"$TMP_DIR/venv/bin/python" -m unittest discover -s tests -v
