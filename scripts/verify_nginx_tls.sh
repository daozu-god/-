#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
BACKEND_PID=""
NGINX_PID=""

cleanup() {
    if [[ -n "$NGINX_PID" ]]; then
        kill "$NGINX_PID" 2>/dev/null || true
    fi
    if [[ -n "$BACKEND_PID" ]]; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

HTTP_PORT="$(free_port)"
HTTPS_PORT="$(free_port)"
BACKEND_PORT="$(free_port)"

if command -v nginx >/dev/null 2>&1; then
    NGINX_BIN="$(command -v nginx)"
else
    mkdir -p "$TMP_DIR/packages" "$TMP_DIR/nginx-root"
    (
        cd "$TMP_DIR/packages"
        apt-get download nginx nginx-common >/dev/null
        for package in ./*.deb; do
            dpkg-deb -x "$package" "$TMP_DIR/nginx-root"
        done
    )
    NGINX_BIN="$TMP_DIR/nginx-root/usr/sbin/nginx"
fi

CERT_PATH="$TMP_DIR/cert.pem"
KEY_PATH="$TMP_DIR/key.pem"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj "/CN=class01.local" \
    -addext "subjectAltName=DNS:class01.local" \
    -keyout "$KEY_PATH" -out "$CERT_PATH" >/dev/null 2>&1

sed \
    -e "s@listen 80;@listen 127.0.0.1:${HTTP_PORT};@" \
    -e "s@listen 443 ssl;@listen 127.0.0.1:${HTTPS_PORT} ssl;@" \
    -e "s@class01.example.com@class01.local@g" \
    -e "s@ssl_certificate .*;@ssl_certificate ${CERT_PATH};@" \
    -e "s@ssl_certificate_key .*;@ssl_certificate_key ${KEY_PATH};@" \
    -e "s@proxy_pass http://127.0.0.1:5000;@proxy_pass http://127.0.0.1:${BACKEND_PORT};@" \
    "$ROOT_DIR/deploy/nginx/class01.conf.example" >"$TMP_DIR/server.conf"

mkdir -p \
    "$TMP_DIR/client_temp" \
    "$TMP_DIR/proxy_temp" \
    "$TMP_DIR/fastcgi_temp" \
    "$TMP_DIR/uwsgi_temp" \
    "$TMP_DIR/scgi_temp"

{
    echo "daemon off;"
    echo "pid $TMP_DIR/nginx.pid;"
    echo "error_log $TMP_DIR/error.log info;"
    echo "events {}"
    echo "http {"
    echo "    access_log $TMP_DIR/access.log;"
    echo "    client_body_temp_path $TMP_DIR/client_temp;"
    echo "    proxy_temp_path $TMP_DIR/proxy_temp;"
    echo "    fastcgi_temp_path $TMP_DIR/fastcgi_temp;"
    echo "    uwsgi_temp_path $TMP_DIR/uwsgi_temp;"
    echo "    scgi_temp_path $TMP_DIR/scgi_temp;"
    cat "$TMP_DIR/server.conf"
    echo "}"
} >"$TMP_DIR/nginx.conf"

cat >"$TMP_DIR/backend.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            "class01-nginx-tls-ok\n"
            f"forwarded-proto={self.headers.get('X-Forwarded-Proto')}\n"
            f"forwarded-host={self.headers.get('X-Forwarded-Host')}\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


HTTPServer(("127.0.0.1", int(__import__("sys").argv[1])), Handler).serve_forever()
PY

python3 "$TMP_DIR/backend.py" "$BACKEND_PORT" &
BACKEND_PID=$!

"$NGINX_BIN" -t -p "$TMP_DIR/" -c "$TMP_DIR/nginx.conf" >/dev/null
"$NGINX_BIN" -p "$TMP_DIR/" -c "$TMP_DIR/nginx.conf" &
NGINX_PID=$!

for _ in {1..50}; do
    if curl --silent --show-error --noproxy '*' \
        --resolve "class01.local:${HTTPS_PORT}:127.0.0.1" \
        --cacert "$CERT_PATH" \
        "https://class01.local:${HTTPS_PORT}/" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

HTTP_STATUS="$(curl --silent --show-error --noproxy '*' \
    --resolve "class01.local:${HTTP_PORT}:127.0.0.1" \
    --output /dev/null --write-out '%{http_code}' \
    "http://class01.local:${HTTP_PORT}/")"
HTTP_LOCATION="$(curl --silent --show-error --noproxy '*' \
    --resolve "class01.local:${HTTP_PORT}:127.0.0.1" \
    --output /dev/null --write-out '%{redirect_url}' \
    "http://class01.local:${HTTP_PORT}/")"
HTTPS_BODY="$(curl --silent --show-error --noproxy '*' \
    --resolve "class01.local:${HTTPS_PORT}:127.0.0.1" \
    --cacert "$CERT_PATH" \
    "https://class01.local:${HTTPS_PORT}/")"
HTTPS_STATUS="$(curl --silent --show-error --noproxy '*' \
    --resolve "class01.local:${HTTPS_PORT}:127.0.0.1" \
    --cacert "$CERT_PATH" \
    --output /dev/null --write-out '%{http_code}' \
    "https://class01.local:${HTTPS_PORT}/")"
TLS12_PROTOCOL="$(printf '' | openssl s_client \
    -connect "127.0.0.1:${HTTPS_PORT}" -servername class01.local \
    -tls1_2 -brief 2>&1 | awk -F': ' '/Protocol version/{print $2; exit}')"
TLS13_PROTOCOL="$(printf '' | openssl s_client \
    -connect "127.0.0.1:${HTTPS_PORT}" -servername class01.local \
    -tls1_3 -brief 2>&1 | awk -F': ' '/Protocol version/{print $2; exit}')"

[[ "$HTTP_STATUS" == "308" ]]
[[ "$HTTP_LOCATION" == https://class01.local/* ]]
[[ "$HTTPS_STATUS" == "200" ]]
grep -q '^class01-nginx-tls-ok$' <<<"$HTTPS_BODY"
grep -q '^forwarded-proto=https$' <<<"$HTTPS_BODY"
grep -q '^forwarded-host=class01.local$' <<<"$HTTPS_BODY"
[[ "$TLS12_PROTOCOL" == "TLSv1.2" ]]
[[ "$TLS13_PROTOCOL" == "TLSv1.3" ]]

echo "NGINX_VERSION=$($NGINX_BIN -v 2>&1)"
echo "NGINX_CONFIG_TEST=PASS"
echo "HTTP_STATUS=$HTTP_STATUS"
echo "HTTP_LOCATION=$HTTP_LOCATION"
echo "HTTPS_STATUS=$HTTPS_STATUS"
echo "HTTPS_BODY_MARKER=class01-nginx-tls-ok"
echo "FORWARDED_PROTO=https"
echo "FORWARDED_HOST=class01.local"
echo "TLS12_PROTOCOL=$TLS12_PROTOCOL"
echo "TLS13_PROTOCOL=$TLS13_PROTOCOL"
