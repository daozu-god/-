# 用户信息管理平台

这是一个使用 Flask 编写的简易登录和用户信息展示服务。运行期从环境读取会话密钥，从本地凭据文件读取账户密码哈希，不读取账户明文密码。

## 运行环境

- Linux
- Python 3.10 或更高版本
- 项目目录 `/opt/Class01`
- Nginx HTTPS 反向代理

Gunicorn 默认只监听 `127.0.0.1:5000`，不能直接映射到公网。

## 安装

```bash
cd /opt/Class01
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

建议使用独立的低权限系统账户运行服务，并确保该账户不能修改应用源码。

## 配置运行密钥

生成随机会话密钥：

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

复制环境文件并分别填入生成结果：

```bash
umask 077
cp .env.example .env
chmod 600 .env
```

`.env` 必须包含：

```dotenv
APP_SECRET_KEY=上一步生成的随机值
APP_ENV=production
USER_STORE_PATH=/opt/Class01/instance/users.json
APP_TRUSTED_HOSTS=实际访问域名
RATELIMIT_STORAGE_URI=memory://
FETCH_ALLOWED_HOSTS=example.com
```

不要把 `.env` 提交到 Git，也不要在不同环境复用会话密钥。应用会拒绝空值和少于 32 个字符的密钥。
`APP_ENV=production` 会启用 HTTPS 安全 Cookie 与严格 CSRF 校验；应用在未配置该变量时也默认采用生产安全设置。仅在明确的本地 HTTP 开发环境中使用 `APP_ENV=development`。

`FETCH_ALLOWED_HOSTS` 是可选的、以逗号分隔的 HTTPS 主机白名单。未配置时，`/fetch-page` 默认拒绝所有外部页面抓取；配置的主机仍必须解析为全局公网地址。

## 一次性初始化账户密码

账户初始密码只传给初始化命令，不写入 `.env`。命令会创建权限为 `0600` 的 `instance/users.json`，文件中只保存两个 scrypt 哈希，并拒绝覆盖已经存在的文件。

```bash
cd /opt/Class01
set -a
. ./.env
set +a
read -rsp "Admin initial password: " ADMIN_INITIAL_PASSWORD
echo
read -rsp "Alice initial password: " ALICE_INITIAL_PASSWORD
echo
export ADMIN_INITIAL_PASSWORD ALICE_INITIAL_PASSWORD
.venv/bin/python init_users.py
unset ADMIN_INITIAL_PASSWORD ALICE_INITIAL_PASSWORD
```

两个密码必须为 12 至 128 个字符。初始化完成后，应用重启只需要 `.env` 中的会话密钥和 `USER_STORE_PATH`，不再需要账户明文密码。

## 启动

```bash
cd /opt/Class01
set -a
. ./.env
set +a
.venv/bin/gunicorn -c gunicorn.conf.py wsgi:app
```

如果继续使用默认的内存限速存储，Gunicorn 必须保持单 worker。

## HTTPS 反向代理结构

仓库中的 `deploy/nginx/class01.conf.example` 定义了下面这条链路：

```text
浏览器 --HTTPS/TLS 1.2 或 1.3--> Nginx :443
                                      |
                                      | HTTP，仅主机回环接口
                                      v
                              Gunicorn 127.0.0.1:5000
```

配置中的 80 端口只执行 308 HTTPS 跳转，443 端口加载证书和私钥，并把请求转发到 Gunicorn。`X-Forwarded-For`、`X-Forwarded-Host` 和 `X-Forwarded-Proto` 会传给 Flask；应用的 `ProxyFix` 配置与单层 Nginx 代理对应。

将示例域名和证书路径替换为实际值后安装配置：

```bash
sed 's/class01\.example\.com/实际域名/g' \
  deploy/nginx/class01.conf.example \
  | sudo tee /etc/nginx/conf.d/class01.conf >/dev/null
sudo nginx -t
sudo systemctl reload nginx
```

## 验证

```bash
python -m unittest discover -s tests -v
uvx ruff check .
uvx ruff format --check .
```

完整安全检查还包括：

```bash
uvx --from bandit bandit -r app.py credential_store.py init_users.py wsgi.py gunicorn.conf.py
uvx --from pip-audit pip-audit -r requirements.txt
```

在 Linux 或 WSL 中可执行动态 Nginx/TLS 与 `0600` 权限复测：

```bash
bash scripts/verify_nginx_tls.sh
bash scripts/verify_linux_security.sh
```

## 目录说明

```text
app.py                 Flask 应用工厂、路由和安全配置
credential_store.py    密码哈希文件初始化与读取
init_users.py          一次性账户密码初始化命令
wsgi.py                Gunicorn 应用入口
gunicorn.conf.py       回环监听和单 worker 配置
deploy/nginx/          HTTPS 终止和回环反向代理配置
scripts/               Nginx/TLS 与 Linux 权限动态复测脚本
templates/             Jinja 页面模板
static/css/            页面样式
tests/                 安全回归测试
requirements.txt       固定的直接依赖
.env.example           运行期环境变量模板，不含账户密码
```
