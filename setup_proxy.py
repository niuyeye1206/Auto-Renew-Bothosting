#!/usr/bin/env python3
"""Set up a local sing-box proxy from NODE_LINK (hy2/vless/trojan/vmess).

Replacement for the remote setup_proxy.sh. Pins sing-box to a fixed
version so a flaky GitHub API 'latest' lookup can never break the proxy
step again (2026-11-17: the API returned a string instead of a release
object, jq died with exit 5, and continue-on-error let the renewal run
direct from a datacenter IP, where the site silently ignored it).

Fails loudly (non-zero exit) on any error, so the workflow never silently
runs the renewal without a proxy.

Writes IS_PROXY=true and PROXY_SERVER=http://127.0.0.1:1080 to
$GITHUB_ENV for the following steps. app.py reads both.
"""
import base64
import json
import os
import socket
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

SINGBOX_VERSION = "1.14.4"
SINGBOX_URL = (
    "https://github.com/SagerNet/sing-box/releases/download/"
    f"v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz"
)
LISTEN_PORT = 1080
CONFIG_PATH = "sing-box-config.json"
LOG_PATH = "sing-box.log"
BIN_PATH = "./sing-box"


def fail(msg):
    print(f"❌ {msg}", file=sys.stderr)
    sys.exit(1)


def parse_query(link):
    return {k: v[0] for k, v in urllib.parse.parse_qs(
        urllib.parse.urlparse(link).query).items()}


def tls_block(q, default_sni=None):
    tls = {"enabled": True}
    sni = q.get("sni") or default_sni
    if sni:
        tls["server_name"] = sni
    if q.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}
    if q.get("alpn"):
        tls["alpn"] = q["alpn"].split(",")
    if q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"):
        tls["insecure"] = True
    return tls


def transport_block(q):
    t = (q.get("type") or "tcp").lower()
    if t == "ws":
        tr = {"type": "ws", "path": q.get("path", "/")}
        if q.get("host"):
            tr["headers"] = {"Host": q["host"]}
        if q.get("ed"):
            try:
                tr["max_early_data"] = int(q["ed"])
                tr["early_data_header_name"] = "Sec-WebSocket-Protocol"
            except ValueError:
                pass
        return tr
    if t == "grpc":
        tr = {"type": "grpc", "service_name": q.get("serviceName", "")}
        return tr
    if t in ("http", "httpupgrade"):
        tr = {"type": "httpupgrade", "path": q.get("path", "/")}
        if q.get("host"):
            tr["host"] = q["host"]
        return tr
    return None


def parse_hy2(link):
    u = urllib.parse.urlparse(link)
    q = parse_query(link)
    tls = {"enabled": True}
    if q.get("sni"):
        tls["server_name"] = q["sni"]
    if q.get("insecure") in ("1", "true"):
        tls["insecure"] = True
    ob = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port,
        "password": urllib.parse.unquote(u.username or ""),
        "tls": tls,
    }
    if q.get("obfs"):
        ob["obfs"] = {"type": q["obfs"],
                       "password": q.get("obfs-password", "")}
    return ob


def parse_vless(link):
    u = urllib.parse.urlparse(link)
    q = parse_query(link)
    ob = {
        "type": "vless",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port,
        "uuid": urllib.parse.unquote(u.username or ""),
    }
    if q.get("flow"):
        ob["flow"] = q["flow"]
    sec = (q.get("security") or "none").lower()
    if sec == "tls":
        ob["tls"] = tls_block(q)
    elif sec == "reality":
        tls = tls_block(q)
        tls["reality"] = {
            "enabled": True,
            "public_key": q.get("pbk", ""),
            "short_id": q.get("sid", ""),
        }
        ob["tls"] = tls
    tr = transport_block(q)
    if tr:
        ob["transport"] = tr
    return ob


def parse_trojan(link):
    u = urllib.parse.urlparse(link)
    q = parse_query(link)
    return {
        "type": "trojan",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port,
        "password": urllib.parse.unquote(u.username or ""),
        "tls": tls_block(q),
    }


def parse_vmess(link):
    raw = link.split("://", 1)[1].split("#", 1)[0]
    raw += "=" * (-len(raw) % 4)
    try:
        vm = json.loads(base64.urlsafe_b64decode(raw))
    except Exception as e:
        fail(f"vmess 链接解析失败: {e}")
    ob = {
        "type": "vmess",
        "tag": "proxy",
        "server": vm.get("add"),
        "server_port": int(vm.get("port", 443)),
        "uuid": vm.get("id"),
        "alter_id": int(vm.get("aid", 0)),
        "security": vm.get("scy", "auto"),
    }
    if vm.get("tls") == "tls":
        ob["tls"] = tls_block({
            "sni": vm.get("sni") or vm.get("host"),
            "fp": vm.get("fp"),
            "alpn": vm.get("alpn"),
        })
    net = (vm.get("net") or "tcp").lower()
    if net == "ws":
        tr = {"type": "ws", "path": vm.get("path", "/")}
        if vm.get("host"):
            tr["headers"] = {"Host": vm["host"]}
        ob["transport"] = tr
    elif net == "grpc":
        ob["transport"] = {"type": "grpc",
                           "service_name": vm.get("path", "")}
    elif net in ("http", "h2"):
        ob["transport"] = {"type": "httpupgrade",
                           "path": vm.get("path", "/")}
    return ob


PARSERS = {
    "hy2": parse_hy2,
    "hysteria2": parse_hy2,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "vmess": parse_vmess,
}


def download_singbox():
    if os.path.exists(BIN_PATH):
        r = subprocess.run([BIN_PATH, "version"], capture_output=True,
                           text=True)
        if r.returncode == 0 and SINGBOX_VERSION in r.stdout:
            print(f"ℹ️ sing-box {SINGBOX_VERSION} 已存在，跳过下载")
            return
    print(f"⬇️ 下载 sing-box {SINGBOX_VERSION}（固定版本，不查 latest）...")
    tmp = "sing-box.tar.gz"
    for attempt in range(1, 4):
        r = subprocess.run(
            ["curl", "-fsSL", "--retry", "2", "-o", tmp, SINGBOX_URL],
            capture_output=True, text=True)
        if r.returncode == 0 and os.path.exists(tmp):
            break
        print(f"⚠️ 下载第 {attempt} 次失败: {r.stderr.strip()[:200]}")
        time.sleep(5)
    else:
        fail("sing-box 下载失败（3 次重试均失败）")
    try:
        with tarfile.open(tmp, "r:gz") as tf:
            tf.extractall(".", filter="data")
    except Exception as e:
        fail(f"sing-box 解压失败: {e}")
    os.rename(f"sing-box-{SINGBOX_VERSION}-linux-amd64/sing-box", BIN_PATH)
    os.chmod(BIN_PATH, 0o755)
    r = subprocess.run([BIN_PATH, "version"], capture_output=True, text=True)
    if r.returncode != 0 or SINGBOX_VERSION not in r.stdout:
        fail("sing-box 二进制不可用")
    print(f"✅ sing-box {SINGBOX_VERSION} 就绪")


def wait_port(port, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


def exit_ip_via_proxy():
    for url in ("https://ifconfig.me", "https://api.ipify.org"):
        try:
            proxy = urllib.request.ProxyHandler(
                {"http": f"http://127.0.0.1:{LISTEN_PORT}",
                 "https": f"http://127.0.0.1:{LISTEN_PORT}"})
            opener = urllib.request.build_opener(proxy)
            req = urllib.request.Request(
                url, headers={"User-Agent": "curl/8.0"})
            with opener.open(req, timeout=15) as resp:
                ip = resp.read().decode().strip()
            if ip:
                return ip
        except Exception as e:
            print(f"⚠️ 经代理查出口 IP 失败 ({url}): {e}")
    return ""


def main():
    link = os.environ.get("NODE_LINK", "").strip()
    if not link:
        fail("NODE_LINK 为空，未设置节点链接")
    scheme = link.split("://", 1)[0].lower()
    if scheme not in PARSERS:
        fail(f"不支持的节点协议: {scheme}（支持 hy2/vless/trojan/vmess）")
    print(f"🔗 解析节点链接: {scheme}://…")
    outbound = PARSERS[scheme](link)
    print(f"🌐 节点服务器: {outbound.get('server')}:{outbound.get('server_port')}")

    download_singbox()

    config = {
        "log": {"level": "warning"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": LISTEN_PORT,
        }],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "proxy"},
    }
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

    r = subprocess.run([BIN_PATH, "check", "-c", CONFIG_PATH],
                       capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"sing-box 配置校验失败: {r.stderr.strip()[:500]}")
    print("✅ sing-box 配置校验通过")

    logf = open(LOG_PATH, "a")
    proc = subprocess.Popen(
        [BIN_PATH, "run", "-c", CONFIG_PATH],
        stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
    print(f"🚀 sing-box 已启动 (pid {proc.pid})，等待本地代理端口...")
    if not wait_port(LISTEN_PORT, timeout=30):
        fail("sing-box 启动后 30 秒内 1080 端口未监听，见 sing-box.log")
    ip = exit_ip_via_proxy()
    if not ip:
        fail("代理端口已监听，但经代理查出口 IP 失败，节点可能不通")
    print(f"📍 代理出口 IP: {ip}")

    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        with open(github_env, "a") as f:
            f.write("IS_PROXY=true\n")
            f.write(f"PROXY_SERVER=http://127.0.0.1:{LISTEN_PORT}\n")
        print("✅ 已导出 IS_PROXY=true / PROXY_SERVER，供后续步骤使用")
    else:
        print("⚠️ 未检测到 GITHUB_ENV（非 Actions 环境），请手动导出 "
              "IS_PROXY=true PROXY_SERVER=http://127.0.0.1:1080")


if __name__ == "__main__":
    main()
