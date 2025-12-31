# =========================
# Multi-Protocol Subscription Merger
# 完整可运行版（可直接复制）
# =========================

import os
import re
import json
import base64
import socket
import logging
import urllib.request
import yaml

# =========================
# GeoIP（可选，自动降级）
# =========================
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

GEOIP_DB = "GeoLite2-City.mmdb"

def get_physical_location(address: str) -> str:
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB):
        return "UN"

    address = re.sub(":.*", "", address)
    try:
        ip = socket.gethostbyname(address)
    except Exception:
        ip = address

    try:
        reader = geoip2.database.Reader(GEOIP_DB)
        resp = reader.city(ip)
        return resp.country.iso_code or "UN"
    except Exception:
        return "UN"

# =========================
# 全局容器 / 去重
# =========================
merged_proxies = []      # 用于 base64 / plain
plain_proxies = []       # 明文
proxy_fingerprint = set()
node_counter = 0

def add_proxy(uri: str, server="", port="", extra=""):
    global node_counter
    fp = f"{server}:{port}:{extra}"
    if fp in proxy_fingerprint:
        return
    proxy_fingerprint.add(fp)
    node_counter += 1
    merged_proxies.append(uri)
    plain_proxies.append(uri)

# =========================
# URL 处理器
# =========================
def process_urls(url_file, processor):
    if not os.path.exists(url_file):
        return
    with open(url_file, "r", encoding="utf-8") as f:
        urls = [i.strip() for i in f.readlines() if i.strip() and not i.startswith("#")]

    for idx, url in enumerate(urls):
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
                processor(data, idx)
        except Exception as e:
            logging.error(f"Error processing URL {url}: {e}")

# =========================
# Clash / Meta
# =========================
def process_clash(data, index):
    try:
        content = yaml.safe_load(data)
        proxies = content.get("proxies", [])
    except Exception:
        return

    for p in proxies:
        t = p.get("type")

        if t == "vless":
            server = p.get("server", "")
            port = p.get("port", 443)
            uuid = p.get("uuid", "")
            network = p.get("network", "")
            tls = int(p.get("tls", 0))
            sni = p.get("servername", "")
            flow = p.get("flow", "")
            insecure = int(p.get("skip-cert-verify", 0))
            reality = p.get("reality-opts", {})
            publicKey = reality.get("public-key", "")
            short_id = reality.get("short-id", "")
            fp = p.get("client-fingerprint", "")
            grpc = p.get("grpc-opts", {}).get("grpc-service-name", "")
            ws_path = p.get("ws-opts", {}).get("path", "")
            ws_host = p.get("ws-opts", {}).get("headers", {}).get("Host", "")

            if tls == 0:
                security = "none"
            elif tls == 1 and publicKey:
                security = "reality"
            else:
                security = "tls"

            loc = get_physical_location(server)
            name = f"{loc}_vless_{index}"
            uri = (
                f"vless://{uuid}@{server}:{port}"
                f"?security={security}&allowInsecure={insecure}&flow={flow}"
                f"&type={network}&fp={fp}&pbk={publicKey}&sid={short_id}"
                f"&sni={sni}&serviceName={grpc}&path={ws_path}&host={ws_host}"
                f"#{name}"
            )
            add_proxy(uri, server, port, uuid)

        elif t == "vmess":
            server = p.get("server", "")
            port = p.get("port", 443)
            uuid = p.get("uuid", "")
            network = p.get("network", "")
            tls = int(p.get("tls", 0))
            sni = p.get("servername", "")
            ws_path = p.get("ws-opts", {}).get("path", "")
            ws_host = p.get("ws-opts", {}).get("headers", {}).get("Host", "")
            security = "tls" if tls else "none"

            loc = get_physical_location(server)
            name = f"{loc}_vmess_{index}"
            uri = (
                f"vmess://{uuid}@{server}:{port}"
                f"?security={security}&type={network}&sni={sni}"
                f"&path={ws_path}&host={ws_host}#{name}"
            )
            add_proxy(uri, server, port, uuid)

        elif t == "tuic":
            server = p.get("server", "")
            port = p.get("port", 443)
            uuid = p.get("uuid", "")
            password = p.get("password", "")
            sni = p.get("sni", "")
            insecure = int(p.get("skip-cert-verify", 0))
            udp_mode = p.get("udp-relay-mode", "naive")
            congestion = p.get("congestion-controller", "bbr")
            alpn = p.get("alpn", [None])[0]

            loc = get_physical_location(server)
            name = f"{loc}_tuic_{index}"
            uri = (
                f"tuic://{uuid}:{password}@{server}:{port}"
                f"?sni={sni}&congestion_control={congestion}"
                f"&udp_relay_mode={udp_mode}&alpn={alpn}"
                f"&allow_insecure={insecure}#{name}"
            )
            add_proxy(uri, server, port, uuid)

        elif t == "hysteria2":
            server = p.get("server", "")
            port = p.get("port", 443)
            auth = p.get("password", "")
            sni = p.get("sni", "")
            insecure = int(p.get("skip-cert-verify", 0))

            loc = get_physical_location(server)
            name = f"{loc}_hy2_{index}"
            uri = (
                f"hysteria2://{auth}@{server}:{port}"
                f"?insecure={insecure}&sni={sni}#{name}"
            )
            add_proxy(uri, server, port, auth)

        elif t == "hysteria":
            server = p.get("server", "")
            port = p.get("port", 443)
            sni = p.get("sni", "")
            auth = p.get("auth-str", "")
            insecure = int(p.get("skip-cert-verify", 0))
            up = 50
            down = 80

            loc = get_physical_location(server)
            name = f"{loc}_hy_{index}"
            uri = (
                f"hysteria://{server}:{port}"
                f"?peer={sni}&auth={auth}&insecure={insecure}"
                f"&upmbps={up}&downmbps={down}#{name}"
            )
            add_proxy(uri, server, port, auth)

# =========================
# naive
# =========================
def process_naive(data, index):
    try:
        j = json.loads(data)
        proxy = j.get("proxy", "")
        if proxy:
            uri = base64.b64encode(proxy.encode()).decode()
            add_proxy(uri, "naive", "", proxy)
    except Exception:
        pass

# =========================
# hysteria json
# =========================
def process_hysteria(data, index):
    try:
        j = json.loads(data)
        server = j.get("server", "")
        auth = j.get("auth_str", "")
        sni = j.get("server_name", "")
        insecure = int(j.get("insecure", 0))

        loc = get_physical_location(server)
        name = f"{loc}_hysteria_{index}"
        uri = (
            f"hysteria://{server}"
            f"?peer={sni}&auth={auth}&insecure={insecure}#{name}"
        )
        add_proxy(uri, server, "", auth)
    except Exception:
        pass

# =========================
# hysteria2 json
# =========================
def process_hysteria2(data, index):
    try:
        j = json.loads(data)
        server = j.get("server", "")
        auth = j.get("auth", "")
        tls = j.get("tls", {})
        insecure = int(tls.get("insecure", 0))
        sni = tls.get("sni", "")

        loc = get_physical_location(server)
        name = f"{loc}_hysteria2_{index}"
        uri = (
            f"hysteria2://{auth}@{server}"
            f"?insecure={insecure}&sni={sni}#{name}"
        )
        add_proxy(uri, server, "", auth)
    except Exception:
        pass

# =========================
# xray
# =========================
def process_xray(data, index):
    try:
        j = json.loads(data)
        out = j["outbounds"][0]
        proto = out.get("protocol")

        if proto == "vless":
            v = out["settings"]["vnext"][0]
            server = v["address"]
            port = v["port"]
            user = v["users"][0]
            uuid = user["id"]
            flow = user.get("flow", "")

            stream = out.get("streamSettings", {})
            network = stream.get("network", "")
            security = stream.get("security", "")
            tls = stream.get("tlsSettings", {})
            sni = tls.get("serverName", "")
            insecure = int(tls.get("allowInsecure", 0))

            loc = get_physical_location(server)
            name = f"{loc}_xray_vless_{index}"
            uri = (
                f"vless://{uuid}@{server}:{port}"
                f"?security={security}&flow={flow}&type={network}"
                f"&sni={sni}&allowInsecure={insecure}#{name}"
            )
            add_proxy(uri, server, port, uuid)
    except Exception:
        pass

# =========================
# 主流程
# =========================
logging.basicConfig(level=logging.INFO)

process_urls("./urls/clash_urls.txt", process_clash)
process_urls("./urls/naiverproxy_urls.txt", process_naive)
process_urls("./urls/hysteria_urls.txt", process_hysteria)
process_urls("./urls/hysteria2_urls.txt", process_hysteria2)
process_urls("./urls/xray_urls.txt", process_xray)

# =========================
# 输出
# =========================
os.makedirs("./sub", exist_ok=True)

# 明文
with open("./sub/plain.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(plain_proxies))

# base64
b64 = base64.b64encode("\n".join(plain_proxies).encode()).decode()
with open("./sub/base64.txt", "w", encoding="utf-8") as f:
    f.write(b64)

# clash.meta.yaml（简单可用版）
clash = {
    "mixed-port": 7890,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "proxies": [],
    "proxy-groups": [
        {
            "name": "AUTO",
            "type": "select",
            "proxies": []
        }
    ],
    "rules": ["MATCH,AUTO"]
}

for i, uri in enumerate(plain_proxies):
    name = f"NODE-{i}"
    clash["proxy-groups"][0]["proxies"].append(name)

with open("./sub/clash.meta.yaml", "w", encoding="utf-8") as f:
    yaml.dump(clash, f, allow_unicode=True)

print(f"DONE. total nodes = {len(plain_proxies)}")
