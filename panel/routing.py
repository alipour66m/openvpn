"""Smart routing, split-tunnel bypass, anti-abuse firewall, DNS presets, and multi-remote failover for GassLight."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable

try:
    from .geoip import GeoIPManager  # type: ignore
except ImportError:
    try:
        from geoip import GeoIPManager  # type: ignore
    except ImportError:
        GeoIPManager = None  # type: ignore

DNS_PRESETS: dict[str, dict[str, Any]] = {
    "cloudflare": {"label": "Cloudflare", "servers": ["1.1.1.1", "1.0.0.1"]},
    "adguard": {"label": "AdGuard (AdBlock)", "servers": ["94.140.14.14", "94.140.15.15"]},
    "adguard_family": {"label": "AdGuard Family", "servers": ["94.140.14.15", "94.140.15.16"]},
    "google": {"label": "Google", "servers": ["8.8.8.8", "8.8.4.4"]},
    "quad9": {"label": "Quad9 (Security)", "servers": ["9.9.9.9", "149.112.112.112"]},
    "shecan": {"label": "Shecan (403 Bypass)", "servers": ["178.22.122.100", "185.51.200.2"]},
    "electro": {"label": "Electro", "servers": ["78.157.42.100", "78.157.42.101"]},
}

BYPASS_PRESETS: dict[str, dict[str, Any]] = {
    "iran_banks": {
        "label": "Iranian Banks & Shaparak",
        "cidrs": [],
        "domains": [
            "shaparak.ir",
            "bpm.shaparak.ir",
            "pec.shaparak.ir",
            "sep.shaparak.ir",
            "sadad.shaparak.ir",
            "asan.shaparak.ir",
            "ikc.shaparak.ir",
            "pna.shaparak.ir",
            "sepehr.shaparak.ir",
            "bankmellat.ir",
            "bmi.ir",
            "bsi.ir",
            "tejaratbank.ir",
            "sb24.ir",
            "bpi.ir",
            "banksepah.ir",
            "bki.ir",
            "refah-bank.ir",
            "ba24.ir",
            "blubank.com",
            "zarinpal.com",
            "snapppay.ir",
        ],
    },
    "iran_essential": {
        "label": "Essential Iranian Services",
        "cidrs": [],
        "domains": [
            "digikala.com",
            "snapp.ir",
            "tapsi.ir",
            "divar.ir",
            "torob.com",
            "aparat.com",
            "filimo.com",
            "namava.ir",
            "balad.ir",
            "neshan.org",
            "my.gov.ir",
            "sso.my.gov.ir",
            "adliran.ir",
            "tax.gov.ir",
            "sanjesh.org",
            "tamin.ir",
            "irancell.ir",
            "mci.ir",
            "rightel.ir",
            "emofid.com",
            "tsetmc.com",
        ],
    },
}

SMART_PRESETS: dict[str, dict[str, Any]] = {
    "ai": {
        "label": "AI Services (ChatGPT / Claude / Gemini)",
        "domains": [
            "openai.com",
            "chatgpt.com",
            "oaistatic.com",
            "oaiusercontent.com",
            "claude.ai",
            "anthropic.com",
            "gemini.google.com",
            "aistudio.google.com",
            "generativelanguage.googleapis.com",
            "perplexity.ai",
            "copilot.microsoft.com",
            "grok.com",
            "x.ai",
            "midjourney.com",
            "cursor.sh",
            "cursor.com",
        ],
    },
    "streaming": {
        "label": "Streaming (Netflix / Spotify / Disney+)",
        "domains": [
            "netflix.com",
            "nflxvideo.net",
            "nflximg.net",
            "nflxso.net",
            "spotify.com",
            "scdn.co",
            "disneyplus.com",
            "bamgrid.com",
            "hulu.com",
            "primevideo.com",
            "hbomax.com",
            "max.com",
        ],
    },
}

DEFAULT_SMART_PORTS = [80, 443, 8080, 8443]
TORRENT_STRINGS = (
    "BitTorrent",
    "BitTorrent protocol",
    "peer_id=",
    ".torrent",
    "announce.php?passkey=",
    "info_hash",
    "get_peers",
    "announce_peer",
    "find_node",
)

BYPASS_BEGIN = "# BEGIN GASSLIGHT-BYPASS"
BYPASS_END = "# END GASSLIGHT-BYPASS"
USER_DNS_BEGIN = "# BEGIN GASSLIGHT-USER-DNS"
USER_DNS_END = "# END GASSLIGHT-USER-DNS"

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_HTTP_HOST_RE = re.compile(r"(?:^|\r?\n)[Hh][Oo][Ss][Tt]:[ \t]*([^\r\n]+)")
_HTTP_METHOD_PREFIXES = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
)


def normalize_domain(raw: str) -> str | None:
    """Normalize a user-entered domain or URL into a clean lowercase hostname."""
    s = (raw or "").strip()
    if not s or s.startswith("#"):
        return None
    s = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", s)
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.split("@")[-1]
    if ":" in s:
        host_part, _, port_part = s.rpartition(":")
        if port_part.isdigit():
            s = host_part
    s = s.lstrip("*.").rstrip(".").lower()
    if not s or "." not in s:
        return None
    if not _HOST_RE.match(s):
        return None
    if re.fullmatch(r"[0-9.]+", s):
        return None
    return s


def domain_matches(host: str | None, rules: Iterable[str]) -> bool:
    """Return True if host matches any domain rule by exact or subdomain boundary."""
    if not host:
        return False
    h = host.strip().rstrip(".").lower()
    if not h:
        return False
    rule_set = {r.strip().lstrip("*.").rstrip(".").lower() for r in rules if r and str(r).strip()}
    if not rule_set:
        return False
    if h in rule_set:
        return True
    parts = h.split(".")
    for idx in range(1, len(parts)):
        suffix = ".".join(parts[idx:])
        if suffix in rule_set:
            return True
    return False


def extract_tls_sni(data: bytes) -> str | None:
    """Safely extract the Server Name Indication hostname from a TLS ClientHello packet."""
    if not data or len(data) < 43:
        return None
    if data[0] != 0x16 or data[1] != 0x03:
        return None
    rec_len = int.from_bytes(data[3:5], "big")
    rec_end = min(len(data), 5 + rec_len)
    if rec_end < 43 or data[5] != 0x01:
        return None
    hs_len = int.from_bytes(data[6:9], "big")
    hs_end = min(rec_end, 9 + hs_len)
    pos = 9 + 2 + 32  # ClientHello version (2) + random (32)
    if pos >= hs_end:
        return None
    sid_len = data[pos]
    pos += 1 + sid_len
    if pos + 2 > hs_end:
        return None
    cs_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2 + cs_len
    if pos + 1 > hs_end:
        return None
    comp_len = data[pos]
    pos += 1 + comp_len
    if pos + 2 > hs_end:
        return None
    ext_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    ext_end = min(hs_end, pos + ext_len)
    while pos + 4 <= ext_end:
        ext_type = int.from_bytes(data[pos : pos + 2], "big")
        elen = int.from_bytes(data[pos + 2 : pos + 4], "big")
        pos += 4
        if pos + elen > ext_end:
            break
        if ext_type == 0x0000 and elen >= 2:
            list_len = int.from_bytes(data[pos : pos + 2], "big")
            npos = pos + 2
            nend = min(pos + elen, npos + list_len)
            while npos + 3 <= nend:
                ntype = data[npos]
                nlen = int.from_bytes(data[npos + 1 : npos + 3], "big")
                npos += 3
                if npos + nlen > nend:
                    break
                if ntype == 0:
                    try:
                        name = data[npos : npos + nlen].decode("ascii").strip(".").lower()
                    except UnicodeDecodeError:
                        return None
                    return name if _HOST_RE.match(name) else None
                npos += nlen
        pos += elen
    return None


def extract_http_host(data: bytes) -> str | None:
    """Extract the hostname from an HTTP/1.x request Host header."""
    if not data or not any(data.startswith(p) for p in _HTTP_METHOD_PREFIXES):
        return None
    head = data[:4096].split(b"\r\n\r\n", 1)[0].decode("latin1", "ignore")
    m = _HTTP_HOST_RE.search(head)
    if not m:
        return None
    raw_host = m.group(1).strip()
    if not raw_host:
        return None
    if raw_host.startswith("["):
        return None
    if ":" in raw_host:
        raw_host = raw_host.rsplit(":", 1)[0]
    host = raw_host.rstrip(".").lower()
    return host if _HOST_RE.match(host) else None


def extract_sni_or_host(data: bytes) -> str | None:
    """Inspect initial client bytes for a TLS SNI or HTTP Host header."""
    return extract_tls_sni(data) or extract_http_host(data)


def parse_cidr_list(items: Iterable[str]) -> tuple[list[str], list[str]]:
    """Validate and canonicalize IPv4 addresses/CIDRs, separating invalid/unsafe entries."""
    valid: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for raw in items:
        s = (raw or "").strip()
        if not s or s.startswith("#"):
            continue
        try:
            net = ipaddress.IPv4Network(s, strict=False)
        except ValueError:
            invalid.append(s)
            continue
        if (
            net.prefixlen < 8
            or net.is_loopback
            or net.is_multicast
            or net.is_link_local
            or net.is_unspecified
            or net.is_reserved
        ):
            invalid.append(s)
            continue
        canon = str(net)
        if canon not in seen:
            seen.add(canon)
            valid.append(canon)
    return valid, invalid


def collapse_and_cap_cidrs(cidrs: Iterable[str], max_routes: int = 250) -> dict[str, Any]:
    """Collapse overlapping IPv4 networks and cap count to stay safe for iOS NetworkExtension."""
    cap = max(1, min(500, int(max_routes or 250)))
    nets: list[ipaddress.IPv4Network] = []
    for raw in cidrs:
        try:
            net = ipaddress.IPv4Network(str(raw).strip(), strict=False)
        except ValueError:
            continue
        if (
            net.prefixlen >= 8
            and not net.is_loopback
            and not net.is_multicast
            and not net.is_link_local
            and not net.is_unspecified
            and not net.is_reserved
        ):
            nets.append(net)
    collapsed = list(ipaddress.collapse_addresses(nets))
    # Prefer broader prefixes first if capping is ever needed so aggregated presets win over /32s
    collapsed.sort(key=lambda n: (n.prefixlen, int(n.network_address)))
    total = len(collapsed)
    capped = collapsed[:cap]
    routes = [(str(n.network_address), str(n.netmask), str(n)) for n in capped]
    return {
        "routes": routes,
        "total_before_cap": total,
        "pushed_count": len(routes),
        "truncated": total > cap,
    }


def render_bypass_block(routes: Iterable[tuple[str, str, str]]) -> str:
    """Render an idempotent OpenVPN CCD split-tunnel bypass block."""
    items = list(routes)
    if not items:
        return ""
    lines = [BYPASS_BEGIN]
    for ip, mask, _cidr in items:
        lines.append(f'push "route {ip} {mask} net_gateway"')
    lines.append(BYPASS_END)
    return "\n".join(lines) + "\n"


def render_user_dns_block(servers: Iterable[str]) -> str:
    """Render an idempotent per-user CCD DNS override block."""
    clean = [s for s in servers if s]
    if not clean:
        return ""
    lines = [USER_DNS_BEGIN] + [f'push "dhcp-option DNS {s}"' for s in clean] + [USER_DNS_END]
    return "\n".join(lines) + "\n"


def patch_marked_block(txt: str, begin_marker: str, end_marker: str, block: str) -> str:
    """Idempotently replace or remove a marker-delimited section in a text config."""
    pat = re.compile(
        rf"^[ \t]*{re.escape(begin_marker)}\r?\n.*?^[ \t]*{re.escape(end_marker)}\r?\n?",
        re.M | re.S,
    )
    cleaned = pat.sub("", txt or "")
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip("\r\n")
    if block:
        prefix = (cleaned + "\n") if cleaned else ""
        return prefix + block.strip("\r\n") + "\n"
    return (cleaned + "\n") if cleaned else ""


def conf_with_max_clients(conf: str, name: str, max_clients: int) -> str:
    """Adjust OpenVPN server instance config for single-device or multi-device mode."""
    mc = max(1, min(50, int(max_clients or 1)))
    out = re.sub(r"^[ \t]*duplicate-cn\b.*\r?\n?", "", conf, flags=re.M)
    out = re.sub(r"^[ \t]*max-clients\b.*\r?\n?", "", out, flags=re.M)
    if mc > 1:
        out = re.sub(r"^[ \t]*ifconfig-pool-persist\b.*\r?\n?", "", out, flags=re.M)
        out = out.rstrip("\r\n") + f"\nduplicate-cn\nmax-clients {mc}\n"
        return out
    ipp = f"ifconfig-pool-persist ipp-{name}.txt"
    if re.search(r"^[ \t]*ifconfig-pool-persist\b", out, re.M):
        out = re.sub(r"^[ \t]*ifconfig-pool-persist\b.*", ipp, out, flags=re.M)
    else:
        out = out.rstrip("\r\n") + f"\n{ipp}\n"
    return out


def parse_backup_remote(line: str) -> dict[str, Any] | None:
    """Parse a backup OpenVPN remote line: host | host:port | host:port:proto | proto://host:port."""
    raw = (line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    proto: str | None = None
    m_scheme = re.match(r"^(tcp|udp)://(.+)$", raw, re.I)
    if m_scheme:
        proto = m_scheme.group(1).lower()
        raw = m_scheme.group(2).strip()
    parts = raw.split(":")
    host = parts[0].strip()
    port: int | None = None
    if len(parts) == 2:
        if not parts[1].isdigit():
            return None
        port = int(parts[1])
    elif len(parts) == 3:
        if not parts[1].isdigit() or parts[2].lower() not in ("tcp", "udp"):
            return None
        port = int(parts[1])
        proto = proto or parts[2].lower()
    elif len(parts) > 3:
        return None
    if not _HOST_RE.match(host):
        return None
    if re.fullmatch(r"[0-9.]+", host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return None
    if port is not None and not 1 <= port <= 65535:
        return None
    canon = host
    if port is not None:
        canon += f":{port}"
        if proto is not None:
            canon += f":{proto}"
    elif proto is not None:
        canon = f"{proto}://{host}"
    return {"host": host, "port": port, "proto": proto, "raw": canon}


def inject_failover_ovpn(
    ovpn_text: str,
    user_port: int,
    user_proto: str,
    global_cfg: dict[str, Any],
    user_remotes: list[str] | None = None,
) -> str:
    """Inject backup remote lines and fast failover timers into an .ovpn client profile."""
    raw_list = list(user_remotes or [])
    if not raw_list:
        if not global_cfg.get("enabled"):
            return ovpn_text
        raw_list = list(global_cfg.get("remotes") or [])

    parsed = [p for p in (parse_backup_remote(x) for x in raw_list) if p]
    if not parsed:
        return ovpn_text

    m_primary = re.search(r"^remote[ \t]+(\S+)[ \t]+(\d+)(?:[ \t]+(\S+))?[ \t]*$", ovpn_text, re.M)
    if not m_primary:
        return ovpn_text

    p_host = m_primary.group(1)
    p_port = int(m_primary.group(2))
    p_proto = (m_primary.group(3) or user_proto or "udp").lower()
    seen = {(p_host.lower(), p_port, p_proto)}
    extra_lines: list[str] = []
    default_proto = (user_proto or "udp").lower()

    for entry in parsed:
        h = entry["host"]
        p = int(entry["port"] or user_port or p_port)
        pr = (entry["proto"] or default_proto).lower()
        key = (h.lower(), p, pr)
        if key in seen:
            continue
        seen.add(key)
        if entry["proto"] and pr != default_proto:
            extra_lines.append(f"remote {h} {p} {pr}")
        else:
            extra_lines.append(f"remote {h} {p}")

    if not extra_lines:
        return ovpn_text

    # Remove existing timer/random/extra remote lines outside inline blocks safely (header is before <ca>)
    head, sep, tail = ovpn_text.partition("<ca>")
    head = re.sub(r"^[ \t]*(?:connect-retry|connect-timeout|remote-random)\b.*\r?\n?", "", head, flags=re.M)
    retry_min = max(1, min(60, int(global_cfg.get("connect_retry_min", 2) or 2)))
    retry_max = max(retry_min, min(120, int(global_cfg.get("connect_retry_max", 5) or 5)))
    conn_to = max(3, min(60, int(global_cfg.get("connect_timeout", 10) or 10)))

    lines = head.splitlines()
    new_head: list[str] = []
    inserted = False
    for line in lines:
        new_head.append(line)
        if not inserted and re.match(r"^[ \t]*remote[ \t]+\S+[ \t]+\d+", line):
            new_head.extend(extra_lines)
            new_head.append(f"connect-retry {retry_min} {retry_max}")
            new_head.append(f"connect-timeout {conn_to}")
            if global_cfg.get("remote_random"):
                new_head.append("remote-random")
            inserted = True

    if not any(re.match(r"^[ \t]*resolv-retry\b", l) for l in new_head):
        new_head.append("resolv-retry infinite")

    rebuilt_head = "\n".join(new_head).rstrip("\n") + "\n"
    return (rebuilt_head + sep + tail) if sep else rebuilt_head


class RoutingManager:
    """Manages split-tunnel bypass, anti-abuse firewall, smart SNI routing, DNS presets, and backup remotes."""

    ABUSE_CHAIN = "GASSLIGHT_ABUSE"

    def __init__(
        self,
        base_dir: str,
        server_dir: str,
        run_fn: Callable[..., Any],
        load_state_fn: Callable[[], dict[str, Any]],
        set_dns_fn: Callable[[list[str]], tuple[bool, str]],
        read_dns_fn: Callable[[], list[str]],
        restart_for_dns_fn: Callable[[], None],
        proxy_sync_fn: Callable[[], None],
        geoip: "GeoIPManager | None" = None,
    ) -> None:
        self.base_dir = base_dir
        self.server_dir = server_dir
        self.run = run_fn
        self.load_state = load_state_fn
        self.set_dns = set_dns_fn
        self.read_dns = read_dns_fn
        self.restart_for_dns = restart_for_dns_fn
        self.proxy_sync = proxy_sync_fn
        self.lock = threading.RLock()
        self._geoip = geoip

        self.bypass_file = os.path.join(base_dir, "bypass.json")
        self.abuse_file = os.path.join(base_dir, "abuse.json")
        self.smart_file = os.path.join(base_dir, "smart_routing.json")
        self.remotes_file = os.path.join(base_dir, "remotes.json")

        self._has_xt_string: bool | None = None
        self._warp_cache: dict[str, Any] = {"checked": 0.0, "reachable": False, "ms": None}

        self.bypass = self._load_json(self.bypass_file, {
            "enabled": False,
            "presets": ["iran_banks"],
            "custom_cidrs": [],
            "custom_domains": [],
            "geoip_enabled": False,
            "geoip_countries": [],
            "max_routes": 250,
            "resolve_hours": 6,
            "resolved_ips": {},
            "last_resolved": 0.0,
        })
        self.abuse = self._load_json(self.abuse_file, {
            "enabled": False,
            "block_smtp": False,
            "block_smtp_alt": False,
            "block_torrent": False,
            "block_torrent_dpi": True,
            "custom_blocked_ports": [],
        })
        self.smart = self._load_json(self.smart_file, {
            "enabled": False,
            "mode": "domains_only",
            "target": "auto",
            "warp_host": "127.0.0.1",
            "warp_port": 40000,
            "presets": ["ai"],
            "domains": [],
            "all_users": True,
            "block_quic": True,
            "fallback_direct": True,
            "ports": list(DEFAULT_SMART_PORTS),
        })
        self.remotes = self._load_json(self.remotes_file, {
            "enabled": False,
            "remotes": [],
            "remote_random": False,
            "connect_retry_min": 2,
            "connect_retry_max": 5,
            "connect_timeout": 10,
        })

    def _load_json(self, path: str, defaults: dict[str, Any]) -> dict[str, Any]:
        cfg = json.loads(json.dumps(defaults))
        try:
            with open(path, encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                cfg.update(saved)
        except (OSError, ValueError):
            pass
        return cfg

    def _save_json(self, path: str, data: dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    # ------------------------------------------------------------------ Bypass
    def _collect_bypass_domains(self, cfg: dict[str, Any]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for key in cfg.get("presets") or []:
            preset = BYPASS_PRESETS.get(key)
            if preset:
                for d in preset.get("domains") or []:
                    nd = normalize_domain(d)
                    if nd and nd not in seen:
                        seen.add(nd)
                        out.append(nd)
        for d in cfg.get("custom_domains") or []:
            nd = normalize_domain(d)
            if nd and nd not in seen:
                seen.add(nd)
                out.append(nd)
        return out

    def _collect_bypass_cidrs(self, cfg: dict[str, Any]) -> list[str]:
        raw: list[str] = []
        for key in cfg.get("presets") or []:
            preset = BYPASS_PRESETS.get(key)
            if preset:
                raw.extend(preset.get("cidrs") or [])
        raw.extend(cfg.get("custom_cidrs") or [])
        resolved_map = cfg.get("resolved_ips") or {}
        if isinstance(resolved_map, dict):
            for dom in self._collect_bypass_domains(cfg):
                for ip in resolved_map.get(dom) or []:
                    raw.append(f"{ip}/32" if "/" not in str(ip) else str(ip))

        # ✅ GeoIP: add all CIDRs for selected countries
        if cfg.get("geoip_enabled") and self._geoip is not None:
            for iso in cfg.get("geoip_countries") or []:
                iso = str(iso).strip().upper()
                if iso:
                    geo_cidrs = self._geoip.country_cidrs(iso)
                    raw.extend(geo_cidrs)

        valid, _bad = parse_cidr_list(raw)
        return valid

    def compute_bypass_routes(self, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
        with self.lock:
            target = cfg if cfg is not None else self.bypass
            if not target.get("enabled"):
                return {"routes": [], "total_before_cap": 0, "pushed_count": 0, "truncated": False}
            cidrs = self._collect_bypass_cidrs(target)
            return collapse_and_cap_cidrs(cidrs, int(target.get("max_routes") or 250))

    def get_bypass(self) -> dict[str, Any]:
        with self.lock:
            snap = json.loads(json.dumps(self.bypass))
            summary = self.compute_bypass_routes(snap)
            snap["route_count"] = summary["pushed_count"]
            snap["total_before_cap"] = summary["total_before_cap"]
            snap["truncated"] = summary["truncated"]
            snap["routes"] = [r[2] for r in summary["routes"]]
            snap["presets_meta"] = {
                k: {"label": v["label"], "domains_count": len(v["domains"]), "cidrs_count": len(v["cidrs"])}
                for k, v in BYPASS_PRESETS.items()
            }
            # GeoIP status
            snap["geoip_available"] = self._geoip is not None
            if self._geoip is not None:
                snap["geoip_status"] = self._geoip.status()
            return snap

    def resolve_bypass_domains(
        self,
        resolver_fn: Callable[[str], list[str]] | None = None,
        sync_ccd: bool = True,
    ) -> dict[str, Any]:
        with self.lock:
            domains = self._collect_bypass_domains(self.bypass)

        def default_resolve(host: str) -> list[str]:
            ips: list[str] = []
            try:
                infos = socket.getaddrinfo(host, None, socket.AF_INET)
                for item in infos:
                    ip = item[4][0]
                    try:
                        addr = ipaddress.IPv4Address(ip)
                    except ValueError:
                        continue
                    if not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved):
                        if ip not in ips:
                            ips.append(ip)
            except OSError:
                pass
            return sorted(ips)[:8]

        fn = resolver_fn or default_resolve
        resolved: dict[str, list[str]] = {}
        failed: list[str] = []
        if domains:
            with ThreadPoolExecutor(max_workers=min(10, len(domains))) as pool:
                results = list(pool.map(lambda d: (d, fn(d)), domains))
            for dom, ips in results:
                clean_ips = []
                for ip in ips or []:
                    try:
                        addr = ipaddress.IPv4Address(str(ip).split("/")[0])
                        if not (addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_reserved):
                            s = str(addr)
                            if s not in clean_ips:
                                clean_ips.append(s)
                    except ValueError:
                        continue
                if clean_ips:
                    resolved[dom] = clean_ips
                else:
                    failed.append(dom)

        with self.lock:
            # Keep previous IPs for domains that temporarily failed DNS if any existed
            prev = self.bypass.get("resolved_ips") or {}
            merged: dict[str, list[str]] = {}
            for dom in domains:
                if dom in resolved:
                    merged[dom] = resolved[dom]
                elif dom in prev:
                    merged[dom] = prev[dom]
            self.bypass["resolved_ips"] = merged
            self.bypass["last_resolved"] = time.time()
            self._save_json(self.bypass_file, self.bypass)
        if sync_ccd:
            self.sync_all_ccd()
        return {
            "domains_total": len(domains),
            "domains_resolved": len(resolved),
            "domains_failed": failed,
            "summary": self.compute_bypass_routes(),
        }

    def save_bypass(
        self,
        payload: dict[str, Any],
        resolve_now: bool = True,
        resolver_fn: Callable[[str], list[str]] | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            enabled = bool(payload.get("enabled", self.bypass["enabled"]))
            presets_in = payload.get("presets", self.bypass["presets"])
            presets = [p for p in (presets_in or []) if p in BYPASS_PRESETS]

            raw_cidrs = payload.get("custom_cidrs", self.bypass["custom_cidrs"])
            if isinstance(raw_cidrs, str):
                raw_cidrs = re.split(r"[\s,]+", raw_cidrs.strip())
            valid_cidrs, bad_cidrs = parse_cidr_list(raw_cidrs or [])

            raw_doms = payload.get("custom_domains", self.bypass["custom_domains"])
            if isinstance(raw_doms, str):
                raw_doms = re.split(r"[\s,]+", raw_doms.strip())
            valid_doms: list[str] = []
            bad_doms: list[str] = []
            for d in raw_doms or []:
                s = (d or "").strip()
                if not s or s.startswith("#"):
                    continue
                nd = normalize_domain(s)
                if nd:
                    if nd not in valid_doms:
                        valid_doms.append(nd)
                else:
                    bad_doms.append(s)

            # ✅ GeoIP countries
            geoip_enabled = bool(payload.get("geoip_enabled", self.bypass.get("geoip_enabled", False)))
            raw_countries = payload.get("geoip_countries", self.bypass.get("geoip_countries", []))
            if isinstance(raw_countries, str):
                raw_countries = re.split(r"[\s,]+", raw_countries.strip())
            geoip_countries: list[str] = []
            for c in raw_countries or []:
                c = str(c).strip().upper()
                if c and c.isalpha() and len(c) <= 10 and c not in geoip_countries:
                    geoip_countries.append(c)

            try:
                max_routes = max(1, min(500, int(payload.get("max_routes", self.bypass["max_routes"]))))
            except (TypeError, ValueError):
                max_routes = 250
            try:
                resolve_hours = max(1, min(168, int(payload.get("resolve_hours", self.bypass["resolve_hours"]))))
            except (TypeError, ValueError):
                resolve_hours = 6

            self.bypass.update(
                enabled=enabled,
                presets=presets,
                custom_cidrs=valid_cidrs,
                custom_domains=valid_doms,
                geoip_enabled=geoip_enabled,
                geoip_countries=geoip_countries,
                max_routes=max_routes,
                resolve_hours=resolve_hours,
            )
            self._save_json(self.bypass_file, self.bypass)

        resolve_info = None
        if enabled and resolve_now:
            resolve_info = self.resolve_bypass_domains(resolver_fn=resolver_fn, sync_ccd=True)
        else:
            self.sync_all_ccd()

        res = self.get_bypass()
        res["invalid_cidrs"] = bad_cidrs
        res["invalid_domains"] = bad_doms
        if resolve_info is not None:
            res["resolve"] = resolve_info
        return res

    def sync_user_ccd(self, name: str, user_dns: list[str] | None = None) -> None:
        ccd_dir = os.path.join(self.server_dir, f"ccd-{name}")
        ccd_file = os.path.join(ccd_dir, name)
        if not os.path.isdir(self.server_dir):
            return
        os.makedirs(ccd_dir, exist_ok=True)
        try:
            with open(ccd_file, encoding="utf-8") as f:
                txt = f.read()
        except OSError:
            txt = ""

        summary = self.compute_bypass_routes()
        bypass_block = render_bypass_block(summary["routes"])
        txt = patch_marked_block(txt, BYPASS_BEGIN, BYPASS_END, bypass_block)

        if user_dns is not None:
            dns_block = render_user_dns_block(user_dns)
            txt = patch_marked_block(txt, USER_DNS_BEGIN, USER_DNS_END, dns_block)

        tmp = ccd_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(txt)
        os.chmod(tmp, 0o644)
        os.replace(tmp, ccd_file)

    def sync_all_ccd(self) -> int:
        if not os.path.isdir(self.server_dir):
            return 0
        count = 0
        for u in self.load_state().get("users", []):
            name = u.get("name")
            if name:
                self.sync_user_ccd(name, u.get("dns") or [])
                count += 1
        return count

    def bypass_resolver_loop(self) -> None:
        while True:
            time.sleep(60)
            try:
                with self.lock:
                    enabled = bool(self.bypass.get("enabled"))
                    interval = max(1, int(self.bypass.get("resolve_hours") or 6)) * 3600
                    last = float(self.bypass.get("last_resolved") or 0)
                if enabled and (time.time() - last >= interval):
                    self.resolve_bypass_domains(sync_ccd=True)
            except Exception as exc:
                print("bypass resolver error:", exc, flush=True)

    # ------------------------------------------------------------------ Anti-Abuse Firewall
    def probe_xt_string(self) -> bool:
        if self._has_xt_string is not None:
            return self._has_xt_string
        try:
            r = self.run(["iptables", "-m", "string", "--help"])
            self._has_xt_string = getattr(r, "returncode", 1) == 0
        except Exception:
            self._has_xt_string = False
        return self._has_xt_string

    def build_abuse_rules(self, cfg: dict[str, Any] | None = None, has_xt_string: bool = True) -> list[list[str]]:
        c = cfg if cfg is not None else self.abuse
        if not c.get("enabled"):
            return []
        rules: list[list[str]] = []
        if c.get("block_smtp"):
            rules.append(["-i", "tun+", "-p", "tcp", "--dport", "25", "-j", "REJECT", "--reject-with", "tcp-reset"])
        if c.get("block_smtp_alt"):
            rules.append(["-i", "tun+", "-p", "tcp", "-m", "multiport", "--dports", "465,587", "-j", "REJECT", "--reject-with", "tcp-reset"])
        if c.get("block_torrent"):
            for spec in (
                ["-i", "tun+", "-p", "tcp", "--dport", "6881:6889", "-j", "DROP"],
                ["-i", "tun+", "-p", "udp", "--dport", "6881:6889", "-j", "DROP"],
                ["-i", "tun+", "-p", "tcp", "--dport", "6969", "-j", "DROP"],
                ["-i", "tun+", "-p", "udp", "--dport", "6969", "-j", "DROP"],
                ["-i", "tun+", "-p", "tcp", "--dport", "51413", "-j", "DROP"],
                ["-i", "tun+", "-p", "udp", "--dport", "51413", "-j", "DROP"],
            ):
                rules.append(spec)
            if c.get("block_torrent_dpi", True) and has_xt_string:
                for pat in TORRENT_STRINGS:
                    rules.append(["-i", "tun+", "-m", "string", "--string", pat, "--algo", "bm", "-j", "DROP"])
        for p in c.get("custom_blocked_ports") or []:
            try:
                pi = int(p)
            except (TypeError, ValueError):
                continue
            if 1 <= pi <= 65535:
                rules.append(["-i", "tun+", "-p", "tcp", "--dport", str(pi), "-j", "DROP"])
                rules.append(["-i", "tun+", "-p", "udp", "--dport", str(pi), "-j", "DROP"])
        return rules

    def sync_abuse_rules(self) -> dict[str, Any]:
        with self.lock:
            has_str = self.probe_xt_string()
            rules = self.build_abuse_rules(self.abuse, has_xt_string=has_str)
            chain = self.ABUSE_CHAIN
            if not rules:
                if self.run(["iptables", "-S", chain]).returncode == 0:
                    for _ in range(32):
                        if self.run(["iptables", "-D", "FORWARD", "-j", chain]).returncode != 0:
                            break
                    self.run(["iptables", "-F", chain])
                    self.run(["iptables", "-X", chain])
                return {"enabled": bool(self.abuse.get("enabled")), "rules": 0, "xt_string": has_str}

            if self.run(["iptables", "-S", chain]).returncode != 0:
                self.run(["iptables", "-N", chain])
            self.run(["iptables", "-F", chain])
            applied = 0
            for spec in rules:
                if self.run(["iptables", "-A", chain, *spec]).returncode == 0:
                    applied += 1

            # Position -j GASSLIGHT_ABUSE in FORWARD right after GL_PROXY_FW (if present) and before any -j ACCEPT
            fwd_out = self.run(["iptables", "-S", "FORWARD"]).stdout or ""
            fwd_rules = [ln.strip() for ln in fwd_out.splitlines() if ln.strip().startswith("-A FORWARD ")]
            jump_line = f"-A FORWARD -j {chain}"
            already_early = False
            if jump_line in fwd_rules:
                idx_jump = fwd_rules.index(jump_line)
                first_accept = next((i for i, l in enumerate(fwd_rules) if " -j ACCEPT" in l), len(fwd_rules))
                if idx_jump < first_accept:
                    already_early = True
            if not already_early:
                for _ in range(32):
                    if self.run(["iptables", "-D", "FORWARD", "-j", chain]).returncode != 0:
                        break
                insert_pos = "2" if fwd_rules and fwd_rules[0] == "-A FORWARD -j GL_PROXY_FW" else "1"
                self.run(["iptables", "-I", "FORWARD", insert_pos, "-j", chain])
            return {"enabled": True, "rules": applied, "xt_string": has_str}

    def get_abuse(self) -> dict[str, Any]:
        with self.lock:
            out = json.loads(json.dumps(self.abuse))
            out["xt_string"] = self._has_xt_string if self._has_xt_string is not None else False
            return out

    def save_abuse(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            ports_in = payload.get("custom_blocked_ports", self.abuse["custom_blocked_ports"])
            if isinstance(ports_in, str):
                ports_in = re.split(r"[,\s]+", ports_in.strip())
            clean_ports: list[int] = []
            for p in ports_in or []:
                if str(p).strip().isdigit():
                    pi = int(str(p).strip())
                    if 1 <= pi <= 65535 and pi not in clean_ports:
                        clean_ports.append(pi)
            self.abuse.update(
                enabled=bool(payload.get("enabled", self.abuse["enabled"])),
                block_smtp=bool(payload.get("block_smtp", self.abuse["block_smtp"])),
                block_smtp_alt=bool(payload.get("block_smtp_alt", self.abuse["block_smtp_alt"])),
                block_torrent=bool(payload.get("block_torrent", self.abuse["block_torrent"])),
                block_torrent_dpi=bool(payload.get("block_torrent_dpi", self.abuse["block_torrent_dpi"])),
                custom_blocked_ports=clean_ports,
            )
            self._save_json(self.abuse_file, self.abuse)
        sync_info = self.sync_abuse_rules()
        out = self.get_abuse()
        out.update(sync_info)
        return out

    # ------------------------------------------------------------------ Smart SNI Routing
    def smart_enabled(self) -> bool:
        return bool(self.smart.get("enabled"))

    def smart_domains_set(self) -> set[str]:
        with self.lock:
            out: set[str] = set()
            for key in self.smart.get("presets") or []:
                preset = SMART_PRESETS.get(key)
                if preset:
                    for d in preset.get("domains") or []:
                        nd = normalize_domain(d)
                        if nd:
                            out.add(nd)
            for d in self.smart.get("domains") or []:
                nd = normalize_domain(d)
                if nd:
                    out.add(nd)
            return out

    def smart_should_proxy(self, host: str | None) -> bool:
        with self.lock:
            if not self.smart.get("enabled"):
                return False
            if self.smart.get("mode") == "all":
                return True
            doms = self.smart_domains_set()
        return domain_matches(host, doms)

    def warp_proxy(self) -> dict[str, Any]:
        with self.lock:
            h = str(self.smart.get("warp_host") or "127.0.0.1").strip() or "127.0.0.1"
            p = max(1, min(65535, int(self.smart.get("warp_port") or 40000)))
        return {"type": "socks5", "host": h, "port": p, "user": "", "pw": "", "key": f"warp:{h}:{p}"}

    def smart_select_pool(self, exlist: list[dict[str, Any]], plist: list[dict[str, Any]]) -> list[dict[str, Any]]:
        with self.lock:
            target = self.smart.get("target", "auto")
        if target == "warp":
            return [self.warp_proxy()]
        if target == "exit":
            return list(exlist)
        if target == "proxy":
            return list(plist)
        if exlist:
            return list(exlist)
        if self.warp_status(timeout=0.3)["reachable"]:
            return [self.warp_proxy()]
        return list(plist)

    def warp_status(self, timeout: float = 0.8) -> dict[str, Any]:
        with self.lock:
            h = str(self.smart.get("warp_host") or "127.0.0.1").strip() or "127.0.0.1"
            p = max(1, min(65535, int(self.smart.get("warp_port") or 40000)))
        now = time.time()
        if now - self._warp_cache.get("checked", 0.0) < 5.0 and self._warp_cache.get("target") == (h, p):
            return dict(self._warp_cache)
        t0 = time.time()
        ok = False
        ms: int | None = None
        try:
            with socket.create_connection((h, p), timeout=timeout):
                ok = True
                ms = int((time.time() - t0) * 1000)
        except OSError:
            ok = False
        res = {"checked": now, "target": (h, p), "host": h, "port": p, "reachable": ok, "ms": ms}
        self._warp_cache = res
        return dict(res)

    def get_smart(self) -> dict[str, Any]:
        with self.lock:
            snap = json.loads(json.dumps(self.smart))
            snap["effective_domains_count"] = len(self.smart_domains_set())
            snap["presets_meta"] = {k: {"label": v["label"], "count": len(v["domains"])} for k, v in SMART_PRESETS.items()}
        ws = self.warp_status(timeout=0.5)
        snap["warp_reachable"] = ws["reachable"]
        snap["warp_ms"] = ws["ms"]
        return snap

    def save_smart(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            mode = str(payload.get("mode", self.smart["mode"])).strip().lower()
            if mode not in ("domains_only", "all"):
                mode = "domains_only"
            target = str(payload.get("target", self.smart["target"])).strip().lower()
            if target not in ("auto", "warp", "exit", "proxy"):
                target = "auto"
            warp_host = str(payload.get("warp_host", self.smart["warp_host"]) or "127.0.0.1").strip()
            if not _HOST_RE.match(warp_host):
                warp_host = "127.0.0.1"
            try:
                warp_port = max(1, min(65535, int(payload.get("warp_port", self.smart["warp_port"]))))
            except (TypeError, ValueError):
                warp_port = 40000
            presets = [p for p in (payload.get("presets", self.smart["presets"]) or []) if p in SMART_PRESETS]
            raw_doms = payload.get("domains", self.smart["domains"])
            if isinstance(raw_doms, str):
                raw_doms = re.split(r"[\s,]+", raw_doms.strip())
            clean_doms: list[str] = []
            bad_doms: list[str] = []
            for d in raw_doms or []:
                s = (d or "").strip()
                if not s or s.startswith("#"):
                    continue
                nd = normalize_domain(s)
                if nd:
                    if nd not in clean_doms:
                        clean_doms.append(nd)
                else:
                    bad_doms.append(s)

            ports_in = payload.get("ports", self.smart["ports"])
            if isinstance(ports_in, str):
                ports_in = re.split(r"[,\s]+", ports_in.strip())
            clean_ports: list[int] = []
            for p in ports_in or []:
                if str(p).strip().isdigit():
                    pi = int(str(p).strip())
                    if 1 <= pi <= 65535 and pi not in clean_ports:
                        clean_ports.append(pi)
            if not clean_ports:
                clean_ports = list(DEFAULT_SMART_PORTS)

            self.smart.update(
                enabled=bool(payload.get("enabled", self.smart["enabled"])),
                mode=mode,
                target=target,
                warp_host=warp_host,
                warp_port=warp_port,
                presets=presets,
                domains=clean_doms,
                all_users=bool(payload.get("all_users", self.smart["all_users"])),
                block_quic=bool(payload.get("block_quic", self.smart["block_quic"])),
                fallback_direct=bool(payload.get("fallback_direct", self.smart["fallback_direct"])),
                ports=clean_ports,
            )
            self._save_json(self.smart_file, self.smart)
        self.proxy_sync()
        out = self.get_smart()
        out["invalid_domains"] = bad_doms
        return out

    # ------------------------------------------------------------------ Multi-Remote Failover
    def get_remotes(self) -> dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.remotes))

    def save_remotes(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            raw_items = payload.get("remotes", self.remotes["remotes"])
            if isinstance(raw_items, str):
                raw_items = [x.strip() for x in re.split(r"[\r\n,]+", raw_items) if x.strip()]
            valid: list[str] = []
            invalid: list[str] = []
            for item in raw_items or []:
                s = str(item).strip()
                if not s or s.startswith("#"):
                    continue
                parsed = parse_backup_remote(s)
                if parsed:
                    if parsed["raw"] not in valid:
                        valid.append(parsed["raw"])
                else:
                    invalid.append(s)
            try:
                rmin = max(1, min(60, int(payload.get("connect_retry_min", self.remotes["connect_retry_min"]))))
            except (TypeError, ValueError):
                rmin = 2
            try:
                rmax = max(rmin, min(120, int(payload.get("connect_retry_max", self.remotes["connect_retry_max"]))))
            except (TypeError, ValueError):
                rmax = 5
            try:
                cto = max(3, min(60, int(payload.get("connect_timeout", self.remotes["connect_timeout"]))))
            except (TypeError, ValueError):
                cto = 10

            self.remotes.update(
                enabled=bool(payload.get("enabled", self.remotes["enabled"])),
                remotes=valid,
                remote_random=bool(payload.get("remote_random", self.remotes["remote_random"])),
                connect_retry_min=rmin,
                connect_retry_max=rmax,
                connect_timeout=cto,
            )
            self._save_json(self.remotes_file, self.remotes)
        out = self.get_remotes()
        out["invalid_remotes"] = invalid
        return out

    def apply_failover(self, ovpn_text: str, user: dict[str, Any] | None = None) -> str:
        with self.lock:
            cfg = dict(self.remotes)
        u = user or {}
        u_remotes = u.get("backup_remotes") or []
        u_port = int(u.get("port") or 1194)
        u_proto = str(u.get("proto") or "udp")
        return inject_failover_ovpn(ovpn_text, u_port, u_proto, cfg, u_remotes)

    # ------------------------------------------------------------------ Smart DNS
    def get_dns_state(self) -> dict[str, Any]:
        current = list(self.read_dns() or [])
        preset = "custom"
        for key, meta in DNS_PRESETS.items():
            if current == meta["servers"]:
                preset = key
                break
        return {"servers": current, "preset": preset, "presets": DNS_PRESETS}

    def apply_dns(self, preset_or_servers: str | list[str]) -> tuple[bool, str, list[str]]:
        if isinstance(preset_or_servers, str):
            key = preset_or_servers.strip().lower()
            if key in DNS_PRESETS:
                servers = list(DNS_PRESETS[key]["servers"])
            else:
                servers = []
                for token in re.split(r"[,\s]+", preset_or_servers.strip()):
                    if not token:
                        continue
                    try:
                        ipaddress.IPv4Address(token)
                    except ValueError:
                        return False, f"invalid IPv4 DNS: {token}", []
                    if token not in servers:
                        servers.append(token)
        else:
            servers = []
            for token in preset_or_servers or []:
                s = str(token).strip()
                try:
                    ipaddress.IPv4Address(s)
                except ValueError:
                    return False, f"invalid IPv4 DNS: {s}", []
                if s not in servers:
                    servers.append(s)

        if not (1 <= len(servers) <= 4):
            return False, "enter 1 to 4 valid IPv4 DNS addresses", []

        current = list(self.read_dns() or [])
        if current == servers:
            return True, "unchanged", servers

        ok, err = self.set_dns(servers)
        if not ok:
            return False, err or "failed to write DNS config", []
        threading.Thread(target=self.restart_for_dns, daemon=True).start()
        return True, "updated", servers

    # ------------------------------------------------------------------ Summary
    def status_summary(self) -> dict[str, Any]:
        with self.lock:
            bypass_sum = self.compute_bypass_routes()
            return {
                "bypass": {
                    "enabled": bool(self.bypass.get("enabled")),
                    "routes": bypass_sum["pushed_count"],
                    "truncated": bypass_sum["truncated"],
                    "presets": list(self.bypass.get("presets") or []),
                },
                "abuse": {
                    "enabled": bool(self.abuse.get("enabled")),
                    "block_smtp": bool(self.abuse.get("block_smtp")),
                    "block_torrent": bool(self.abuse.get("block_torrent")),
                },
                "smart": {
                    "enabled": bool(self.smart.get("enabled")),
                    "mode": self.smart.get("mode"),
                    "target": self.smart.get("target"),
                    "domains": len(self.smart_domains_set()),
                },
                "dns": self.get_dns_state()["servers"],
                "remotes": {
                    "enabled": bool(self.remotes.get("enabled")),
                    "count": len(self.remotes.get("remotes") or []),
                },
            }
