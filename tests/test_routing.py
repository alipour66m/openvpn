"""Offline & loopback unit/integration tests for panel/routing.py and multi-device accounting."""

from __future__ import annotations

import os
import socket
import struct
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from panel.routing import (  # noqa: E402
    RoutingManager,
    collapse_and_cap_cidrs,
    conf_with_max_clients,
    domain_matches,
    extract_http_host,
    extract_sni_or_host,
    extract_tls_sni,
    inject_failover_ovpn,
    normalize_domain,
    parse_backup_remote,
    parse_cidr_list,
    patch_marked_block,
    render_bypass_block,
)


def build_tls_client_hello(server_name: str) -> bytes:
    """Build a valid RFC 5246/6066 TLS 1.2 ClientHello with an SNI extension."""
    name_bytes = server_name.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(name_bytes)) + name_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    hello_body = (
        b"\x03\x03"          # TLS 1.2
        + (b"\xaa" * 32)     # random
        + b"\x00"            # session id len = 0
        + b"\x00\x02\x13\x01"  # cipher suites (1 suite)
        + b"\x01\x00"        # compression methods (null)
        + extensions
    )
    handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class RoutingHelpersTestCase(unittest.TestCase):
    def test_tls_sni_and_http_host_extraction(self) -> None:
        pkt = build_tls_client_hello("api.openai.com")
        self.assertEqual(extract_tls_sni(pkt), "api.openai.com")
        self.assertEqual(extract_sni_or_host(pkt), "api.openai.com")

        # Truncated or garbage packets return None safely without raising
        for bad in (b"", b"\x16\x03\x01", pkt[:25], b"SSH-2.0-OpenSSH_9.0\r\n"):
            self.assertIsNone(extract_tls_sni(bad))

        http_req = b"GET /v1/models HTTP/1.1\r\nHost: Claude.AI:80\r\nUser-Agent: test\r\n\r\n"
        self.assertEqual(extract_http_host(http_req), "claude.ai")
        self.assertEqual(extract_sni_or_host(http_req), "claude.ai")

    def test_domain_normalization_and_matching(self) -> None:
        self.assertEqual(normalize_domain("HTTPS://Chat.OpenAI.com:443/chat"), "chat.openai.com")
        self.assertEqual(normalize_domain("*.anthropic.com"), "anthropic.com")
        self.assertIsNone(normalize_domain("1.2.3.4"))
        self.assertIsNone(normalize_domain("localhost"))

        rules = ["openai.com", "claude.ai"]
        self.assertTrue(domain_matches("openai.com", rules))
        self.assertTrue(domain_matches("api.openai.com", rules))
        self.assertTrue(domain_matches("a.b.claude.ai.", rules))
        self.assertFalse(domain_matches("notopenai.com", rules))
        self.assertFalse(domain_matches(None, rules))

    def test_cidr_validation_collapse_and_ios_cap(self) -> None:
        valid, invalid = parse_cidr_list([
            "5.200.1.0/24",
            "5.200.0.0/24",
            "0.0.0.0/0",     # unsafe blanket override
            "127.0.0.0/8",   # loopback
            "not-an-ip",
        ])
        self.assertEqual(valid, ["5.200.1.0/24", "5.200.0.0/24"])
        self.assertEqual(invalid, ["0.0.0.0/0", "127.0.0.0/8", "not-an-ip"])

        collapsed = collapse_and_cap_cidrs(["5.200.0.0/24", "5.200.1.0/24"], max_routes=250)
        self.assertEqual(collapsed["routes"], [("5.200.0.0", "255.255.254.0", "5.200.0.0/23")])
        self.assertFalse(collapsed["truncated"])

        many = [f"5.201.{i // 256}.{i % 256}/32" for i in range(0, 600, 2)]
        capped = collapse_and_cap_cidrs(many, max_routes=100)
        self.assertEqual(capped["pushed_count"], 100)
        self.assertTrue(capped["truncated"])

    def test_ccd_patching_and_max_clients_conf(self) -> None:
        block = render_bypass_block([("5.200.0.0", "255.255.254.0", "5.200.0.0/23")])
        patched = patch_marked_block("# custom line\n", "# BEGIN GASSLIGHT-BYPASS", "# END GASSLIGHT-BYPASS", block)
        self.assertIn('push "route 5.200.0.0 255.255.254.0 net_gateway"', patched)
        # Re-patching is idempotent
        patched2 = patch_marked_block(patched, "# BEGIN GASSLIGHT-BYPASS", "# END GASSLIGHT-BYPASS", block)
        self.assertEqual(patched, patched2)
        # Disabling removes only marked block
        cleared = patch_marked_block(patched, "# BEGIN GASSLIGHT-BYPASS", "# END GASSLIGHT-BYPASS", "")
        self.assertEqual(cleared, "# custom line\n")

        base_conf = "port 2222\nproto tcp\nserver 10.101.0.0 255.255.255.0\nifconfig-pool-persist ipp-ali.txt\n"
        multi = conf_with_max_clients(base_conf, "ali", 3)
        self.assertIn("duplicate-cn", multi)
        self.assertIn("max-clients 3", multi)
        self.assertNotIn("ifconfig-pool-persist", multi)

        single = conf_with_max_clients(multi, "ali", 1)
        self.assertNotIn("duplicate-cn", single)
        self.assertNotIn("max-clients", single)
        self.assertIn("ifconfig-pool-persist ipp-ali.txt", single)

    def test_failover_ovpn_injection(self) -> None:
        base_ovpn = "client\ndev tun\nproto tcp\nremote 185.10.20.1 2222\nresolv-retry infinite\n<ca>\nCERT\n</ca>\n"
        disabled_cfg = {"enabled": False, "remotes": ["185.10.20.2:443"], "remote_random": False}
        self.assertEqual(inject_failover_ovpn(base_ovpn, 2222, "tcp", disabled_cfg), base_ovpn)

        cfg = {
            "enabled": True,
            "remotes": ["185.10.20.1:2222", "ir2.example.com", "ir3.example.com:443:udp"],
            "remote_random": True,
            "connect_retry_min": 2,
            "connect_retry_max": 5,
            "connect_timeout": 9,
        }
        out = inject_failover_ovpn(base_ovpn, 2222, "tcp", cfg)
        self.assertIn("remote 185.10.20.1 2222\nremote ir2.example.com 2222\nremote ir3.example.com 443 udp\n", out)
        self.assertEqual(out.count("remote 185.10.20.1 2222"), 1)
        self.assertIn("connect-retry 2 5", out)
        self.assertIn("connect-timeout 9", out)
        self.assertIn("remote-random", out)
        self.assertIsNotNone(parse_backup_remote("udp://1.2.3.4:1194"))
        self.assertIsNone(parse_backup_remote("bad host!!"))


class RoutingManagerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = os.path.join(self.tmp.name, "panel")
        self.sdir = os.path.join(self.tmp.name, "server")
        os.makedirs(self.base, exist_ok=True)
        os.makedirs(os.path.join(self.sdir, "ccd-ali"), exist_ok=True)
        self.cmds: list[list[str]] = []
        self.dns_servers = ["1.1.1.1", "8.8.8.8"]
        self.dns_restarts = 0
        self.proxy_syncs = 0
        self.fwd_lines = [
            "-P FORWARD ACCEPT",
            "-A FORWARD -j GL_PROXY_FW",
            "-A FORWARD -s 10.101.0.0/24 -j ACCEPT",
        ]
        self.state = {"users": [{"name": "ali", "id": 1, "port": 2222, "subnet": "10.101.0", "proto": "tcp"}]}

        class _Res:
            def __init__(self, code=0, stdout=""):
                self.returncode = code
                self.stdout = stdout

        def fake_run(cmd):
            self.cmds.append(list(cmd))
            if cmd[:3] == ["iptables", "-S", "FORWARD"]:
                return _Res(0, "\n".join(self.fwd_lines))
            if cmd[:3] == ["iptables", "-S", "GASSLIGHT_ABUSE"]:
                return _Res(0 if any("GASSLIGHT_ABUSE" in l for l in self.fwd_lines) else 1, "")
            if cmd[:4] == ["iptables", "-I", "FORWARD", "2"]:
                self.fwd_lines.insert(2, f"-A FORWARD -j {cmd[5]}")
            return _Res(0, "")

        self.rm = RoutingManager(
            base_dir=self.base,
            server_dir=self.sdir,
            run_fn=fake_run,
            load_state_fn=lambda: self.state,
            set_dns_fn=lambda s: (not self.dns_servers.__setitem__(slice(None), list(s)), "") if isinstance(s, list) else (True, ""),
            read_dns_fn=lambda: list(self.dns_servers),
            restart_for_dns_fn=lambda: setattr(self, "dns_restarts", self.dns_restarts + 1),
            proxy_sync_fn=lambda: setattr(self, "proxy_syncs", self.proxy_syncs + 1),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_bypass_resolve_and_ccd_sync(self) -> None:
        res = self.rm.save_bypass(
            {
                "enabled": True,
                "presets": ["iran_banks"],
                "custom_cidrs": ["194.225.0.0/16"],
                "custom_domains": ["mybank.ir"],
                "max_routes": 250,
            },
            resolve_now=True,
            resolver_fn=lambda d: ["5.200.10.20"] if "shaparak" in d or d == "mybank.ir" else [],
        )
        self.assertTrue(res["enabled"])
        self.assertGreaterEqual(res["route_count"], 2)
        ccd_txt = open(os.path.join(self.sdir, "ccd-ali", "ali"), encoding="utf-8").read()
        self.assertIn('push "route 194.225.0.0 255.255.0.0 net_gateway"', ccd_txt)
        self.assertIn('push "route 5.200.10.20 255.255.255.255 net_gateway"', ccd_txt)

        # Turn off bypass -> strips routes cleanly
        res_off = self.rm.save_bypass({"enabled": False})
        self.assertEqual(res_off["route_count"], 0)
        ccd_txt2 = open(os.path.join(self.sdir, "ccd-ali", "ali"), encoding="utf-8").read()
        self.assertNotIn("GASSLIGHT-BYPASS", ccd_txt2)

    def test_abuse_rules_with_and_without_xt_string_and_placement(self) -> None:
        res = self.rm.save_abuse({
            "enabled": True,
            "block_smtp": True,
            "block_smtp_alt": True,
            "block_torrent": True,
            "block_torrent_dpi": True,
            "custom_blocked_ports": [2525],
        })
        self.assertTrue(res["enabled"])
        self.assertGreater(res["rules"], 10)
        # Inserted at pos 2 (right after GL_PROXY_FW, before user ACCEPT)
        self.assertIn(["iptables", "-I", "FORWARD", "2", "-j", "GASSLIGHT_ABUSE"], self.cmds)

        # Fallback without xt_string produces port-only rules cleanly
        no_dpi = self.rm.build_abuse_rules(self.rm.abuse, has_xt_string=False)
        self.assertFalse(any("string" in r for r in no_dpi))
        self.assertTrue(any("6881:6889" in r for r in no_dpi))

    def test_smart_routing_and_loopback_sni_dispatch(self) -> None:
        self.rm.save_smart({
            "enabled": True,
            "mode": "domains_only",
            "target": "warp",
            "presets": ["ai"],
            "domains": ["custom-ai.example"],
        })
        self.assertTrue(self.rm.smart_should_proxy("chat.openai.com"))
        self.assertTrue(self.rm.smart_should_proxy("sub.custom-ai.example"))
        self.assertFalse(self.rm.smart_should_proxy("google.com"))
        self.assertFalse(self.rm.smart_should_proxy("notopenai.com"))

        # Real TCP loopback integration: mock SOCKS5 server + mock Direct echo server
        socks_hosts: list[str] = []
        direct_hits: list[bytes] = []

        def run_socks5_server(srv_sock: socket.socket) -> None:
            while True:
                try:
                    conn, _ = srv_sock.accept()
                except OSError:
                    break
                try:
                    with conn:
                        conn.settimeout(3)
                        greet = conn.recv(16)
                        if not greet:
                            continue
                        conn.sendall(b"\x05\x00")
                        hdr = conn.recv(4)
                        if len(hdr) < 4:
                            continue
                        atyp = hdr[3]
                        if atyp == 3:
                            hlen = conn.recv(1)[0]
                            host = conn.recv(hlen).decode("ascii")
                        else:
                            host = socket.inet_ntoa(conn.recv(4))
                        conn.recv(2)
                        socks_hosts.append(host)
                        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                        payload = conn.recv(4096)
                        conn.sendall(b"SOCKS5:" + payload)
                except OSError:
                    continue

        def run_direct_server(srv_sock: socket.socket) -> None:
            while True:
                try:
                    conn, _ = srv_sock.accept()
                except OSError:
                    break
                with conn:
                    payload = conn.recv(4096)
                    direct_hits.append(payload)
                    conn.sendall(b"DIRECT:" + payload)

        s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_sock.bind(("127.0.0.1", 0))
        s_sock.listen(5)
        s_port = s_sock.getsockname()[1]

        d_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        d_sock.bind(("127.0.0.1", 0))
        d_sock.listen(5)
        d_port = d_sock.getsockname()[1]

        t1 = threading.Thread(target=run_socks5_server, args=(s_sock,), daemon=True)
        t2 = threading.Thread(target=run_direct_server, args=(d_sock,), daemon=True)
        t1.start()
        t2.start()

        try:
            self.rm.save_smart({"warp_host": "127.0.0.1", "warp_port": s_port, "target": "warp"})
            pool = self.rm.smart_select_pool([], [])
            self.assertEqual(pool[0]["port"], s_port)

            for sni, expected_prefix in (("api.openai.com", b"SOCKS5:"), ("example.com", b"DIRECT:")):
                pkt = build_tls_client_hello(sni)
                host = extract_sni_or_host(pkt)
                if self.rm.smart_should_proxy(host):
                    p = pool[0]
                    up = socket.create_connection((p["host"], p["port"]), timeout=3)
                    up.sendall(b"\x05\x01\x00")
                    self.assertEqual(up.recv(2), b"\x05\x00")
                    hb = host.encode("ascii")
                    up.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", 443))
                    self.assertEqual(up.recv(10)[1], 0)
                else:
                    up = socket.create_connection(("127.0.0.1", d_port), timeout=3)
                up.sendall(pkt)
                echoed = up.recv(4096)
                up.close()
                self.assertEqual(echoed, expected_prefix + pkt)

            self.assertEqual(socks_hosts, ["api.openai.com"])
            self.assertEqual(len(direct_hits), 1)
        finally:
            s_sock.close()
            d_sock.close()

    def test_multi_session_accounting_summation(self) -> None:
        # Execute account_mgmt + reset_usage directly on an isolated namespace from panel.py
        import ast

        panel_src = open(os.path.join(ROOT, "panel", "panel.py"), encoding="utf-8").read()
        tree = ast.parse(panel_src)
        want = {"_add_usage", "account_mgmt", "reset_usage", "lease_ip"}
        snippets = [ast.get_source_segment(panel_src, node) for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name in want]
        ns = {
            "USAGE": {},
            "CONN": {},
            "RATES": {},
            "ACTIVE_WINDOW": 45,
            "SERVER_DIR": self.sdir,
            "SLOCK": threading.Lock(),
            "time": __import__("time"),
            "read_user_counters": lambda: {},
        }
        exec("\n\n".join(snippets), ns)
        ns["USAGE"]["ali"] = {"up": 100, "down": 200, "d": "2026-11-19", "du": 10, "dd": 20, "mt": 1000.0,
                              "sk": "0:950", "sr": 50, "st": 80}
        u = {"name": "ali", "subnet": "10.101.0"}

        # First tick: legacy session continues (+100 rx, +200 tx) AND second device connects (since >= mt - 5)
        rows1 = [
            {"cid": "0", "ip": "10.101.0.2", "real_ip": "1.1.1.1:1111", "rx": 150, "tx": 280, "since": 950},
            {"cid": "1", "ip": "10.101.0.3", "real_ip": "2.2.2.2:2222", "rx": 300, "tx": 400, "since": 1002},
        ]
        ns["account_mgmt"](u, rows1, 2.0, 1002.0, "2026-11-19")
        self.assertEqual(ns["USAGE"]["ali"]["up"], 100 + 100 + 300)
        self.assertEqual(ns["USAGE"]["ali"]["down"], 200 + 200 + 400)
        self.assertTrue(ns["CONN"]["ali"]["online"])
        self.assertEqual(ns["CONN"]["ali"]["online_count"], 2)
        self.assertEqual(ns["CONN"]["ali"]["ips"], ["10.101.0.2", "10.101.0.3"])

        # Reset usage while 2 sessions remain connected -> baselines preserved, no double-count on next tick
        ns["reset_usage"](u)
        self.assertEqual(ns["USAGE"]["ali"]["up"], 0)
        rows2 = [
            {"cid": "0", "ip": "10.101.0.2", "real_ip": "1.1.1.1:1111", "rx": 200, "tx": 300, "since": 950},
            {"cid": "1", "ip": "10.101.0.3", "real_ip": "2.2.2.2:2222", "rx": 350, "tx": 450, "since": 1002},
        ]
        ns["account_mgmt"](u, rows2, 2.0, 1004.0, "2026-11-19")
        self.assertEqual(ns["USAGE"]["ali"]["up"], 50 + 50)
        self.assertEqual(ns["USAGE"]["ali"]["down"], 20 + 50)


if __name__ == "__main__":
    unittest.main()
