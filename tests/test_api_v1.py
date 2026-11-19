"""Offline unit tests for GassLight REST API v1 (panel/api_v1.py)."""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
import re
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _ensure_flask_stub() -> None:
    """Provide a minimal Flask + Werkzeug test shim when Flask is absent locally."""
    try:
        import flask  # noqa: F401
        return
    except ImportError:
        pass

    werkzeug = types.ModuleType("werkzeug")
    security = types.ModuleType("werkzeug.security")
    security.generate_password_hash = lambda pw: "pbkdf2:" + hashlib.sha256(pw.encode()).hexdigest()
    security.check_password_hash = lambda h, pw: hmac.compare_digest(h, "pbkdf2:" + hashlib.sha256(pw.encode()).hexdigest())
    sys.modules["werkzeug"] = werkzeug
    sys.modules["werkzeug.security"] = security

    flask = types.ModuleType("flask")

    class _Req:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.args: dict[str, str] = {}
            self.form: dict[str, str] = {}
            self.method: str = "GET"
            self.remote_addr: str = "127.0.0.1"
            self._json: object = None

        def get_json(self, silent: bool = False):
            return self._json

    req = _Req()
    sess: dict[str, object] = {}

    class _Response:
        def __init__(self, data: object, status: int = 200) -> None:
            self.data = data
            self.status_code = status

        def get_json(self):
            return self.data

    class _MiniApp:
        def __init__(self) -> None:
            self.routes: list[tuple[str, list[str], object]] = []

        def route(self, rule: str, methods: list[str] | None = None):
            meths = methods or ["GET"]

            def deco(fn):
                self.routes.append((rule, meths, fn))
                return fn

            return deco

        def dispatch(self, method: str, path: str, json_body=None, headers=None, args=None):
            req.method = method
            req._json = json_body
            req.headers = headers or {}
            req.args = args or {}
            req.form = {}
            for rule, meths, fn in self.routes:
                if method not in meths:
                    continue
                regex = "^" + re.sub(r"<([^>]+)>", r"(?P<\1>[^/]+)", rule) + "$"
                m = re.match(regex, path)
                if m:
                    res = fn(**m.groupdict())
                    if isinstance(res, tuple):
                        body, code = res
                    else:
                        body, code = res, 200
                    if isinstance(body, _Response):
                        return _Response(body.data, code)
                    return _Response(body, code)
            return _Response({"error": "not found"}, 404)

    flask.Flask = lambda *a, **kw: _MiniApp()
    flask.request = req
    flask.session = sess
    flask.jsonify = lambda *a, **kw: _Response(dict(kw) if kw else (a[0] if a else {}))
    flask.send_file = lambda bio, **kw: _Response(bio.read(), 200)
    sys.modules["flask"] = flask
    flask._app_cls = _MiniApp
    flask._sess = sess


_ensure_flask_stub()

from flask import Flask, session  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402
from panel.api_v1 import register_api_v1  # noqa: E402


class ApiV1TestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = self.tmp.name
        self.ovpn_dir = os.path.join(self.base, "ovpn")
        os.makedirs(self.ovpn_dir, exist_ok=True)
        self.state: dict[str, object] = {"users": []}
        self.usage: dict[str, dict] = {}
        self.conn: dict[str, dict] = {}
        self.rates: dict[str, tuple[int, int]] = {}
        self.enforced = 0
        self.synced = 0
        self.cmds: list[list[str]] = []

        import threading

        pw_hash = generate_password_hash("secret123")
        auth_data = {"users": [{"username": "gasslight", "hash": pw_hash}]}

        def load_state():
            return json.loads(json.dumps(self.state))

        def save_state(st):
            self.state = json.loads(json.dumps(st))

        def create_instance(name, port, sub, proto="udp"):
            return True, None

        def edit_instance(u, new_id, new_port, proto):
            u["id"], u["port"], u["proto"] = new_id, new_port, proto
            return True, None

        def remove_instance(u):
            return None

        def enforce_blocks():
            self.enforced += 1
            for u in self.state["users"]:
                if u.get("disabled"):
                    u["blocked"] = "manual"
                elif u.get("blocked") == "manual":
                    u["blocked"] = None

        def proxy_sync_rules():
            self.synced += 1

        def reset_usage(u):
            self.usage[u["name"]] = {"up": 0, "down": 0, "du": 0, "dd": 0}

        def build_ovpn(name, port, path, proto):
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"client\nproto {proto}\nremote 1.2.3.4 {port}\n<ca>\nCERT\n</ca>\n")

        self.app = Flask(__name__)
        deps = {
            "BASE": self.base,
            "OVPN_DIR": self.ovpn_dir,
            "APP_NAME": "GassLight",
            "LOCK": threading.RLock(),
            "SLOCK": threading.Lock(),
            "FAILS": {},
            "DUMMY_HASH": pw_hash,
            "NAME_RE": re.compile(r"^[A-Za-z0-9_-]{1,32}$"),
            "USAGE": self.usage,
            "CONN": self.conn,
            "RATES": self.rates,
            "SYS": {"cpu": 12.5, "mem": {"used": 100, "total": 1000}},
            "load_auth": lambda: auth_data,
            "current_admin": lambda: session.get("user") if session.get("ok") else None,
            "load_state": load_state,
            "save_state": save_state,
            "daily_bytes": lambda rec: (rec.get("du", 0), rec.get("dd", 0)),
            "portal_token": lambda u: "tok_" + u["name"],
            "host_ready": lambda: True,
            "next_port": lambda st: max([u["port"] for u in st["users"]] + [2221]) + 1,
            "port_error": lambda st, port, proto: "port in use" if any(u["port"] == port and u.get("proto") == proto for u in st["users"]) else None,
            "ovpn_addr_valid": lambda a: "." in a,
            "free_id": lambda st: max([u["id"] for u in st["users"]] + [0]) + 1,
            "new_subnet": lambda idx, st: f"10.8.{idx}",
            "create_instance": create_instance,
            "edit_instance": edit_instance,
            "remove_instance": remove_instance,
            "save_speed": lambda: None,
            "apply_speed": lambda u: True,
            "enforce_blocks": enforce_blocks,
            "proxy_sync_rules": proxy_sync_rules,
            "reset_usage": reset_usage,
            "build_ovpn": build_ovpn,
            "ovpn_bytes": lambda path, u: __import__("pathlib").Path(path).read_bytes(),
            "feature_state": lambda: ("off", "off"),
            "run": lambda cmd: self.cmds.append(cmd),
        }
        register_api_v1(self.app, deps)
        session.clear()

    def tearDown(self) -> None:
        session.clear()
        self.tmp.cleanup()

    def call(self, method: str, path: str, json_body=None, headers=None, args=None):
        return self.app.dispatch(method, path, json_body=json_body, headers=headers, args=args)

    def test_auth_crud_and_token_flow(self) -> None:
        # Unauthenticated rejected
        r = self.call("GET", "/api/v1/users")
        self.assertEqual(r.status_code, 401)

        # Login with bad password rejected
        r = self.call("POST", "/api/v1/auth/login", json_body={"username": "gasslight", "password": "wrong"})
        self.assertEqual(r.status_code, 401)

        # Valid login
        r = self.call("POST", "/api/v1/auth/login", json_body={"username": "gasslight", "password": "secret123"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

        # Create API token & clear session cookie to test pure Bearer auth
        tok_resp = self.call("POST", "/api/v1/auth/tokens", json_body={"label": "telegram-bot"})
        self.assertEqual(tok_resp.status_code, 201)
        token_data = tok_resp.get_json()
        bearer = {"Authorization": "Bearer " + token_data["token"]}
        session.clear()

        # Create user via Bearer token
        c_resp = self.call(
            "POST",
            "/api/v1/users",
            json_body={"name": "ovpn_u1", "proto": "tcp", "days": 30, "total": 25.5},
            headers=bearer,
        )
        self.assertEqual(c_resp.status_code, 201)
        u = c_resp.get_json()["user"]
        self.assertEqual(u["port"], 2222)
        self.assertEqual(u["proto"], "tcp")
        self.assertEqual(u["limit_total"], 25.5)
        self.assertTrue(u["enable"])

        # Duplicate user rejected with 409
        dup = self.call("POST", "/api/v1/users", json_body={"name": "ovpn_u1", "proto": "tcp"}, headers=bearer)
        self.assertEqual(dup.status_code, 409)

        # Partial PATCH preserves proto/port while updating total & speed
        p_resp = self.call("PATCH", "/api/v1/users/ovpn_u1", json_body={"total": 50, "speed": 10}, headers=bearer)
        self.assertEqual(p_resp.status_code, 200)
        pu = p_resp.get_json()["user"]
        self.assertEqual(pu["limit_total"], 50.0)
        self.assertEqual(pu["speed"], 10.0)
        self.assertEqual(pu["port"], 2222)

        # Disable / Enable manual toggle
        d_resp = self.call("POST", "/api/v1/users/ovpn_u1/disable", headers=bearer)
        self.assertEqual(d_resp.status_code, 200)
        self.assertTrue(d_resp.get_json()["user"]["disabled"])
        self.assertEqual(d_resp.get_json()["user"]["blocked"], "manual")
        self.assertFalse(d_resp.get_json()["user"]["enable"])

        e_resp = self.call("POST", "/api/v1/users/ovpn_u1/enable", headers=bearer)
        self.assertEqual(e_resp.status_code, 200)
        self.assertFalse(e_resp.get_json()["user"]["disabled"])
        self.assertIsNone(e_resp.get_json()["user"]["blocked"])
        self.assertTrue(e_resp.get_json()["user"]["enable"])

        # OVPN profile JSON download + Extend + Reset + Status
        o_resp = self.call("GET", "/api/v1/users/ovpn_u1/ovpn", headers=bearer, args={"format": "json"})
        self.assertEqual(o_resp.status_code, 200)
        self.assertIn("remote 1.2.3.4 2222", o_resp.get_json()["content"])

        ex_resp = self.call("POST", "/api/v1/users/ovpn_u1/extend", json_body={"days": 15}, headers=bearer)
        self.assertEqual(ex_resp.status_code, 200)
        rst_resp = self.call("POST", "/api/v1/users/ovpn_u1/reset", headers=bearer)
        self.assertEqual(rst_resp.status_code, 200)

        st_resp = self.call("GET", "/api/v1/status", headers=bearer)
        self.assertEqual(st_resp.status_code, 200)
        self.assertEqual(st_resp.get_json()["api_version"], "1.1")
        self.assertEqual(st_resp.get_json()["users_total"], 1)

        # min_port allocates sequentially above existing user ports (and above floor)
        m_resp = self.call(
            "POST",
            "/api/v1/users",
            json_body={"name": "ovpn_u2", "proto": "udp", "min_port": 3000},
            headers=bearer,
        )
        self.assertEqual(m_resp.status_code, 201)
        self.assertEqual(m_resp.get_json()["user"]["port"], 3000)

        m2_resp = self.call(
            "POST",
            "/api/v1/users",
            json_body={"name": "ovpn_u3", "proto": "tcp", "min_port": 2222},
            headers=bearer,
        )
        self.assertEqual(m2_resp.status_code, 201)
        self.assertEqual(m2_resp.get_json()["user"]["port"], 3001)

        # Cleanup extra users
        self.assertEqual(self.call("DELETE", "/api/v1/users/ovpn_u2", headers=bearer).status_code, 200)
        self.assertEqual(self.call("DELETE", "/api/v1/users/ovpn_u3", headers=bearer).status_code, 200)

        # Delete user
        del_resp = self.call("DELETE", "/api/v1/users/ovpn_u1", headers=bearer)
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(self.call("GET", "/api/v1/users/ovpn_u1", headers=bearer).status_code, 404)

        # Revoke Bearer token
        rev = self.call("DELETE", "/api/v1/auth/tokens", json_body={"id": token_data["id"]}, headers=bearer)
        self.assertEqual(rev.status_code, 200)
        self.assertEqual(self.call("GET", "/api/v1/users", headers=bearer).status_code, 401)

    def test_all_required_deps_exist_in_real_panel_py(self) -> None:
        with open(os.path.join(ROOT, "panel", "panel.py"), encoding="utf-8") as f:
            panel_src = f.read()
        with open(os.path.join(ROOT, "panel", "api_v1.py"), encoding="utf-8") as f:
            api_src = f.read()
        required_keys = sorted(set(re.findall(r'deps\["([^"]+)"\]', api_src)))
        missing = [
            k for k in required_keys
            if not re.search(rf'(?:^def {re.escape(k)}\b|^{re.escape(k)}\s*=)', panel_src, re.M)
        ]
        self.assertEqual(missing, [], f"api_v1.py references missing panel.py symbols: {missing}")


if __name__ == "__main__":
    unittest.main()
