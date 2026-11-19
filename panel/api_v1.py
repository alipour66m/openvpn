"""REST API v1 blueprint/routes for the GassLight OpenVPN panel."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import secrets
import time
from functools import wraps
from typing import Any, Callable

from flask import jsonify, request, send_file, session
from werkzeug.security import check_password_hash


def register_api_v1(app: Any, deps: dict[str, Any]) -> None:
    """Attach REST API v1 endpoints (/api/v1/*) to the Flask app using panel helpers."""
    base_dir = deps["BASE"]
    api_keys_file = os.path.join(base_dir, "api_keys.json")
    lock = deps["LOCK"]
    slock = deps["SLOCK"]
    fails = deps["FAILS"]

    def _load_keys() -> list[dict[str, Any]]:
        if not os.path.exists(api_keys_file):
            return []
        try:
            with open(api_keys_file, encoding="utf-8") as f:
                data = json.load(f)
            return data.get("keys", []) if isinstance(data, dict) else []
        except Exception:
            return []

    def _save_keys(keys: list[dict[str, Any]]) -> None:
        tmp = api_keys_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"keys": keys}, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, api_keys_file)

    def _extract_token() -> str:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return (request.headers.get("X-API-Key") or "").strip()

    def _token_actor() -> str | None:
        raw = _extract_token()
        if not raw:
            return None
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        for entry in _load_keys():
            if hmac.compare_digest(entry.get("hash", ""), digest):
                return entry.get("owner") or "api"
        return None

    def _json_body() -> dict[str, Any]:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def _err(message: str, code: int = 400, detail: str | None = None):
        payload: dict[str, Any] = {"ok": False, "error": message}
        if detail:
            payload["detail"] = detail
        return jsonify(payload), code

    def api_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*a: Any, **kw: Any) -> Any:
            if deps["current_admin"]() or _token_actor():
                return fn(*a, **kw)
            return _err("authentication required", 401)

        return wrapper

    def _serialize_user(u: dict[str, Any], include_portal: bool = True) -> dict[str, Any]:
        name = u["name"]
        with slock:
            rec = dict(deps["USAGE"].get(name, {}))
            cn = dict(deps["CONN"].get(name, {}))
            ru, rd = deps["RATES"].get(name, (0, 0))
            du, dd = deps["daily_bytes"](rec)
        portal_fn = deps.get("portal_token")
        portal_token = (portal_fn(u) if callable(portal_fn) else u.get("token")) if include_portal else None
        blocked = u.get("blocked")
        disabled = bool(u.get("disabled"))
        expires = u.get("expires")
        is_expired = bool(expires and float(expires) <= time.time())
        return {
            "id": u["id"],
            "name": name,
            "port": u["port"],
            "proto": u.get("proto", "udp"),
            "created": u["created"],
            "expires": expires,
            "is_expired": is_expired,
            "up": rec.get("up", 0),
            "down": rec.get("down", 0),
            "day_up": du,
            "day_down": dd,
            "speed": u.get("speed"),
            "limit_daily": u.get("limit_daily"),
            "limit_total": u.get("limit_total"),
            "disabled": disabled,
            "blocked": blocked,
            "enable": (not disabled) and (blocked is None) and (not is_expired),
            "online": bool(cn.get("online")),
            "ip": cn.get("ip"),
            "last": cn.get("last"),
            "since": cn.get("since"),
            "rate_up": ru,
            "rate_down": rd,
            "ovpn_addr": u.get("ovpn_addr"),
            "px": bool(u.get("px")),
            "ex": bool(u.get("ex")),
            "portal_token": portal_token,
        }

    @app.route("/api/v1/auth/login", methods=["POST"])
    def api_v1_login():
        ip = request.remote_addr or "unknown"
        cnt, until = fails.get(ip, (0, 0))
        if until > time.time():
            return _err("too many failed login attempts", 429)
        body = _json_body()
        uname = str(body.get("username") or request.form.get("username") or "").strip()
        pw = str(body.get("password") or request.form.get("password") or "")
        adm = next((a for a in deps["load_auth"]()["users"] if a["username"] == uname), None)
        good = check_password_hash(adm["hash"] if adm else deps["DUMMY_HASH"], pw)
        if adm and good:
            fails.pop(ip, None)
            session.clear()
            session["ok"], session["user"] = True, uname
            return jsonify(ok=True, user=uname)
        cnt += 1
        fails[ip] = (cnt, time.time() + 300 if cnt >= 5 else 0)
        return _err("invalid credentials", 401)

    @app.route("/api/v1/auth/tokens", methods=["GET", "POST", "DELETE"])
    @api_auth
    def api_v1_tokens():
        if request.method == "GET":
            keys = [{"id": k["id"], "label": k.get("label", ""), "owner": k.get("owner", "admin"), "created": k.get("created")} for k in _load_keys()]
            return jsonify(ok=True, tokens=keys)
        if request.method == "POST":
            body = _json_body()
            label = str(body.get("label") or "bot").strip()[:64] or "bot"
            owner = deps["current_admin"]() or _token_actor() or "admin"
            raw = "gl_" + secrets.token_urlsafe(32)
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            key_id = secrets.token_hex(6)
            with lock:
                keys = _load_keys()
                keys.append({"id": key_id, "label": label, "owner": owner, "hash": digest, "created": int(time.time())})
                _save_keys(keys)
            return jsonify(ok=True, id=key_id, label=label, token=raw), 201
        body = _json_body()
        key_id = str(body.get("id") or request.args.get("id") or "").strip()
        with lock:
            keys = _load_keys()
            filtered = [k for k in keys if k.get("id") != key_id]
            if len(filtered) == len(keys):
                return _err("token not found", 404)
            _save_keys(filtered)
        return jsonify(ok=True, deleted=key_id)

    @app.route("/api/v1/status", methods=["GET"])
    @api_auth
    def api_v1_status():
        users = deps["load_state"]()["users"]
        with slock:
            online = sum(1 for u in users if deps["CONN"].get(u["name"], {}).get("online"))
            sys_info = dict(deps["SYS"])
        blocked = sum(1 for u in users if u.get("blocked") or u.get("disabled"))
        return jsonify(
            ok=True,
            api_version="1.1",
            app=deps["APP_NAME"],
            now=time.time(),
            users_total=len(users),
            users_online=online,
            users_blocked=blocked,
            users_active=max(0, len(users) - blocked),
            sys={
                "cpu": sys_info.get("cpu", 0),
                "cores": os.cpu_count() or 1,
                "load": list(os.getloadavg()) if hasattr(os, "getloadavg") else [0.0, 0.0, 0.0],
                "mem": sys_info.get("mem") or {},
            },
        )

    @app.route("/api/v1/users", methods=["GET", "POST"])
    @api_auth
    def api_v1_users():
        if request.method == "GET":
            st = deps["load_state"]()
            return jsonify(ok=True, now=time.time(), users=[_serialize_user(u) for u in st["users"]])

        body = _json_body()
        name = str(body.get("name") or "").strip()
        proto = str(body.get("proto") or "udp").lower().strip()
        manual = bool(body.get("manual")) or (body.get("port") is not None)
        try:
            days = int(body.get("days") or 0)
            expires_raw = body.get("expires")
            expires_val = float(expires_raw) if expires_raw is not None else None
            speed = round(float(body.get("speed") or 0), 2)
            daily = round(float(body.get("daily") or 0), 3)
            total = round(float(body.get("total") or 0), 3)
            mport = int(body["port"]) if (manual and body.get("port") is not None) else None
            min_port = int(body["min_port"]) if body.get("min_port") is not None else None
        except (TypeError, ValueError):
            return _err("invalid numeric parameter", 400)

        oa = str(body.get("ovpn_addr") or "").strip()
        disabled = bool(body.get("disabled", False))

        def _pick_min_port(st_obj: dict[str, Any], start_floor: int, proto_val: str) -> int | None:
            skip = {8088, 8089, 2096, 8443}
            used_ports = [int(x.get("port", 0)) for x in st_obj.get("users", []) if isinstance(x.get("port"), int)]
            highest = max(used_ports) if used_ports else 0
            start = max(start_floor, highest + 1)
            for p in range(start, 65536):
                if p not in skip and deps["port_error"](st_obj, p, proto_val) is None:
                    return p
            for p in range(start_floor, min(start, 65536)):
                if p not in skip and deps["port_error"](st_obj, p, proto_val) is None:
                    return p
            return None

        with lock:
            st = deps["load_state"]()
            if manual and mport is not None:
                port = mport
            elif min_port is not None and 1 <= min_port <= 65535:
                port = _pick_min_port(st, min_port, proto)
            else:
                port = deps["next_port"](st)
            err = None
            if not deps["host_ready"]():
                err = "openvpn host is not ready (server.crt missing)"
            elif not deps["NAME_RE"].match(name):
                err = "invalid name (1..32 chars: A-Za-z0-9_-)"
            elif proto not in ("udp", "tcp"):
                err = "proto must be udp or tcp"
            elif not 0 <= days <= 3650:
                err = "days must be between 0 and 3650"
            elif not 0 <= speed <= 10000:
                err = "speed must be between 0 and 10000"
            elif not (0 <= daily <= 1e6 and 0 <= total <= 1e6):
                err = "limits must be between 0 and 1000000 GB"
            elif oa and not deps["ovpn_addr_valid"](oa):
                err = "invalid ovpn_addr"
            elif any(u["name"] == name for u in st["users"]):
                return _err("user already exists", 409)
            elif port is None:
                err = "no free port available"
            else:
                err = deps["port_error"](st, port, proto)
            if err:
                return _err(err, 422)

            idx = deps["free_id"](st)
            sub = deps["new_subnet"](idx, st)
            ok, cerr = deps["create_instance"](name, port, sub, proto)
            if not ok:
                return _err("instance creation failed", 500, detail=str(cerr))

            now = time.time()
            if expires_val is not None:
                final_exp = expires_val if expires_val > 0 else None
            else:
                final_exp = (now + days * 86400) if days else None

            user = {
                "name": name,
                "id": idx,
                "port": port,
                "subnet": sub,
                "created": now,
                "expires": final_exp,
                "proto": proto,
                "speed": speed or None,
                "limit_daily": daily or None,
                "limit_total": total or None,
                "ovpn_addr": oa or None,
                "disabled": disabled,
                "blocked": "manual" if disabled else None,
            }
            st["users"].append(user)
            st["users"].sort(key=lambda u: u["id"])
            deps["save_state"](st)
            if speed:
                deps["apply_speed"](user)
        if disabled:
            deps["enforce_blocks"]()
        return jsonify(ok=True, user=_serialize_user(user)), 201

    @app.route("/api/v1/users/<name>", methods=["GET", "PATCH", "DELETE"])
    @api_auth
    def api_v1_user_item(name: str):
        if request.method == "GET":
            u = next((x for x in deps["load_state"]()["users"] if x["name"] == name), None)
            if not u:
                return _err("user not found", 404)
            return jsonify(ok=True, user=_serialize_user(u))

        if request.method == "DELETE":
            return api_v1_user_delete(name)

        return api_v1_user_update(name)

    @app.route("/api/v1/users/<name>/update", methods=["POST"])
    @api_auth
    def api_v1_user_update(name: str):
        body = _json_body()
        with lock:
            st = deps["load_state"]()
            u = next((x for x in st["users"] if x["name"] == name), None)
            if not u:
                return _err("user not found", 404)

            others = {"users": [x for x in st["users"] if x["name"] != name]}
            old_proto = u.get("proto", "udp")
            proto = str(body.get("proto", old_proto)).lower().strip()
            oa = str(body.get("ovpn_addr", u.get("ovpn_addr") or "") or "").strip()

            try:
                new_id = int(body.get("id", u["id"]))
                new_port = int(body.get("port", u["port"]))
                speed = round(float(body.get("speed") if "speed" in body else (u.get("speed") or 0)) or 0, 2)
                daily = round(float(body.get("daily") if "daily" in body else (u.get("limit_daily") or 0)) or 0, 3)
                total = round(float(body.get("total") if "total" in body else (u.get("limit_total") or 0)) or 0, 3)
            except (TypeError, ValueError):
                return _err("invalid numeric parameter", 400)

            err = None
            if proto not in ("udp", "tcp"):
                err = "proto must be udp or tcp"
            elif new_id < 1 or any(x["id"] == new_id for x in others["users"]):
                err = "invalid or duplicate id"
            elif not 0 <= speed <= 10000:
                err = "speed must be between 0 and 10000"
            elif not (0 <= daily <= 1e6 and 0 <= total <= 1e6):
                err = "limits must be between 0 and 1000000 GB"
            elif oa and not deps["ovpn_addr_valid"](oa):
                err = "invalid ovpn_addr"
            elif (new_port, proto) != (u["port"], old_proto):
                err = deps["port_error"](others, new_port, proto)
            if err:
                return _err(err, 422)

            if "expires" in body:
                exp = body["expires"]
                u["expires"] = float(exp) if (exp is not None and float(exp) > 0) else None
            elif "days" in body:
                days = int(body["days"])
                if not 0 <= days <= 3650:
                    return _err("days must be between 0 and 3650", 422)
                u["expires"] = (time.time() + days * 86400) if days > 0 else None

            if (new_id, new_port, proto) != (u["id"], u["port"], old_proto):
                ok, e = deps["edit_instance"](u, new_id, new_port, proto)
                if not ok:
                    return _err("instance update failed", 500, detail=str(e))
                if u.get("blocked"):
                    deps["run"](["systemctl", "disable", "--now", f"openvpn-server@{name}"])

            u["speed"] = speed or None
            u["limit_daily"] = daily or None
            u["limit_total"] = total or None
            u["ovpn_addr"] = oa or None

            if "disabled" in body:
                u["disabled"] = bool(body["disabled"])
            elif "enable" in body:
                u["disabled"] = not bool(body["enable"])

            px_st, ex_st = deps["feature_state"]()
            if px_st == "ok" and "px" in body:
                u["px"] = bool(body["px"])
            if ex_st == "ok" and "ex" in body:
                u["ex"] = bool(body["ex"])

            st["users"].sort(key=lambda x: x["id"])
            deps["save_state"](st)
            deps["apply_speed"](u)

        deps["enforce_blocks"]()
        deps["proxy_sync_rules"]()
        u_latest = next((x for x in deps["load_state"]()["users"] if x["name"] == name), u)
        return jsonify(ok=True, user=_serialize_user(u_latest))

    @app.route("/api/v1/users/<name>/extend", methods=["POST"])
    @api_auth
    def api_v1_user_extend(name: str):
        body = _json_body()
        unlimited = bool(body.get("unlimited", False))
        try:
            days = int(body.get("days", 0))
        except (TypeError, ValueError):
            return _err("days must be an integer", 400)
        with lock:
            st = deps["load_state"]()
            u = next((x for x in st["users"] if x["name"] == name), None)
            if not u:
                return _err("user not found", 404)
            if unlimited or days == 0:
                u["expires"] = None
            elif 1 <= days <= 3650:
                u["expires"] = max(u.get("expires") or 0, time.time()) + days * 86400
            else:
                return _err("days must be between 0 and 3650", 422)
            deps["save_state"](st)
        return jsonify(ok=True, user=_serialize_user(u))

    @app.route("/api/v1/users/<name>/reset", methods=["POST"])
    @api_auth
    def api_v1_user_reset(name: str):
        with lock:
            st = deps["load_state"]()
            u = next((x for x in st["users"] if x["name"] == name), None)
            if not u:
                return _err("user not found", 404)
            deps["reset_usage"](u)
        deps["enforce_blocks"]()
        u_latest = next((x for x in deps["load_state"]()["users"] if x["name"] == name), u)
        return jsonify(ok=True, user=_serialize_user(u_latest))

    @app.route("/api/v1/users/<name>/enable", methods=["POST"])
    @api_auth
    def api_v1_user_enable(name: str):
        with lock:
            st = deps["load_state"]()
            u = next((x for x in st["users"] if x["name"] == name), None)
            if not u:
                return _err("user not found", 404)
            u["disabled"] = False
            deps["save_state"](st)
        deps["enforce_blocks"]()
        u_latest = next((x for x in deps["load_state"]()["users"] if x["name"] == name), u)
        return jsonify(ok=True, user=_serialize_user(u_latest))

    @app.route("/api/v1/users/<name>/disable", methods=["POST"])
    @api_auth
    def api_v1_user_disable(name: str):
        with lock:
            st = deps["load_state"]()
            u = next((x for x in st["users"] if x["name"] == name), None)
            if not u:
                return _err("user not found", 404)
            u["disabled"] = True
            deps["save_state"](st)
        deps["enforce_blocks"]()
        u_latest = next((x for x in deps["load_state"]()["users"] if x["name"] == name), u)
        return jsonify(ok=True, user=_serialize_user(u_latest))

    @app.route("/api/v1/users/<name>/delete", methods=["POST"])
    @api_auth
    def api_v1_user_delete(name: str):
        with lock:
            st = deps["load_state"]()
            u = next((x for x in st["users"] if x["name"] == name), None)
            if not u:
                return _err("user not found", 404)
            deps["remove_instance"](u)
            st["users"] = [x for x in st["users"] if x["name"] != name]
            deps["save_state"](st)
        return jsonify(ok=True, deleted=name)

    @app.route("/api/v1/users/<name>/ovpn", methods=["GET"])
    @api_auth
    def api_v1_user_ovpn(name: str):
        u = next((x for x in deps["load_state"]()["users"] if x["name"] == name), None)
        if not u:
            return _err("user not found", 404)
        path = f"{deps['OVPN_DIR']}/{name}.ovpn"
        if not os.path.exists(path):
            try:
                deps["build_ovpn"](name, u["port"], path, u.get("proto", "udp"))
            except Exception as exc:
                return _err("ovpn profile unavailable", 500, detail=str(exc))
        raw = deps["ovpn_bytes"](path, u)
        if request.args.get("format") == "json":
            return jsonify(ok=True, name=name, filename=f"{name}.ovpn", content=raw.decode("utf-8", errors="replace"))
        return send_file(io.BytesIO(raw), as_attachment=True, download_name=f"{name}.ovpn")

    @app.route("/api/v1/ports/check", methods=["GET"])
    @api_auth
    def api_v1_ports_check():
        try:
            port = int(request.args.get("port", ""))
        except ValueError:
            return jsonify(ok=False, free=False, msg="invalid port")
        proto = request.args.get("proto", "udp")
        proto = proto if proto in ("udp", "tcp") else "udp"
        err = deps["port_error"](deps["load_state"](), port, proto)
        return jsonify(ok=True, free=(err is None), port=port, proto=proto, msg=err or "free")
