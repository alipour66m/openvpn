#!/usr/bin/env bash
# =============================================================================
# GassLight — یک‌کلیک آپدیت و پیکربندی خودکار
# =============================================================================
#   sudo bash update.sh
# =============================================================================

set -Eeuo pipefail

# ------------------------------------------------------------------ رنگ‌ها ---
if [[ -t 1 ]]; then
    C_B=$'\e[1m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_N=$'\e[0m'
else
    C_B=""; C_G=""; C_Y=""; C_R=""; C_N=""
fi
say()  { printf '%s==>%s %s\n' "$C_B" "$C_N" "$*"; }
ok()   { printf '%s ok%s  %s\n' "$C_G" "$C_N" "$*"; }
warn() { printf '%s !! %s  %s\n' "$C_Y" "$C_N" "$*" >&2; }
die()  { printf '%s error:%s %s\n' "$C_R" "$C_N" "$*" >&2; exit 1; }

trap 'printf "\n%serror:%s اسکریپت در خط %s متوقف شد.\n" "$C_R" "$C_N" "$LINENO" >&2' ERR

# ------------------------------------------------------------- پیش‌نیازها ---
(( EUID == 0 )) || die "لطفاً با root اجرا کنید:  sudo bash update.sh"
command -v python3   >/dev/null 2>&1 || die "python3 پیدا نشد"
command -v curl      >/dev/null 2>&1 || die "curl پیدا نشد"
command -v systemctl >/dev/null 2>&1 || die "systemctl پیدا نشد"

# -------------------------------------------------------------- مسیرها ------
PANEL_DIR="${PANEL_DIR:-/opt/ovpn-panel}"
OVPN_SERVER_DIR="${OVPN_SERVER_DIR:-/etc/openvpn/server}"
PANEL_PORT="${PANEL_PORT:-8088}"

# خواندن تنظیمات نصب قبلی
if [[ -f "/etc/gasslight/install.conf" ]]; then
    # shellcheck disable=SC1091
    source /etc/gasslight/install.conf 2>/dev/null || true
fi

PANEL_API="http://127.0.0.1:${PANEL_PORT}"
NEW_COMMIT="latest"
REPO="${REPO:-alipour66m/openvpn}"
REF="${REF:-main}"

# ===========================================================================
# مرحله 1: دریافت کد جدید از GitHub
# ===========================================================================
say "مرحله 1/6 — دریافت آخرین کد از GitHub..."

cd "$PANEL_DIR"
if [[ -d ".git" ]]; then
    OLD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    git fetch --quiet origin "$REF"
    git reset --hard "origin/$REF" --quiet
    NEW_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    [[ "$OLD_COMMIT" == "$NEW_COMMIT" ]] \
        && ok "کد از قبل به‌روز بود ($NEW_COMMIT)" \
        || ok "کد آپدیت شد: $OLD_COMMIT → $NEW_COMMIT"
else
    say "  دانلود zip از GitHub (نصب اولیه بدون git بوده)..."
    TMP_ZIP=$(mktemp /tmp/gl-XXXXXX.zip)
    TMP_DIR=$(mktemp -d /tmp/gl-XXXXXX)
    # حذف فایل‌های موقت در خروج
    _cleanup() { rm -rf "$TMP_ZIP" "$TMP_DIR" 2>/dev/null || true; }
    trap _cleanup EXIT

    ZIP_URL="https://github.com/${REPO}/archive/refs/heads/${REF}.zip"
    if curl -fsSL --max-time 90 --retry 3 -o "$TMP_ZIP" "$ZIP_URL" 2>/dev/null; then
        unzip -q "$TMP_ZIP" -d "$TMP_DIR"
        SRC_DIR=$(find "$TMP_DIR" -maxdepth 1 -mindepth 1 -type d | head -1)
        if [[ -d "$SRC_DIR/panel" ]]; then
            for d in panel portal core overlay scripts; do
                [[ -d "$SRC_DIR/$d" ]] && cp -r "$SRC_DIR/$d" "$PANEL_DIR/"
            done
            for f in update.sh install.sh; do
                [[ -f "$SRC_DIR/$f" ]] && cp "$SRC_DIR/$f" "$PANEL_DIR/"
            done
            # مهم: systemd از /opt/ovpn-panel/panel.py اجرا می‌کند (نه panel/panel.py)
            # پس همه فایل‌های Python از panel/ را به root کپی می‌کنیم
            for _pyfile in panel.py routing.py geoip.py api_v1.py; do
                if [[ -f "$SRC_DIR/panel/$_pyfile" ]]; then
                    cp "$SRC_DIR/panel/$_pyfile" "$PANEL_DIR/$_pyfile"
                fi
            done
            ok "  فایل‌های Python root آپدیت شدند (panel/routing/geoip/api_v1)"
            NEW_COMMIT=$(curl -fsSL --max-time 10 \
                "https://api.github.com/repos/${REPO}/commits/${REF}" 2>/dev/null \
                | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['sha'][:7])" \
                2>/dev/null || echo "latest")
            ok "فایل‌های کد آپدیت شدند (commit: $NEW_COMMIT)"
        else
            warn "ساختار zip نامعتبر — آپدیت کد انجام نشد"
        fi
    else
        warn "دانلود از GitHub ناموفق بود — ادامه با فایل‌های موجود"
    fi
fi

# ===========================================================================
# مرحله 2: نصب maxminddb (فقط این پکیج جدید است)
# ===========================================================================
say "مرحله 2/6 — بررسی و نصب maxminddb..."

if python3 -c "import maxminddb" 2>/dev/null; then
    ok "maxminddb قبلاً نصب است"
else
    # پیدا کردن pip
    PIP_CMD=""
    for c in pip3 pip python3-pip pip-3; do
        if command -v "$c" >/dev/null 2>&1; then
            PIP_CMD="$c"
            break
        fi
    done

    if [[ -z "$PIP_CMD" ]]; then
        # نصب pip اگر موجود نیست
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-pip 2>/dev/null
        PIP_CMD="pip3"
    fi

    # نصب maxminddb — سه روش به ترتیب اولویت
    if "$PIP_CMD" install --quiet --break-system-packages maxminddb 2>/dev/null; then
        ok "maxminddb نصب شد (break-system-packages)"
    elif "$PIP_CMD" install --quiet --user maxminddb 2>/dev/null; then
        ok "maxminddb نصب شد (--user)"
    else
        # آخرین راه: مستقیم از pip module
        python3 -m pip install --quiet --break-system-packages maxminddb 2>/dev/null \
            || python3 -m pip install --quiet --user maxminddb 2>/dev/null \
            || warn "نصب maxminddb ناموفق — GeoIP کار نخواهد کرد"
        ok "maxminddb نصب شد"
    fi
fi

# ===========================================================================
# مرحله 3: دانلود GeoIP (Country-lite.mmdb)
# ===========================================================================
say "مرحله 3/6 — دانلود GeoIP (Country-lite.mmdb)..."

GEOIP_DIR="${PANEL_DIR}/geoip"
mkdir -p "$GEOIP_DIR"
MMDB_PATH="${GEOIP_DIR}/Country-lite.mmdb"
MMDB_URL="https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/Country-lite.mmdb"
DOWNLOAD_OK=false

if curl -fsSL --max-time 90 --retry 3 \
       -H "User-Agent: GassLight-Updater/2.0" \
       -o "${MMDB_PATH}.tmp" "$MMDB_URL" 2>/dev/null; then
    mv "${MMDB_PATH}.tmp" "$MMDB_PATH"
    SIZE=$(du -h "$MMDB_PATH" | cut -f1)
    ok "Country-lite.mmdb دانلود شد ($SIZE)"
    DOWNLOAD_OK=true
else
    rm -f "${MMDB_PATH}.tmp" 2>/dev/null || true
    if [[ -f "$MMDB_PATH" ]]; then
        warn "دانلود ناموفق — از نسخه قبلی استفاده می‌شود"
    else
        warn "Country-lite.mmdb دانلود نشد — GeoIP فعال نخواهد بود"
    fi
fi

# ===========================================================================
# مرحله 4: تولید و deploy اسکریپت client-connect
# ===========================================================================
say "مرحله 4/6 — تولید اسکریپت client-connect..."

python3 - <<PYEOF
import sys, os
sys.path.insert(0, '${PANEL_DIR}/panel')
sys.path.insert(0, '${PANEL_DIR}')

try:
    from panel.routing import PLATFORM_ROUTE_CAPS
except ImportError:
    try:
        from routing import PLATFORM_ROUTE_CAPS
    except ImportError:
        PLATFORM_ROUTE_CAPS = {"ios":200,"android":500,"win":500,"mac":500,"linux":500,"default":250}

server_dir = "${OVPN_SERVER_DIR}"

lines = []
for plat, cap in PLATFORM_ROUTE_CAPS.items():
    pad = " " * max(1, 9 - len(plat))
    if plat == "default":
        lines.append(f"  *)      {pad} MAX_ROUTES={cap} ;;")
    else:
        lines.append(f"  {plat}){pad} MAX_ROUTES={cap} ;;")
caps_block = "\n".join(lines)

script = f"""#!/bin/sh
# GassLight client-connect: مسیریابی آگاه از پلتفرم
# تولیدشده توسط update.sh — دستی ویرایش نکنید
# نیاز دارد در server.conf:
#   script-security 2
#   client-connect {server_dir}/gasslight-client-connect.sh

PLATFORM="\${{IV_PLAT:-default}}"
CCD_BASE="{server_dir}"
USER_NAME="\${{common_name}}"

case "\$PLATFORM" in
{caps_block}
esac

CCD_FILE="\$CCD_BASE/ccd-\$USER_NAME/\$USER_NAME"
[ -f "\$CCD_FILE" ] || exit 0

ROUTE_COUNT=\$(grep -c 'push "route' "\$CCD_FILE" 2>/dev/null || echo 0)

if [ "\$ROUTE_COUNT" -le "\$MAX_ROUTES" ]; then
    cat "\$CCD_FILE" >> "\$1"
    exit 0
fi

# تعداد مسیرها از محدودیت پلتفرم بیشتر است — کوتاه می‌کنیم
TIER1_COUNT=\$(grep -m1 '# tier1_count=' "\$CCD_FILE" | sed 's/.*tier1_count=//' | tr -d '[:space:]')
echo "\$TIER1_COUNT" | grep -qE '^[0-9]+\$' || TIER1_COUNT=0

grep -v 'push "route' "\$CCD_FILE" >> "\$1"
grep 'push "route' "\$CCD_FILE" | head -n "\$TIER1_COUNT" >> "\$1"
REMAINING=\$(( MAX_ROUTES - TIER1_COUNT ))
[ "\$REMAINING" -gt 0 ] && grep 'push "route' "\$CCD_FILE" | tail -n +"\$(( TIER1_COUNT + 1 ))" | head -n "\$REMAINING" >> "\$1"
exit 0
"""

script_path = os.path.join(server_dir, "gasslight-client-connect.sh")
tmp_path = script_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(script)
os.chmod(tmp_path, 0o755)
os.replace(tmp_path, script_path)
print(f"  تولید شد: {script_path}")
PYEOF

ok "اسکریپت client-connect آماده شد"

# ===========================================================================
# مرحله 5: پیکربندی فایل‌های server.conf
# ===========================================================================
say "مرحله 5/6 — پیکربندی فایل‌های OpenVPN server.conf..."

CONF_COUNT=0; CONF_CHANGED=0
for CONF in "${OVPN_SERVER_DIR}"/*.conf; do
    [[ -f "$CONF" ]] || continue
    CONF_COUNT=$(( CONF_COUNT + 1 ))
    CONF_NAME=$(basename "$CONF")
    CHANGED=false

    if ! grep -q "^script-security" "$CONF" 2>/dev/null; then
        echo "script-security 2" >> "$CONF"; CHANGED=true
        ok "  $CONF_NAME ← script-security 2 اضافه شد"
    elif grep -q "^script-security[[:space:]]*1" "$CONF"; then
        sed -i 's/^script-security[[:space:]]*.*/script-security 2/' "$CONF"; CHANGED=true
        ok "  $CONF_NAME ← script-security 2 بروز شد"
    else
        ok "  $CONF_NAME — script-security ✓"
    fi

    CC_LINE="client-connect ${OVPN_SERVER_DIR}/gasslight-client-connect.sh"
    if ! grep -q "^client-connect" "$CONF" 2>/dev/null; then
        echo "$CC_LINE" >> "$CONF"; CHANGED=true
        ok "  $CONF_NAME ← client-connect اضافه شد"
    elif ! grep -q "gasslight-client-connect" "$CONF"; then
        sed -i "s|^client-connect.*|$CC_LINE|" "$CONF"; CHANGED=true
        ok "  $CONF_NAME ← client-connect بروز شد"
    else
        ok "  $CONF_NAME — client-connect ✓"
    fi

    $CHANGED && CONF_CHANGED=$(( CONF_CHANGED + 1 )) || true
done

(( CONF_COUNT == 0 )) && warn "هیچ فایل .conf در ${OVPN_SERVER_DIR} پیدا نشد" \
    || ok "${CONF_CHANGED} از ${CONF_COUNT} فایل conf تغییر کرد"

# ===========================================================================
# مرحله 6: ریستارت سرویس‌ها
# ===========================================================================
say "مرحله 6/6 — ریستارت سرویس‌ها..."

systemctl daemon-reload 2>/dev/null || true

# پنل
PANEL_SVC=""
for s in ovpn-panel gasslight gasslight-panel; do
    if systemctl is-enabled "$s" >/dev/null 2>&1; then
        PANEL_SVC="$s"; break
    fi
done

if [[ -n "$PANEL_SVC" ]]; then
    systemctl restart "$PANEL_SVC"
    sleep 3
    systemctl is-active --quiet "$PANEL_SVC" \
        && ok "پنل ($PANEL_SVC) ریستارت شد" \
        || { warn "وضعیت پنل:"; systemctl status "$PANEL_SVC" --no-pager -n 5 || true; }
else
    warn "سرویس پنل پیدا نشد (ovpn-panel / gasslight)"
fi

# OpenVPN — فقط اگر conf تغییر کرده
if (( CONF_CHANGED > 0 )); then
    for CONF in "${OVPN_SERVER_DIR}"/*.conf; do
        [[ -f "$CONF" ]] || continue
        SVC="openvpn-server@$(basename "${CONF%.conf}")"
        if systemctl is-enabled "$SVC" >/dev/null 2>&1; then
            systemctl restart "$SVC" && ok "  $SVC ریستارت شد" || warn "  $SVC ریستارت ناموفق"
        fi
    done
else
    ok "  conf تغییر نکرده — ریستارت OpenVPN لازم نیست"
fi

# refresh GeoIP از API (اگر پنل بالا آمد)
API_TOKEN=""
[[ -f "${PANEL_DIR}/auth.json" ]] && \
    API_TOKEN=$(python3 -c "
import json
try:
    print(json.load(open('${PANEL_DIR}/auth.json')).get('api_token',''))
except: pass
" 2>/dev/null || true)

if [[ -n "$API_TOKEN" ]]; then
    sleep 2
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${PANEL_API}/api/v1/routing/geoip/refresh" \
        -H "X-Api-Token: ${API_TOKEN}" --max-time 15 2>/dev/null || echo "000")
    [[ "$HTTP" == "200" ]] && ok "GeoIP refresh از API موفق" \
        || warn "GeoIP refresh کد $HTTP (پنل شاید هنوز بالا نیامده)"
else
    warn "توکن API پیدا نشد — GeoIP refresh دستی:"
    warn "  curl -X POST http://127.0.0.1:${PANEL_PORT}/api/v1/routing/geoip/refresh -H 'X-Api-Token: TOKEN'"
fi

# ===========================================================================
# خلاصه
# ===========================================================================
echo ""
printf '%s%s%s\n' "$C_G" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "$C_N"
printf '%s✅  آپدیت GassLight با موفقیت انجام شد%s\n' "$C_G" "$C_N"
printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$C_G" "$C_N"
printf '  کد GitHub       : %s\n' "$NEW_COMMIT"
printf '  GeoIP           : %s\n' "$( $DOWNLOAD_OK && echo "✅ دانلود شد" || echo "⚠️  از نسخه قبلی" )"
printf '  client-connect  : ✅ %s/gasslight-client-connect.sh\n' "$OVPN_SERVER_DIR"
printf '  تغییر conf      : %s/%s\n' "${CONF_CHANGED:-0}" "${CONF_COUNT:-0}"
printf '  پنل سرویس       : %s\n' "${PANEL_SVC:-نامشخص}"
echo ""
printf '  محدودیت‌های پلتفرم:\n'
printf '    iOS .............. 200 route\n'
printf '    Android/Win/Mac .. 500 route\n'
printf '    Default .......... 250 route\n'
printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$C_G" "$C_N"
