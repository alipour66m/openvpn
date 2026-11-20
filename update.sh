#!/usr/bin/env bash
# =============================================================================
# GassLight — یک‌کلیک آپدیت و پیکربندی خودکار
# =============================================================================
#
#   sudo bash update.sh
#
# این اسکریپت:
#   1. کد جدید را از GitHub دریافت می‌کند
#   2. پکیج‌های Python را آپدیت می‌کند
#   3. اسکریپت client-connect را تولید و deploy می‌کند
#   4. فایل‌های server.conf را برای هر سرور پیکربندی می‌کند
#   5. GeoIP (Country-lite.mmdb) را دانلود می‌کند
#   6. سرویس‌ها را ریستارت می‌کند
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
command -v python3 >/dev/null 2>&1 || die "python3 پیدا نشد"
command -v git     >/dev/null 2>&1 || die "git پیدا نشد"
command -v curl    >/dev/null 2>&1 || die "curl پیدا نشد"
command -v systemctl >/dev/null 2>&1 || die "systemctl پیدا نشد (Ubuntu/Debian لازم است)"

# نصب pip3 اگر موجود نیست
if ! command -v pip3 >/dev/null 2>&1; then
    say "pip3 پیدا نشد — نصب می‌شود..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y -qq python3-pip python3-venv 2>/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3-pip 2>/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3-pip 2>/dev/null
    fi
    command -v pip3 >/dev/null 2>&1 || die "نصب pip3 ناموفق بود — دستی نصب کنید: apt install python3-pip"
    ok "pip3 نصب شد"
fi

# -------------------------------------------------------------- مسیرها ------
PANEL_DIR="${PANEL_DIR:-/opt/ovpn-panel}"
OVPN_SERVER_DIR="${OVPN_SERVER_DIR:-/etc/openvpn/server}"
PANEL_PORT="${PANEL_PORT:-8088}"
PANEL_API="http://127.0.0.1:${PANEL_PORT}"

# خواندن توکن API از فایل تنظیمات
API_TOKEN=""
if [[ -f "/etc/gasslight/install.conf" ]]; then
    # shellcheck disable=SC1091
    source /etc/gasslight/install.conf
fi
if [[ -f "${PANEL_DIR}/auth.json" ]]; then
    API_TOKEN=$(python3 -c "
import json, sys
try:
    d = json.load(open('${PANEL_DIR}/auth.json'))
    print(d.get('api_token', ''))
except Exception:
    pass
" 2>/dev/null || true)
fi

# ===========================================================================
# مرحله 1: دریافت کد جدید از GitHub
# ===========================================================================
say "مرحله 1/6 — دریافت آخرین کد از GitHub..."
cd "$PANEL_DIR"

if [[ -d ".git" ]]; then
    OLD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    git fetch --quiet origin main
    git reset --hard origin/main --quiet
    NEW_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    if [[ "$OLD_COMMIT" == "$NEW_COMMIT" ]]; then
        ok "کد از قبل به‌روز بود ($NEW_COMMIT)"
    else
        ok "کد آپدیت شد: $OLD_COMMIT → $NEW_COMMIT"
    fi
else
    warn "دایرکتوری git پیدا نشد، آپدیت git انجام نشد"
fi

# ===========================================================================
# مرحله 2: آپدیت پکیج‌های Python
# ===========================================================================
say "مرحله 2/6 — آپدیت پکیج‌های Python..."

VENV=""
for v in "$PANEL_DIR/venv" "$PANEL_DIR/.venv" "/opt/ovpn-venv"; do
    if [[ -f "$v/bin/pip" ]]; then
        VENV="$v"
        break
    fi
done

if [[ -n "$VENV" ]]; then
    PIP="$VENV/bin/pip"
    ok "محیط مجازی پیدا شد: $VENV"
else
    PIP="pip3"
    warn "محیط مجازی پیدا نشد، از pip3 سیستم استفاده می‌شود"
fi

# نصب پکیج‌ها (سازگار با Ubuntu 22/24 و سیستم‌های جدید)
PIP_OPTS="--quiet --upgrade"
# Ubuntu 23+ و Debian 12+ نیاز به --break-system-packages دارند
if "$PIP" install --help 2>&1 | grep -q "break-system-packages"; then
    if [[ -z "$VENV" ]]; then
        PIP_OPTS="$PIP_OPTS --break-system-packages"
    fi
fi

# shellcheck disable=SC2086
"$PIP" install $PIP_OPTS \
    maxminddb \
    flask \
    markupsafe \
    werkzeug \
    requests

ok "پکیج‌ها آپدیت شدند"

# ===========================================================================
# مرحله 3: دانلود GeoIP (Country-lite.mmdb)
# ===========================================================================
say "مرحله 3/6 — دانلود GeoIP (Country-lite.mmdb از Chocolate4U)..."

GEOIP_DIR="${PANEL_DIR}/geoip"
mkdir -p "$GEOIP_DIR"
MMDB_PATH="${GEOIP_DIR}/Country-lite.mmdb"
MMDB_URL="https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/Country-lite.mmdb"

DOWNLOAD_OK=false
if curl -fsSL --max-time 60 --retry 3 \
       -H "User-Agent: GassLight-Updater/2.0" \
       -o "${MMDB_PATH}.tmp" "$MMDB_URL" 2>/dev/null; then
    mv "${MMDB_PATH}.tmp" "$MMDB_PATH"
    SIZE=$(du -h "$MMDB_PATH" | cut -f1)
    ok "Country-lite.mmdb دانلود شد ($SIZE)"
    DOWNLOAD_OK=true
else
    warn "دانلود Country-lite.mmdb ناموفق بود (بعداً از طریق API امتحان می‌شود)"
    rm -f "${MMDB_PATH}.tmp" || true
fi

# متغیر محیطی برای panel تا mmdb را پیدا کند
export GEOIP_MMDB_PATH="$MMDB_PATH"

# ===========================================================================
# مرحله 4: تولید و deploy اسکریپت client-connect
# ===========================================================================
say "مرحله 4/6 — تولید اسکریپت client-connect..."

# این اسکریپت را مستقیماً می‌نویسیم (نه از طریق API چون پنل هنوز ریستارت نشده)
# مقادیر را از PLATFORM_ROUTE_CAPS در routing.py می‌خوانیم

python3 - <<'PYEOF'
import sys, os
sys.path.insert(0, '/opt/ovpn-panel/panel')
sys.path.insert(0, '/opt/ovpn-panel')

try:
    from panel.routing import PLATFORM_ROUTE_CAPS, RoutingManager
    caps = PLATFORM_ROUTE_CAPS
except ImportError:
    try:
        from routing import PLATFORM_ROUTE_CAPS, RoutingManager
        caps = PLATFORM_ROUTE_CAPS
    except ImportError:
        caps = {"ios":200,"android":500,"win":500,"mac":500,"linux":500,"default":250}

server_dir = os.environ.get("OVPN_SERVER_DIR", "/etc/openvpn/server")

# تولید case block
lines = []
for plat, cap in caps.items():
    if plat == "default":
        lines.append(f"  *)       MAX_ROUTES={cap} ;;")
    else:
        lines.append(f"  {plat})     MAX_ROUTES={cap} ;;")
caps_block = "\n".join(lines)

script = f"""#!/bin/sh
# GassLight client-connect: مسیریابی آگاه از پلتفرم
# ساخته‌شده توسط update.sh — دستی ویرایش نکنید
# OpenVPN متغیر $IV_PLAT را ست می‌کند: ios/android/win/linux/mac
# این فایل در server.conf باید اشاره شود:
#   script-security 2
#   client-connect {server_dir}/gasslight-client-connect.sh

PLATFORM="${{IV_PLAT:-default}}"
CCD_BASE="{server_dir}"
USER_NAME="${{common_name}}"

case "$PLATFORM" in
{caps_block}
esac

CCD_FILE="$CCD_BASE/ccd-$USER_NAME/$USER_NAME"
if [ ! -f "$CCD_FILE" ]; then
    exit 0
fi

ROUTE_COUNT=$(grep -c 'push "route' "$CCD_FILE" 2>/dev/null || echo 0)

if [ "$ROUTE_COUNT" -le "$MAX_ROUTES" ]; then
    cat "$CCD_FILE" >> "$1"
    exit 0
fi

# تعداد مسیرها از محدودیت پلتفرم بیشتر است — کوتاه می‌کنیم
TIER1_COUNT=$(grep -m1 '# tier1_count=' "$CCD_FILE" | sed 's/.*tier1_count=//' | tr -d '[:space:]')
if [ -z "$TIER1_COUNT" ] || ! echo "$TIER1_COUNT" | grep -qE '^[0-9]+$'; then
    TIER1_COUNT=0
fi

grep -v 'push "route' "$CCD_FILE" >> "$1"
grep 'push "route' "$CCD_FILE" | head -n "$TIER1_COUNT" >> "$1"
REMAINING=$(( MAX_ROUTES - TIER1_COUNT ))
if [ "$REMAINING" -gt 0 ]; then
    grep 'push "route' "$CCD_FILE" | tail -n +"$(( TIER1_COUNT + 1 ))" | head -n "$REMAINING" >> "$1"
fi

exit 0
"""

script_path = os.path.join(server_dir, "gasslight-client-connect.sh")
tmp_path = script_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(script)
os.chmod(tmp_path, 0o755)
os.replace(tmp_path, script_path)
print(f"OK: {script_path}")
PYEOF

ok "اسکریپت client-connect در ${OVPN_SERVER_DIR}/gasslight-client-connect.sh ذخیره شد"

# ===========================================================================
# مرحله 5: پیکربندی فایل‌های server.conf
# ===========================================================================
say "مرحله 5/6 — پیکربندی فایل‌های OpenVPN server.conf..."

CONF_COUNT=0
CONF_CHANGED=0

for CONF in "${OVPN_SERVER_DIR}"/*.conf; do
    [[ -f "$CONF" ]] || continue
    CONF_COUNT=$(( CONF_COUNT + 1 ))
    CONF_NAME=$(basename "$CONF")
    CHANGED=false

    # بررسی و اضافه کردن script-security 2
    if ! grep -q "^script-security" "$CONF"; then
        echo "script-security 2" >> "$CONF"
        CHANGED=true
        ok "  $CONF_NAME ← script-security 2 اضافه شد"
    elif grep -q "^script-security 1" "$CONF"; then
        sed -i 's/^script-security 1/script-security 2/' "$CONF"
        CHANGED=true
        ok "  $CONF_NAME ← script-security 1→2 آپدیت شد"
    else
        ok "  $CONF_NAME — script-security قبلاً تنظیم بود"
    fi

    # بررسی و اضافه کردن client-connect
    CC_LINE="client-connect ${OVPN_SERVER_DIR}/gasslight-client-connect.sh"
    if ! grep -q "^client-connect" "$CONF"; then
        echo "$CC_LINE" >> "$CONF"
        CHANGED=true
        ok "  $CONF_NAME ← client-connect اضافه شد"
    elif ! grep -q "gasslight-client-connect" "$CONF"; then
        # خط قدیمی client-connect را جایگزین می‌کند
        sed -i "s|^client-connect.*|$CC_LINE|" "$CONF"
        CHANGED=true
        ok "  $CONF_NAME ← client-connect به‌روز شد"
    else
        ok "  $CONF_NAME — client-connect قبلاً تنظیم بود"
    fi

    if $CHANGED; then
        CONF_CHANGED=$(( CONF_CHANGED + 1 ))
    fi
done

if (( CONF_COUNT == 0 )); then
    warn "هیچ فایل .conf در ${OVPN_SERVER_DIR} پیدا نشد"
else
    ok "${CONF_CHANGED} از ${CONF_COUNT} فایل conf تغییر کرد"
fi

# ===========================================================================
# مرحله 6: ریستارت سرویس‌ها
# ===========================================================================
say "مرحله 6/6 — ریستارت سرویس‌ها..."

# ریستارت پنل GassLight
PANEL_SVC=""
for s in gasslight gasslight-panel ovpn-panel; do
    if systemctl is-enabled "$s" >/dev/null 2>&1; then
        PANEL_SVC="$s"
        break
    fi
done

if [[ -n "$PANEL_SVC" ]]; then
    systemctl restart "$PANEL_SVC"
    sleep 3
    if systemctl is-active --quiet "$PANEL_SVC"; then
        ok "سرویس پنل ($PANEL_SVC) ریستارت شد"
    else
        warn "سرویس پنل ریستارت شد اما وضعیت نامشخص است"
        systemctl status "$PANEL_SVC" --no-pager -n 5 || true
    fi
else
    warn "سرویس پنل پیدا نشد (gasslight / gasslight-panel / ovpn-panel)"
fi

# ریستارت OpenVPN سرورها (اگر conf تغییر کرده)
if (( CONF_CHANGED > 0 )); then
    say "  ریستارت سرویس‌های OpenVPN..."
    for CONF in "${OVPN_SERVER_DIR}"/*.conf; do
        [[ -f "$CONF" ]] || continue
        SVC_NAME="openvpn-server@$(basename "${CONF%.conf}")"
        if systemctl is-enabled "$SVC_NAME" >/dev/null 2>&1; then
            systemctl restart "$SVC_NAME" && ok "  $SVC_NAME ریستارت شد" || warn "  $SVC_NAME ریستارت ناموفق"
        fi
    done
else
    ok "  هیچ تغییری در conf نبود — ریستارت OpenVPN لازم نیست"
fi

# ===========================================================================
# تریگر refresh GeoIP از API (اگر پنل بالا آمد)
# ===========================================================================
if [[ -n "$API_TOKEN" ]]; then
    say "GeoIP refresh از API..."
    sleep 2
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${PANEL_API}/api/v1/routing/geoip/refresh" \
        -H "X-Api-Token: ${API_TOKEN}" \
        --max-time 15 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
        ok "GeoIP refresh موفق (API)"
    else
        warn "GeoIP refresh از API ناموفق (کد $HTTP_CODE) — از فایل محلی استفاده می‌شود"
    fi
else
    warn "توکن API پیدا نشد — GeoIP refresh از API انجام نشد"
    warn "می‌توانید دستی اجرا کنید:"
    warn "  curl -X POST http://127.0.0.1:${PANEL_PORT}/api/v1/routing/geoip/refresh -H 'X-Api-Token: YOUR_TOKEN'"
fi

# ===========================================================================
# خلاصه نهایی
# ===========================================================================
echo ""
printf '%s%s%s\n' "$C_G" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "$C_N"
printf '%s✅ آپدیت GassLight با موفقیت انجام شد%s\n' "$C_G" "$C_N"
printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$C_G" "$C_N"
echo ""
printf '  %-30s %s\n' "کد GitHub:" "${NEW_COMMIT:-latest}"
printf '  %-30s %s\n' "GeoIP:" "$( [[ "$DOWNLOAD_OK" == "true" ]] && echo "✅ دانلود شد" || echo "⚠️  از فایل قبلی" )"
printf '  %-30s %s\n' "client-connect script:" "✅ ${OVPN_SERVER_DIR}/gasslight-client-connect.sh"
printf '  %-30s %s\n' "فایل‌های conf تغییر کرده:" "${CONF_CHANGED}/${CONF_COUNT}"
printf '  %-30s %s\n' "پنل سرویس:" "${PANEL_SVC:-نامشخص}"
echo ""
printf '  %-30s\n' "محدودیت‌های پلتفرم:"
printf '    iOS .............. 200 route\n'
printf '    Android/Win/Mac .. 500 route\n'
printf '    Default .......... 250 route\n'
echo ""
printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$C_G" "$C_N"
