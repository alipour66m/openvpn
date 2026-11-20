"""
geoip.py — GeoIP CIDR extractor for GassLight OpenVPN panel.

Sources supported (in priority order):
1. Chocolate4U/Iran-v2ray-rules  Country.mmdb / Country-lite.mmdb  (MaxMind-compatible)
2. IPdeny plain text (.zone files)                                  (no dependency)

Usage:
    gm = GeoIPManager()
    cidrs = gm.country_cidrs("IR")   # list of "x.x.x.x/y" strings (IPv4 only)
    info  = gm.status()
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
import urllib.request
import ssl
from typing import Any

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------
_BASE = os.path.dirname(os.path.abspath(__file__))
_DATA = os.path.join(_BASE, "data")

MMDB_LITE_PATH    = os.path.join(_DATA, "Country-lite.mmdb")   # IR only (~127 KB)
MMDB_FULL_PATH    = os.path.join(_DATA, "Country.mmdb")        # all countries (~8 MB)
IPDENY_CACHE_DIR  = os.path.join(_DATA, "ipdeny")              # fallback txt files

# GitHub release download base
_GH_BASE = "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download"
MMDB_LITE_URL = f"{_GH_BASE}/Country-lite.mmdb"
MMDB_FULL_URL = f"{_GH_BASE}/Country.mmdb"

# IPdeny fallback (no login needed)
IPDENY_URL = "https://www.ipdeny.com/ipblocks/data/aggregated/{iso}-aggregated.zone"

# How often to auto-refresh (seconds). Default: every 24 h.
AUTO_UPDATE_INTERVAL = 86400


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _download(url: str, dest: str, timeout: int = 60) -> bool:
    """Download url → dest. Returns True on success."""
    os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
    tmp = dest + ".tmp"
    ctx = ssl._create_unverified_context()
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "GassLight-GeoIP/1.0")
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            data = r.read()
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, dest)
        return True
    except Exception as exc:
        print(f"[geoip] download failed {url}: {exc}", flush=True)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


def _parse_ipdeny(text: str) -> list[str]:
    """Parse IPdeny .zone file → list of CIDR strings."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.IPv4Network(line, strict=False)
            if net.prefixlen >= 1:
                out.append(str(net))
        except ValueError:
            pass
    return out


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------
class GeoIPManager:
    """
    Extracts IPv4 CIDRs for a given country ISO code.

    Priority:
      1. Country-lite.mmdb  (IR + PRIVATE only, 127 KB, Chocolate4U)
      2. Country.mmdb       (all countries, 8 MB, Chocolate4U)
      3. IPdeny .zone files (plain text fallback, any country)

    Call `ensure_database()` once at startup to download if missing.
    Call `refresh()` to force a re-download.
    """

    def __init__(
        self,
        mmdb_lite: str = MMDB_LITE_PATH,
        mmdb_full: str = MMDB_FULL_PATH,
        ipdeny_dir: str = IPDENY_CACHE_DIR,
        auto_update: bool = True,
    ) -> None:
        self._lite_path = mmdb_lite
        self._full_path = mmdb_full
        self._ipdeny_dir = ipdeny_dir
        self._auto_update = auto_update
        self._lock = threading.Lock()
        self._last_update: float = 0.0
        self._reader_lite: Any = None   # maxminddb.Reader or None
        self._reader_full: Any = None
        self._ipdeny_cache: dict[str, list[str]] = {}

        # Try to load existing files without downloading
        self._try_load()

        # Start background auto-update thread
        if auto_update:
            t = threading.Thread(target=self._update_loop, daemon=True)
            t.start()

    # ------------------------------------------------------------------ load
    def _try_load(self) -> None:
        """Load MMDB files if they exist on disk."""
        try:
            import maxminddb  # type: ignore
            if os.path.exists(self._lite_path):
                self._reader_lite = maxminddb.open_database(self._lite_path)
            if os.path.exists(self._full_path):
                self._reader_full = maxminddb.open_database(self._full_path)
        except ImportError:
            pass  # maxminddb not installed; fall back to ipdeny
        except Exception as exc:
            print(f"[geoip] mmdb load error: {exc}", flush=True)

    # ------------------------------------------------------------------ download
    def ensure_database(self, force_full: bool = False) -> dict[str, Any]:
        """
        Download Country-lite.mmdb (and optionally Country.mmdb).
        Returns status dict.
        """
        results: dict[str, Any] = {}

        # Lite is enough for Iranian use case
        if not os.path.exists(self._lite_path) or force_full:
            ok = _download(MMDB_LITE_URL, self._lite_path)
            results["lite"] = "downloaded" if ok else "failed"
            if ok:
                self._try_load()
        else:
            results["lite"] = "already_exists"

        if force_full and not os.path.exists(self._full_path):
            ok = _download(MMDB_FULL_URL, self._full_path)
            results["full"] = "downloaded" if ok else "failed"
            if ok:
                self._try_load()

        self._last_update = time.time()
        return results

    def refresh(self, full: bool = False) -> dict[str, Any]:
        """Force re-download of database files."""
        try:
            if os.path.exists(self._lite_path):
                os.unlink(self._lite_path)
            if full and os.path.exists(self._full_path):
                os.unlink(self._full_path)
        except OSError:
            pass
        return self.ensure_database(force_full=full)

    def _update_loop(self) -> None:
        """Background thread: re-download every AUTO_UPDATE_INTERVAL seconds."""
        while True:
            time.sleep(3600)
            try:
                age = time.time() - self._last_update
                if age >= AUTO_UPDATE_INTERVAL:
                    self.refresh()
            except Exception as exc:
                print(f"[geoip] auto-update error: {exc}", flush=True)

    # ------------------------------------------------------------------ query
    def _cidrs_from_mmdb(self, reader: Any, iso: str) -> list[str]:
        """Extract all IPv4 CIDRs for a given ISO code from an mmdb reader."""
        iso = iso.strip().upper()
        out: list[str] = []
        try:
            for item1, item2 in reader:
                rec = item1 if isinstance(item1, dict) else item2
                net = item2 if isinstance(item1, dict) else item1
                if not isinstance(rec, dict):
                    continue
                rec_iso = (rec.get("country") or {}).get("iso_code", "")
                if rec_iso != iso:
                    continue
                cidr_str = str(net)
                # IPv4 only
                try:
                    n = ipaddress.ip_network(cidr_str, strict=False)
                    if isinstance(n, ipaddress.IPv4Network) and n.prefixlen >= 1:
                        out.append(cidr_str)
                except ValueError:
                    pass
        except Exception as exc:
            print(f"[geoip] mmdb iter error: {exc}", flush=True)
        return out

    def _cidrs_from_ipdeny(self, iso: str) -> list[str]:
        """Fetch CIDRs from ipdeny.com (cached per session)."""
        iso = iso.strip().upper().lower()
        with self._lock:
            if iso in self._ipdeny_cache:
                return self._ipdeny_cache[iso]

        # Try cached file first
        cache_file = os.path.join(self._ipdeny_dir, f"{iso}.zone")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, encoding="utf-8") as f:
                    text = f.read()
                cidrs = _parse_ipdeny(text)
                with self._lock:
                    self._ipdeny_cache[iso] = cidrs
                return cidrs
            except OSError:
                pass

        # Download fresh
        url = IPDENY_URL.format(iso=iso)
        try:
            os.makedirs(self._ipdeny_dir, mode=0o700, exist_ok=True)
            if _download(url, cache_file, timeout=15):
                with open(cache_file, encoding="utf-8") as f:
                    cidrs = _parse_ipdeny(f.read())
                with self._lock:
                    self._ipdeny_cache[iso] = cidrs
                return cidrs
        except Exception as exc:
            print(f"[geoip] ipdeny error for {iso}: {exc}", flush=True)

        return []

    def country_cidrs(self, iso: str) -> list[str]:
        """
        Return all IPv4 CIDRs for the given country ISO code (e.g. 'IR').

        Uses Country-lite.mmdb if available (best for IR),
        falls back to Country.mmdb, then IPdeny.
        """
        iso = iso.strip().upper()
        if not iso or len(iso) > 20:
            return []

        # 1. Try lite mmdb (fast, IR-focused)
        if self._reader_lite is not None:
            cidrs = self._cidrs_from_mmdb(self._reader_lite, iso)
            if cidrs:
                return cidrs

        # 2. Try full mmdb (all countries)
        if self._reader_full is not None:
            cidrs = self._cidrs_from_mmdb(self._reader_full, iso)
            if cidrs:
                return cidrs

        # 3. IPdeny fallback (no dependency, any country)
        return self._cidrs_from_ipdeny(iso.lower())

    def available_countries(self) -> list[str]:
        """
        List country codes available in the loaded databases.
        Returns country ISO codes only (excludes PRIVATE, CLOUDFLARE, etc.)
        """
        isos: set[str] = set()
        readers = [r for r in (self._reader_lite, self._reader_full) if r is not None]
        for reader in readers:
            try:
                for item1, item2 in reader:
                    rec = item1 if isinstance(item1, dict) else item2
                    if isinstance(rec, dict):
                        iso = (rec.get("country") or {}).get("iso_code", "")
                        # Keep only real ISO-2 country codes (2-3 capital letters)
                        if iso and len(iso) <= 3 and iso.isalpha() and iso.isupper():
                            isos.add(iso)
            except Exception:
                pass
        # Always include IR as ipdeny fallback
        isos.add("IR")
        return sorted(isos)

    def domain_to_cidrs(self, domain: str, resolve_fn=None) -> list[str]:
        """
        Resolve a domain → IP → lookup country → return all country CIDRs.
        Useful for 'route everything in the same country as this domain'.
        """
        import socket

        resolve = resolve_fn or (lambda h: [i[4][0] for i in socket.getaddrinfo(h, None, socket.AF_INET)])
        try:
            ips = resolve(domain)
        except Exception:
            return []

        seen_countries: set[str] = set()
        cidrs: list[str] = []

        for ip_str in ips[:4]:
            try:
                # Lookup country for this IP
                iso = self._lookup_ip_country(ip_str)
                if iso and iso not in seen_countries:
                    seen_countries.add(iso)
                    cidrs.extend(self.country_cidrs(iso))
            except Exception:
                pass

        return cidrs

    def _lookup_ip_country(self, ip_str: str) -> str | None:
        """Lookup country ISO for a single IP address."""
        for reader in (self._reader_lite, self._reader_full):
            if reader is None:
                continue
            try:
                rec = reader.get(ip_str)
                if isinstance(rec, dict):
                    return (rec.get("country") or {}).get("iso_code")
            except Exception:
                pass
        return None

    def status(self) -> dict[str, Any]:
        """Return current status of GeoIP databases."""
        lite_exists = os.path.exists(self._lite_path)
        full_exists = os.path.exists(self._full_path)
        return {
            "mmdb_lite_loaded":  self._reader_lite is not None,
            "mmdb_full_loaded":  self._reader_full is not None,
            "mmdb_lite_path":    self._lite_path,
            "mmdb_full_path":    self._full_path,
            "mmdb_lite_size_kb": os.path.getsize(self._lite_path) // 1024 if lite_exists else 0,
            "mmdb_full_size_kb": os.path.getsize(self._full_path) // 1024 if full_exists else 0,
            "ipdeny_cached":     list(self._ipdeny_cache.keys()),
            "last_update":       self._last_update,
            "source":            (
                "mmdb_lite" if self._reader_lite else
                "mmdb_full" if self._reader_full else
                "ipdeny"
            ),
            # Quick test for IR
            "ir_networks": len(self.country_cidrs("IR")),
        }
