#!/usr/bin/env python3
# insigniaDNS

import argparse
import ipaddress
import json
import queue
import socket
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from sys import platform
from typing import Dict, List, Optional, Tuple

from dnslib import A, DNSLabel, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import DNSServer
from requests import get
from requests.exceptions import RequestException, Timeout


APP_VERSION = "1.2.0"
APP_NAME = "insigniaDNS"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
CACHE_PATH = BASE_DIR / "dns_cache.json"
DEFAULT_HEALTH_HOSTS = [("1.1.1.1", 443), ("8.8.8.8", 53)]
DEFAULT_PUBLIC_DNS = ["1.1.1.1", "8.8.8.8"]
CONFIG_POLL_INTERVAL_SEC = 2
UPSTREAM_TIMEOUT_SEC = 2.0
ZONE_FETCH_TIMEOUT_SEC = 5.0
UPDATE_CHECK_INTERVAL_SEC = 6 * 60 * 60
TRAP_CHECK_INTERVAL_SEC = 15 * 60
REVALIDATION_BURST = 10

DEFAULT_CONFIG = {
    "listen_ip": "auto",
    "port": 53,
    "zones_url": "https://insignia.live/dns_zones.json",
    "refresh_interval_sec": 900,
    "upstream_dns": "1.1.1.1",
    "cache_enabled": True,
    "cache_ttl_sec": 300,
    "persist_cache": False,
    "metrics_enabled": False,
    "metrics_port": 9090,
    "health_print_interval": 10,
    "dns_trap_detection": True,
    "update_check_url": "https://insignia.live/version.json",
}

LOG_LOCK = threading.Lock()


def log(level: str, message: str, **fields) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    suffix = ""
    if fields:
        rendered = " ".join(f"{key}={fields[key]}" for key in sorted(fields))
        suffix = f" | {rendered}"
    with LOG_LOCK:
        print(f"{timestamp} [{level}] {message}{suffix}", flush=True)


def log_health(snapshot: Dict[str, str]) -> None:
    lines = [
        "[HEALTH]",
        f"Zones: {snapshot['zones']}",
        f"Upstream DNS: {snapshot['upstream']}",
        f"Internet: {snapshot['internet']}",
        f"DNS Check: {snapshot['dns_check']}",
        f"Cache: {snapshot['cache']}",
        f"Mode: {snapshot['mode']}",
        f"Trap Detection: {snapshot['trap']}",
    ]
    with LOG_LOCK:
        print("\n".join(lines), flush=True)


def get_platform_name() -> str:
    platforms = {
        "linux1": "Linux",
        "linux2": "Linux",
        "linux": "Linux",
        "darwin": "macOS",
        "win32": "Windows",
    }
    return platforms.get(platform, platform)


def format_ip(address: str) -> str:
    octets = str(address).split(".")
    return f"{int(octets[0]):03d}.{int(octets[1]):03d}.{int(octets[2]):03d}.{int(octets[3]):03d}"


def format_console_dns_value(address: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(address)
    except ValueError:
        return address
    if ip_obj.version == 4:
        return format_ip(address)
    return address


def detect_local_ip() -> str:
    probes = [("10.255.255.255", 1), ("1.1.1.1", 80), ("8.8.8.8", 80)]
    for host, port in probes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((host, port))
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def fqdn(name) -> str:
    return str(DNSLabel(str(name))).lower()


def is_private_address(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def is_loopback_address(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def choose_bind_ip(configured_ip: str) -> str:
    if configured_ip == "auto":
        return detect_local_ip()
    return configured_ip


def safe_int(value, default: int, minimum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, parsed)


def safe_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("1", "true", "yes", "on"):
            return True
        if lowered in ("0", "false", "no", "off"):
            return False
    return default


def merge_config(raw_config: dict) -> dict:
    config = dict(DEFAULT_CONFIG)
    if not isinstance(raw_config, dict):
        return config

    if isinstance(raw_config.get("listen_ip"), str) and raw_config["listen_ip"].strip():
        config["listen_ip"] = raw_config["listen_ip"].strip()
    if isinstance(raw_config.get("zones_url"), str) and raw_config["zones_url"].strip():
        config["zones_url"] = raw_config["zones_url"].strip()
    if isinstance(raw_config.get("upstream_dns"), str) and raw_config["upstream_dns"].strip():
        config["upstream_dns"] = raw_config["upstream_dns"].strip()
    if isinstance(raw_config.get("update_check_url"), str) and raw_config["update_check_url"].strip():
        config["update_check_url"] = raw_config["update_check_url"].strip()

    config["port"] = safe_int(raw_config.get("port"), DEFAULT_CONFIG["port"], 1)
    config["refresh_interval_sec"] = safe_int(
        raw_config.get("refresh_interval_sec"),
        DEFAULT_CONFIG["refresh_interval_sec"],
        30,
    )
    config["cache_ttl_sec"] = safe_int(raw_config.get("cache_ttl_sec"), DEFAULT_CONFIG["cache_ttl_sec"], 1)
    config["metrics_port"] = safe_int(raw_config.get("metrics_port"), DEFAULT_CONFIG["metrics_port"], 1)
    config["health_print_interval"] = safe_int(
        raw_config.get("health_print_interval"),
        DEFAULT_CONFIG["health_print_interval"],
        5,
    )

    config["cache_enabled"] = safe_bool(raw_config.get("cache_enabled"), DEFAULT_CONFIG["cache_enabled"])
    config["persist_cache"] = safe_bool(raw_config.get("persist_cache"), DEFAULT_CONFIG["persist_cache"])
    config["metrics_enabled"] = safe_bool(raw_config.get("metrics_enabled"), DEFAULT_CONFIG["metrics_enabled"])
    config["dns_trap_detection"] = safe_bool(
        raw_config.get("dns_trap_detection"),
        DEFAULT_CONFIG["dns_trap_detection"],
    )

    fallback_dns = raw_config.get("fallback_dns")
    if isinstance(fallback_dns, str) and fallback_dns.strip():
        config["fallback_dns"] = [fallback_dns.strip()]
    elif isinstance(fallback_dns, list):
        config["fallback_dns"] = [str(item).strip() for item in fallback_dns if str(item).strip()]
    else:
        config["fallback_dns"] = []

    return config


def atomic_write_json(path: Path, payload: dict) -> None:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temp_path.replace(path)


def ensure_default_config(path: Path) -> None:
    if path.exists():
        return
    atomic_write_json(path, DEFAULT_CONFIG)
    log("INFO", "Generated default config.json", path=str(path))


def load_json_file(path: Path) -> Tuple[Optional[dict], Optional[str]]:
    if not path.exists():
        return None, "missing"
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle), None
    except (OSError, ValueError) as exc:
        return None, str(exc)


def parse_version(version: str) -> Tuple[int, ...]:
    parts = []
    for piece in str(version).split("."):
        digits = "".join(char for char in piece if char.isdigit())
        if digits:
            parts.append(int(digits))
        else:
            parts.append(0)
    return tuple(parts)


@dataclass
class ZoneRecord:
    ip: str
    ttl: int = 300

    def try_rr(self, question) -> Optional[RR]:
        if question.qtype in (QTYPE.A, QTYPE.ANY):
            return RR(rname=question.qname, rtype=QTYPE.A, rdata=A(self.ip), ttl=self.ttl)
        return None


@dataclass
class CachedResponse:
    qname: str
    qtype: int
    response_hex: str
    stored_at: float
    expires_at: float
    stale_until: float
    ttl_sec: int
    kind: str


class Metrics:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.counters = defaultdict(int)
        self.gauges = {
            "trap_detection_score": 0,
            "update_available": 0,
            "cache_entries": 0,
        }

    def inc(self, name: str, amount: int = 1) -> None:
        with self.lock:
            self.counters[name] += amount

    def set_gauge(self, name: str, value) -> None:
        with self.lock:
            self.gauges[name] = value

    def snapshot(self) -> Dict[str, float]:
        with self.lock:
            data = dict(self.counters)
            data.update(self.gauges)
        return data

    def render_prometheus(self) -> str:
        snapshot = self.snapshot()
        lines = [
            f"dns_requests_total {snapshot.get('dns_requests_total', 0)}",
            f"cache_hits {snapshot.get('cache_hits', 0)}",
            f"cache_misses {snapshot.get('cache_misses', 0)}",
            f"upstream_failures {snapshot.get('upstream_failures', 0)}",
            f"zone_refresh_success {snapshot.get('zone_refresh_success', 0)}",
            f"zone_refresh_failures {snapshot.get('zone_refresh_failures', 0)}",
            f"trap_detection_score {snapshot.get('trap_detection_score', 0)}",
            f"update_available {snapshot.get('update_available', 0)}",
            f"cache_entries {snapshot.get('cache_entries', 0)}",
        ]
        return "\n".join(lines) + "\n"


class ConfigManager:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.config = dict(DEFAULT_CONFIG)
        self.last_mtime = None
        self.last_error = None
        self.load(force=True)

    def load(self, force: bool = False) -> Tuple[dict, bool]:
        changed = False
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            mtime = None
        if not force and mtime == self.last_mtime:
            return self.get(), False

        raw_config, error = load_json_file(self.path)
        if raw_config is None:
            if error == "missing":
                ensure_default_config(self.path)
                raw_config = dict(DEFAULT_CONFIG)
                error = None
                try:
                    mtime = self.path.stat().st_mtime
                except OSError:
                    mtime = None
            else:
                log("WARN", "Invalid config.json, falling back to defaults", error=error)
                raw_config = dict(DEFAULT_CONFIG)
        merged = merge_config(raw_config)
        with self.lock:
            if merged != self.config:
                changed = True
            self.config = merged
            self.last_mtime = mtime
            self.last_error = error
        if changed or force:
            log("INFO", "Loaded configuration", listen_ip=merged["listen_ip"], port=merged["port"])
        return self.get(), changed

    def get(self) -> dict:
        with self.lock:
            return dict(self.config)


class DNSCache:
    def __init__(self, metrics: Metrics, path: Path) -> None:
        self.metrics = metrics
        self.path = path
        self.lock = threading.Lock()
        self.entries: Dict[Tuple[str, int], CachedResponse] = {}
        self.pending_revalidation = set()
        self.revalidation_queue = queue.Queue()

    def _update_size_metric(self) -> None:
        self.metrics.set_gauge("cache_entries", len(self.entries))

    def load_persisted(self) -> None:
        payload, error = load_json_file(self.path)
        if payload is None:
            if error and error != "missing":
                log("WARN", "Could not read persisted cache", error=error)
            return
        entries = payload.get("entries", []) if isinstance(payload, dict) else []
        loaded = 0
        now = time.time()
        with self.lock:
            for item in entries:
                try:
                    entry = CachedResponse(
                        qname=str(item["qname"]),
                        qtype=int(item["qtype"]),
                        response_hex=str(item["response_hex"]),
                        stored_at=float(item["stored_at"]),
                        expires_at=float(item["expires_at"]),
                        stale_until=float(item["stale_until"]),
                        ttl_sec=int(item["ttl_sec"]),
                        kind=str(item["kind"]),
                    )
                except (KeyError, TypeError, ValueError):
                    continue
                if entry.stale_until > now:
                    self.entries[(entry.qname, entry.qtype)] = entry
                    loaded += 1
            self._update_size_metric()
        if loaded:
            log("CACHE", "Reloaded persisted cache", entries=loaded)

    def persist(self) -> None:
        now = time.time()
        with self.lock:
            entries = [
                {
                    "qname": entry.qname,
                    "qtype": entry.qtype,
                    "response_hex": entry.response_hex,
                    "stored_at": entry.stored_at,
                    "expires_at": entry.expires_at,
                    "stale_until": entry.stale_until,
                    "ttl_sec": entry.ttl_sec,
                    "kind": entry.kind,
                }
                for entry in self.entries.values()
                if entry.stale_until > now
            ]
        atomic_write_json(self.path, {"entries": entries, "saved_at": now})
        log("CACHE", "Persisted cache to disk", entries=len(entries), path=str(self.path))

    def get(self, qname: str, qtype: int) -> Tuple[Optional[CachedResponse], Optional[str]]:
        key = (qname, qtype)
        now = time.time()
        with self.lock:
            entry = self.entries.get(key)
            if entry is None:
                return None, None
            if entry.expires_at > now:
                return entry, "fresh"
            if entry.stale_until > now:
                return entry, "stale"
            self.entries.pop(key, None)
            self.pending_revalidation.discard(key)
            self._update_size_metric()
        return None, None

    def set(self, entry: CachedResponse) -> None:
        key = (entry.qname, entry.qtype)
        with self.lock:
            self.entries[key] = entry
            self._update_size_metric()

    def invalidate_names(self, names: set) -> None:
        if not names:
            return
        names = {fqdn(name) for name in names}
        with self.lock:
            doomed = [key for key in self.entries if key[0] in names]
            for key in doomed:
                self.entries.pop(key, None)
                self.pending_revalidation.discard(key)
            self._update_size_metric()
        if doomed:
            log("CACHE", "Invalidated cache entries after zone update", entries=len(doomed))

    def queue_revalidation(self, qname: str, qtype: int) -> None:
        key = (qname, qtype)
        with self.lock:
            if key in self.pending_revalidation:
                return
            self.pending_revalidation.add(key)
        self.revalidation_queue.put(key)

    def pop_revalidation_batch(self, limit: int) -> List[Tuple[str, int]]:
        items = []
        for _ in range(limit):
            try:
                items.append(self.revalidation_queue.get_nowait())
            except queue.Empty:
                break
        return items

    def mark_revalidation_done(self, key: Tuple[str, int]) -> None:
        with self.lock:
            self.pending_revalidation.discard(key)

    def size(self) -> int:
        with self.lock:
            return len(self.entries)


class ZoneManager:
    def __init__(self, config_manager: ConfigManager, metrics: Metrics, cache: DNSCache) -> None:
        self.config_manager = config_manager
        self.metrics = metrics
        self.cache = cache
        self.lock = threading.Lock()
        self.zones: Dict[str, List[ZoneRecord]] = {}
        self.last_successful_payload = None
        self.last_zone_keys = set()
        self.last_refresh_ok = False
        self.last_refresh_latency_ms = None
        self.last_refresh_error = "never fetched"
        self.last_refresh_at = None
        self.stop_event = threading.Event()
        self.thread = None

    def get_snapshot(self) -> Dict[str, List[ZoneRecord]]:
        with self.lock:
            return dict(self.zones)

    def get_names(self) -> List[str]:
        with self.lock:
            return sorted(self.zones.keys())

    def get_status(self) -> dict:
        with self.lock:
            return {
                "ok": self.last_refresh_ok,
                "latency_ms": self.last_refresh_latency_ms,
                "error": self.last_refresh_error,
                "refreshed_at": self.last_refresh_at,
                "count": len(self.zones),
            }

    def _parse_zone_json(self, payload: list) -> Dict[str, List[ZoneRecord]]:
        if not isinstance(payload, list):
            raise ValueError("zone payload must be a list")

        parsed = {}
        for item in payload:
            if not isinstance(item, dict):
                raise ValueError("zone entry must be an object")
            name = item.get("name")
            zone_type = str(item.get("type", "")).lower()
            value = item.get("value")
            if not name or zone_type not in ("a", "p") or not value:
                raise ValueError("zone entry missing required fields")
            name_fqdn = fqdn(name)
            if zone_type == "a":
                target_ip = str(ipaddress.ip_address(str(value)))
            else:
                target_ip = socket.gethostbyname(str(value))
            parsed[name_fqdn] = [ZoneRecord(ip=target_ip)]
        return parsed

    def refresh_once(self, timeout_sec: float = ZONE_FETCH_TIMEOUT_SEC) -> bool:
        config = self.config_manager.get()
        started = time.monotonic()
        try:
            response = get(
                config["zones_url"],
                headers={"User-Agent": f"{APP_NAME}/{APP_VERSION} ({get_platform_name()})"},
                timeout=timeout_sec,
            )
            response.raise_for_status()
            payload = response.json()
            parsed_zones = self._parse_zone_json(payload)
        except (RequestException, Timeout, ValueError, OSError) as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            with self.lock:
                self.last_refresh_ok = False
                self.last_refresh_latency_ms = latency_ms
                self.last_refresh_error = str(exc)
            self.metrics.inc("zone_refresh_failures")
            log("WARN", "Zone refresh failed", error=str(exc), latency_ms=latency_ms)
            return False

        latency_ms = int((time.monotonic() - started) * 1000)
        with self.lock:
            previous_keys = set(self.zones.keys())
            self.zones = parsed_zones
            self.last_successful_payload = payload
            self.last_zone_keys = set(parsed_zones.keys())
            self.last_refresh_ok = True
            self.last_refresh_latency_ms = latency_ms
            self.last_refresh_error = ""
            self.last_refresh_at = time.time()
        self.cache.invalidate_names(previous_keys | set(parsed_zones.keys()))
        self.metrics.inc("zone_refresh_success")
        log("INFO", "Zone refresh succeeded", zones=len(parsed_zones), latency_ms=latency_ms)
        return True

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._loop, name="zone-refresh", daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        backoff = 1
        while not self.stop_event.is_set():
            config = self.config_manager.get()
            ok = self.refresh_once()
            wait_for = config["refresh_interval_sec"] if ok else min(config["refresh_interval_sec"], backoff)
            if not ok:
                backoff = min(backoff * 2, config["refresh_interval_sec"])
            else:
                backoff = 1
            if self.stop_event.wait(wait_for):
                break

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)


class ForwardResult:
    def __init__(self, response: Optional[DNSRecord], server: str, latency_ms: Optional[int], error: Optional[str]):
        self.response = response
        self.server = server
        self.latency_ms = latency_ms
        self.error = error


class UpstreamForwarder:
    def __init__(self, config_manager: ConfigManager, metrics: Metrics) -> None:
        self.config_manager = config_manager
        self.metrics = metrics
        self.lock = threading.Lock()
        self.server_health = {}

    def _record_health(self, server: str, ok: bool, latency_ms: Optional[int], error: Optional[str]) -> None:
        with self.lock:
            self.server_health[server] = {
                "ok": ok,
                "latency_ms": latency_ms,
                "error": error,
                "checked_at": time.time(),
            }

    def get_health(self, server: str) -> dict:
        with self.lock:
            return dict(self.server_health.get(server, {}))

    def _query_server(self, request: DNSRecord, server: str, timeout_sec: float = UPSTREAM_TIMEOUT_SEC) -> ForwardResult:
        started = time.monotonic()
        payload = request.pack()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_sec)
        try:
            sock.sendto(payload, (server, 53))
            response_data, _ = sock.recvfrom(4096)
            response = DNSRecord.parse(response_data)
            latency_ms = int((time.monotonic() - started) * 1000)
            self._record_health(server, True, latency_ms, None)
            return ForwardResult(response=response, server=server, latency_ms=latency_ms, error=None)
        except (OSError, ValueError) as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            self._record_health(server, False, latency_ms, str(exc))
            return ForwardResult(response=None, server=server, latency_ms=latency_ms, error=str(exc))
        finally:
            sock.close()

    def resolve(self, request: DNSRecord) -> ForwardResult:
        config = self.config_manager.get()
        servers = [config["upstream_dns"]]
        for fallback in config.get("fallback_dns", []):
            if fallback not in servers:
                servers.append(fallback)
        last_result = None
        for server in servers:
            result = self._query_server(request, server)
            last_result = result
            if result.response is not None:
                return result
        self.metrics.inc("upstream_failures")
        return last_result or ForwardResult(response=None, server=config["upstream_dns"], latency_ms=None, error="no upstream configured")

    def simple_lookup(self, qname: str, server: str, qtype: str = "A") -> ForwardResult:
        request = DNSRecord.question(qname, qtype)
        return self._query_server(request, server)


class ResolverStatsLogger:
    def log_recv(self, handler, data):
        return

    def log_send(self, handler, data):
        return

    def log_request(self, handler, request):
        log("DNS", "Received request", client=handler.client_address[0], qname=str(request.q.qname), qtype=QTYPE[request.q.qtype])

    def log_reply(self, handler, reply):
        log("DNS", "Sent reply", client=handler.client_address[0], rcode=RCODE[reply.header.rcode], answers=len(reply.rr))

    def log_error(self, handler, exc):
        log("ERROR", "Invalid DNS request", client=handler.client_address[0], error=str(exc))

    def log_truncated(self, handler, reply):
        return

    def log_data(self, dnsobj):
        return


class InsigniaResolver:
    def __init__(self, config_manager: ConfigManager, zone_manager: ZoneManager, cache: DNSCache, forwarder: UpstreamForwarder, metrics: Metrics) -> None:
        self.config_manager = config_manager
        self.zone_manager = zone_manager
        self.cache = cache
        self.forwarder = forwarder
        self.metrics = metrics

    def _response_ttl(self, reply: DNSRecord, config: dict, fallback_ttl: int) -> int:
        ttls = [rr.ttl for rr in list(reply.rr) + list(reply.auth) + list(reply.ar) if getattr(rr, "ttl", None) is not None]
        derived = min(ttls) if ttls else fallback_ttl
        return max(1, min(config["cache_ttl_sec"], int(derived)))

    def _cache_reply(self, request: DNSRecord, reply: DNSRecord, kind: str, ttl_sec: int) -> None:
        config = self.config_manager.get()
        if not config["cache_enabled"]:
            return
        qname = fqdn(request.q.qname)
        qtype = request.q.qtype
        now = time.time()
        entry = CachedResponse(
            qname=qname,
            qtype=qtype,
            response_hex=reply.pack().hex(),
            stored_at=now,
            expires_at=now + ttl_sec,
            stale_until=now + (ttl_sec * 2),
            ttl_sec=ttl_sec,
            kind=kind,
        )
        self.cache.set(entry)

    def _build_cached_reply(self, request: DNSRecord, entry: CachedResponse, state: str) -> Optional[DNSRecord]:
        try:
            reply = DNSRecord.parse(bytes.fromhex(entry.response_hex))
        except (ValueError, TypeError):
            return None
        now = time.time()
        remaining = int(entry.expires_at - now)
        ttl_value = 1 if state == "stale" else max(1, remaining)
        reply.header.id = request.header.id
        for record in list(reply.rr) + list(reply.auth) + list(reply.ar):
            record.ttl = min(record.ttl, ttl_value) if record.ttl else ttl_value
        return reply

    def _make_servfail(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply

    def _make_zone_reply(self, request: DNSRecord, zone_records: List[ZoneRecord]) -> DNSRecord:
        reply = request.reply()
        for record in zone_records:
            rr = record.try_rr(request.q)
            if rr:
                reply.add_answer(rr)
        return reply

    def _resolve_without_cache(self, request: DNSRecord) -> DNSRecord:
        config = self.config_manager.get()
        qname = fqdn(request.q.qname)
        zone_records = self.zone_manager.get_snapshot().get(qname)

        if zone_records is not None:
            reply = self._make_zone_reply(request, zone_records)
            ttl_sec = self._response_ttl(reply, config, fallback_ttl=300)
            self._cache_reply(request, reply, "zone", ttl_sec)
            return reply

        forward_result = self.forwarder.resolve(request)
        if forward_result.response is not None:
            ttl_fallback = 60 if forward_result.response.header.rcode == RCODE.NXDOMAIN else config["cache_ttl_sec"]
            ttl_sec = self._response_ttl(forward_result.response, config, fallback_ttl=ttl_fallback)
            self._cache_reply(request, forward_result.response, "upstream", ttl_sec)
            return forward_result.response

        reply = self._make_servfail(request)
        self._cache_reply(request, reply, "servfail", min(30, config["cache_ttl_sec"]))
        return reply

    def revalidate_key(self, qname: str, qtype: int) -> None:
        try:
            qtype_name = QTYPE[qtype]
        except KeyError:
            qtype_name = "A"
        request = DNSRecord.question(qname, qtype_name)
        try:
            self._resolve_without_cache(request)
        except Exception as exc:
            log("WARN", "Cache revalidation failed", qname=qname, qtype=qtype_name, error=str(exc))

    def resolve(self, request, handler):
        self.metrics.inc("dns_requests_total")
        qname = fqdn(request.q.qname)
        qtype = request.q.qtype
        config = self.config_manager.get()

        if config["cache_enabled"]:
            entry, state = self.cache.get(qname, qtype)
            if entry is not None and state:
                cached_reply = self._build_cached_reply(request, entry, state)
                if cached_reply is not None:
                    self.metrics.inc("cache_hits")
                    if state == "stale":
                        self.cache.queue_revalidation(qname, qtype)
                    return cached_reply
            self.metrics.inc("cache_misses")

        try:
            return self._resolve_without_cache(request)
        except Exception as exc:
            log("ERROR", "Resolver failure", qname=qname, qtype=QTYPE[qtype], error=str(exc))
            return self._make_servfail(request)


class MaintenanceManager:
    def __init__(
        self,
        config_manager: ConfigManager,
        zone_manager: ZoneManager,
        forwarder: UpstreamForwarder,
        cache: DNSCache,
        resolver: InsigniaResolver,
        metrics: Metrics,
        bind_ip: str,
    ) -> None:
        self.config_manager = config_manager
        self.zone_manager = zone_manager
        self.forwarder = forwarder
        self.cache = cache
        self.resolver = resolver
        self.metrics = metrics
        self.bind_ip = bind_ip
        self.stop_event = threading.Event()
        self.thread = None
        self.last_health = 0.0
        self.last_trap = 0.0
        self.last_update = 0.0
        self.last_config = 0.0
        self.last_health_snapshot = {
            "zones": "UNKNOWN",
            "upstream": "UNKNOWN",
            "internet": "UNKNOWN",
            "dns_check": "UNKNOWN",
            "cache": "0 entries",
            "mode": "STARTING",
            "trap": "UNKNOWN",
        }
        self.trap_score = 0
        self.update_available = False
        self.last_update_version = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._loop, name="maintenance", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def _check_internet(self) -> Tuple[bool, str]:
        for host, port in DEFAULT_HEALTH_HOSTS:
            try:
                started = time.monotonic()
                sock = socket.create_connection((host, port), timeout=2)
                sock.close()
                latency_ms = int((time.monotonic() - started) * 1000)
                return True, f"OK ({latency_ms}ms)"
            except OSError:
                continue
        return False, "DOWN"

    def _check_dns(self, server: str) -> Tuple[bool, str]:
        result = self.forwarder.simple_lookup("example.com", server, "A")
        if result.response is None:
            return False, f"FAIL ({result.error})"
        if result.response.header.rcode != RCODE.NOERROR or not result.response.rr:
            return False, f"FAIL (rcode={RCODE[result.response.header.rcode]})"
        return True, f"OK ({result.latency_ms}ms)"

    def _check_zones_endpoint(self) -> Tuple[bool, str]:
        status = self.zone_manager.get_status()
        if status["ok"] and status["latency_ms"] is not None:
            return True, f"OK ({status['latency_ms']}ms)"
        if status["error"]:
            return False, f"FAIL ({status['error']})"
        return False, "FAIL"

    def _run_trap_detection(self, config: dict) -> None:
        if not config["dns_trap_detection"]:
            self.trap_score = 0
            self.metrics.set_gauge("trap_detection_score", 0)
            self.last_health_snapshot["trap"] = "DISABLED"
            return

        zone_names = self.zone_manager.get_names()[:5]
        if not zone_names:
            self.trap_score = 0
            self.metrics.set_gauge("trap_detection_score", 0)
            self.last_health_snapshot["trap"] = "NO DATA"
            return

        fallback_public = DEFAULT_PUBLIC_DNS[0]
        if config["upstream_dns"] == fallback_public:
            fallback_public = DEFAULT_PUBLIC_DNS[1]

        mismatches = 0
        checks = 0
        zone_snapshot = self.zone_manager.get_snapshot()

        for zone_name in zone_names:
            expected_ips = {record.ip for record in zone_snapshot.get(zone_name, [])}
            upstream = self.forwarder.simple_lookup(zone_name, config["upstream_dns"], "A")
            public = self.forwarder.simple_lookup(zone_name, fallback_public, "A")
            upstream_ips = {
                str(rr.rdata)
                for rr in (upstream.response.rr if upstream.response is not None else [])
                if rr.rtype == QTYPE.A
            }
            public_ips = {
                str(rr.rdata)
                for rr in (public.response.rr if public.response is not None else [])
                if rr.rtype == QTYPE.A
            }
            checks += 1
            if upstream.response is None or upstream.response.header.rcode == RCODE.NXDOMAIN:
                mismatches += 1
                continue
            if expected_ips and upstream_ips != expected_ips and public_ips == expected_ips:
                mismatches += 1
                continue
            if public.response is not None and public.response.header.rcode == RCODE.NXDOMAIN and upstream_ips:
                mismatches += 1

        confidence = int((mismatches / max(1, checks)) * 100)
        self.trap_score = confidence
        self.metrics.set_gauge("trap_detection_score", confidence)
        if confidence >= 50:
            log("WARN", "Possible DNS interception detected", confidence=f"{confidence}%")
            self.last_health_snapshot["trap"] = f"WARNING ({confidence}%)"
        else:
            self.last_health_snapshot["trap"] = f"CLEAN ({confidence}%)"

    def _run_update_check(self, config: dict) -> None:
        try:
            response = get(
                config["update_check_url"],
                headers={"User-Agent": f"{APP_NAME}/{APP_VERSION} ({get_platform_name()})"},
                timeout=4,
            )
            response.raise_for_status()
            payload = response.json()
            latest_version = str(payload.get("latest_version", "")).strip()
            if latest_version and parse_version(latest_version) > parse_version(APP_VERSION):
                self.update_available = True
                self.last_update_version = latest_version
                self.metrics.set_gauge("update_available", 1)
                log("UPDATE", f"New version available: {latest_version} (current: {APP_VERSION})")
            else:
                self.update_available = False
                self.last_update_version = latest_version or APP_VERSION
                self.metrics.set_gauge("update_available", 0)
        except (RequestException, Timeout, ValueError) as exc:
            self.update_available = False
            self.metrics.set_gauge("update_available", 0)
            log("WARN", "Update check failed", error=str(exc))

    def _report_health(self, config: dict) -> None:
        zones_ok, zones_status = self._check_zones_endpoint()
        upstream_ok, upstream_status = self._check_dns(config["upstream_dns"])
        internet_ok, internet_status = self._check_internet()
        public_dns_ok, public_dns_status = self._check_dns(DEFAULT_PUBLIC_DNS[0])

        if not internet_ok:
            mode = "INTERNET_DOWN"
        elif not upstream_ok:
            mode = "UPSTREAM_FAILURE"
        elif not public_dns_ok:
            mode = "DNS_FAILURE"
        elif not zones_ok:
            mode = "ZONE_FAILURE"
        else:
            mode = "NORMAL"

        self.last_health_snapshot = {
            "zones": zones_status,
            "upstream": upstream_status,
            "internet": internet_status,
            "dns_check": public_dns_status,
            "cache": f"{self.cache.size()} entries",
            "mode": mode,
            "trap": self.last_health_snapshot.get("trap", "UNKNOWN"),
        }
        log_health(self.last_health_snapshot)

    def _check_runtime_config_changes(self, config: dict) -> None:
        effective_bind = choose_bind_ip(config["listen_ip"])
        if effective_bind != self.bind_ip:
            log("WARN", "listen_ip changed in config.json; restart required to apply", current=self.bind_ip, configured=effective_bind)
        if config["port"] != DEFAULT_CONFIG["port"]:
            log("WARN", "Non-default DNS port configured; clients must use that port explicitly", port=config["port"])

    def _drain_revalidation_queue(self) -> None:
        for key in self.cache.pop_revalidation_batch(REVALIDATION_BURST):
            try:
                self.resolver.revalidate_key(key[0], key[1])
            finally:
                self.cache.mark_revalidation_done(key)

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            now = time.time()
            config = self.config_manager.get()

            if now - self.last_config >= CONFIG_POLL_INTERVAL_SEC:
                config, changed = self.config_manager.load()
                if changed:
                    self._check_runtime_config_changes(config)
                self.last_config = now

            self._drain_revalidation_queue()

            if now - self.last_health >= config["health_print_interval"]:
                self._report_health(config)
                self.last_health = now

            if now - self.last_trap >= TRAP_CHECK_INTERVAL_SEC:
                self._run_trap_detection(config)
                self.last_trap = now

            if now - self.last_update >= UPDATE_CHECK_INTERVAL_SEC:
                self._run_update_check(config)
                self.last_update = now

            if self.stop_event.wait(1):
                break


class MetricsServer:
    def __init__(self, bind_ip: str, port: int, metrics: Metrics) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.metrics = metrics
        self.httpd = None
        self.thread = None

    def start(self) -> None:
        metrics = self.metrics

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/metrics":
                    self.send_response(404)
                    self.end_headers()
                    return
                payload = metrics.render_prometheus().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):
                return

        self.httpd = HTTPServer((self.bind_ip, self.port), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="metrics-server", daemon=True)
        self.thread.start()
        log("INFO", "Metrics endpoint enabled", url=f"http://{self.bind_ip}:{self.port}/metrics")

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)


def print_banner(bind_ip: str) -> None:
    print("+===============================+")
    print("|      Insignia DNS Server      |")
    print(f"|         Version {APP_VERSION:<5}         |")
    print("+===============================+\n")
    print("== Welcome to insigniaDNS! ==")
    print("This server helps Xbox Original clients reach Insignia services when an ISP interferes with custom DNS.\n")
    print("== How To Use ==")
    print("First, make sure that your console is connected to the same LAN as this computer.\n")
    print("Then, put these settings in for DNS on your console:")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print(f"Primary DNS:   {format_console_dns_value(bind_ip)}")
    print("Secondary DNS: 001.001.001.001")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    print("== Getting Help ==")
    print("Need help? Visit our Discord server or check out https://support.insignia.live\n")


def print_platform_notes() -> None:
    operating_system = get_platform_name()
    log("INFO", "Detected operating system", platform=operating_system)
    if operating_system in ("Linux", "macOS"):
        log("INFO", "Binding to UDP/TCP port 53 usually requires root or equivalent privileges")
    elif operating_system == "Windows":
        log("INFO", "Allow the application through the firewall if Windows prompts for network access")


def run_setup_wizard(config_manager: ConfigManager, zone_manager: ZoneManager, forwarder: UpstreamForwarder) -> int:
    config = config_manager.get()
    detected_ip = choose_bind_ip(config["listen_ip"])
    print_banner(detected_ip)
    print_platform_notes()
    print("== Setup Wizard ==")
    print(f"Config path: {CONFIG_PATH}")
    print(f"Detected LAN IP: {detected_ip}")
    print(f"Configured upstream DNS: {config['upstream_dns']}")

    zone_ok = zone_manager.refresh_once(timeout_sec=4)
    upstream_result = forwarder.simple_lookup("example.com", config["upstream_dns"], "A")

    print("\nChecks:")
    print(f"- Zone endpoint reachable: {'YES' if zone_ok else 'NO'}")
    print(f"- Upstream DNS reachable: {'YES' if upstream_result.response is not None else 'NO'}")
    if upstream_result.response is not None:
        print(f"- Upstream latency: {upstream_result.latency_ms}ms")
    else:
        print(f"- Upstream error: {upstream_result.error}")

    print("\nConsole DNS settings:")
    print(f"- Primary DNS: {format_console_dns_value(detected_ip)}")
    print("- Secondary DNS: 1.1.1.1")

    if not is_private_address(detected_ip):
        print("\nWarning: the detected bind IP is not a private LAN address. This tool is intended for LAN use only.")

    print("\nNext step:")
    print(f"- Run: python {Path(__file__).name}")
    return 0


def start_servers(bind_ip: str, port: int, resolver: InsigniaResolver, dns_logger: ResolverStatsLogger):
    return [
        DNSServer(resolver=resolver, port=port, address=bind_ip, tcp=True, logger=dns_logger),
        DNSServer(resolver=resolver, port=port, address=bind_ip, tcp=False, logger=dns_logger),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Insignia LAN DNS redirect service")
    parser.add_argument("--setup", action="store_true", help="run setup checks and generate config.json if needed")
    args = parser.parse_args()

    ensure_default_config(CONFIG_PATH)
    config_manager = ConfigManager(CONFIG_PATH)
    metrics = Metrics()
    cache = DNSCache(metrics=metrics, path=CACHE_PATH)
    config = config_manager.get()
    if config["persist_cache"]:
        cache.load_persisted()

    zone_manager = ZoneManager(config_manager=config_manager, metrics=metrics, cache=cache)
    forwarder = UpstreamForwarder(config_manager=config_manager, metrics=metrics)
    resolver = InsigniaResolver(
        config_manager=config_manager,
        zone_manager=zone_manager,
        cache=cache,
        forwarder=forwarder,
        metrics=metrics,
    )

    if args.setup:
        return run_setup_wizard(config_manager, zone_manager, forwarder)

    bind_ip = choose_bind_ip(config["listen_ip"])
    port = config["port"]

    print_banner(bind_ip)
    print_platform_notes()

    if not is_private_address(bind_ip):
        if is_loopback_address(bind_ip):
            log("WARN", "Binding to loopback only. This is fine for testing, but LAN clients will not reach the server", bind_ip=bind_ip)
        else:
            log("ERROR", "Refusing to bind to a non-private address. insigniaDNS is intended for LAN use only", bind_ip=bind_ip)
            return 1

    zone_manager.refresh_once(timeout_sec=4)
    zone_manager.start()

    maintenance = MaintenanceManager(
        config_manager=config_manager,
        zone_manager=zone_manager,
        forwarder=forwarder,
        cache=cache,
        resolver=resolver,
        metrics=metrics,
        bind_ip=bind_ip,
    )
    maintenance.start()

    metrics_server = None
    if config["metrics_enabled"]:
        try:
            metrics_server = MetricsServer(bind_ip=bind_ip, port=config["metrics_port"], metrics=metrics)
            metrics_server.start()
        except OSError as exc:
            log("WARN", "Metrics endpoint could not start", error=str(exc))

    try:
        servers = start_servers(bind_ip, port, resolver, ResolverStatsLogger())
    except PermissionError:
        log("ERROR", "Permission error: run as administrator/root or allow binding to the configured port")
        maintenance.stop()
        zone_manager.stop()
        if metrics_server:
            metrics_server.stop()
        return 1
    except OSError as exc:
        log("ERROR", "Could not start DNS listeners", error=str(exc), bind_ip=bind_ip, port=port)
        maintenance.stop()
        zone_manager.stop()
        if metrics_server:
            metrics_server.stop()
        return 1

    for server in servers:
        server.start_thread()

    log("INFO", "insigniaDNS is ready", bind_ip=bind_ip, port=port)

    try:
        while True:
            time.sleep(0.25)
    except KeyboardInterrupt:
        log("INFO", "Shutdown requested by user")
    finally:
        for server in servers:
            server.stop()
        maintenance.stop()
        zone_manager.stop()
        if metrics_server:
            metrics_server.stop()
        if config_manager.get().get("persist_cache"):
            try:
                cache.persist()
            except OSError as exc:
                log("WARN", "Could not persist cache on shutdown", error=str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
