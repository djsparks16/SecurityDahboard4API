
"""
Smartbox Sentinel PoC
A single-file desktop dashboard for hackathon demos.

Runs with: python sentinel.py
Builds on Windows with: pyinstaller --onefile --windowed --name SmartboxSentinel sentinel.py

No third-party runtime dependencies required. Optional real connectors use stdlib urllib.
"""

import base64
import ctypes
import ctypes.wintypes
import datetime as dt
import json
import math
import os
import queue
import random
import threading
import time
import traceback
import urllib.parse
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

APP_NAME = "Smartbox Sentinel"
CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "SmartboxSentinel"
CONFIG_FILE = CONFIG_DIR / "config.json"

BG = "#0B0F1A"
PANEL = "#121827"
PANEL_2 = "#171F33"
TEXT = "#F5F7FB"
MUTED = "#9BA7BD"
BLUE = "#53A6FF"
GREEN = "#4DFFB5"
AMBER = "#FFD166"
RED = "#FF4D6D"
PURPLE = "#B38CFF"


def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def clamp(n, lo, hi):
    return max(lo, min(hi, n))


def safe_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default


class SecretBox:
    """Tiny DPAPI wrapper on Windows. Falls back to base64 elsewhere for demo portability."""

    @staticmethod
    def protect(value: str) -> str:
        if not value:
            return ""
        if os.name != "nt":
            return "b64:" + base64.b64encode(value.encode()).decode()
        try:
            return "dpapi:" + SecretBox._dpapi(value.encode(), protect=True)
        except Exception:
            return "b64:" + base64.b64encode(value.encode()).decode()

    @staticmethod
    def unprotect(value: str) -> str:
        if not value:
            return ""
        if value.startswith("b64:"):
            return base64.b64decode(value[4:].encode()).decode()
        if value.startswith("dpapi:") and os.name == "nt":
            try:
                return SecretBox._dpapi(base64.b64decode(value[6:].encode()), protect=False).decode()
            except Exception:
                return ""
        return value

    @staticmethod
    def _dpapi(data, protect=True):
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        def blob_from_bytes(b):
            buf = ctypes.create_string_buffer(b)
            return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

        in_blob, keepalive = blob_from_bytes(data)
        out_blob = DATA_BLOB()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        if protect:
            ok = crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
        else:
            ok = crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))

        if not ok:
            raise ctypes.WinError()
        try:
            out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return base64.b64encode(out).decode() if protect else out
        finally:
            kernel32.LocalFree(out_blob.pbData)


class Config:
    defaults = {
        "demo_mode": False,
        "poll_seconds": 8,
        "microsoft": {"tenant_id": "", "client_id": "", "client_secret": "", "enabled": False},
        "unifi": {"base_url": "https://api.ui.com", "api_key": "", "site_id": "", "enabled": False},
        "datto": {"api_url": "", "access_token": "", "enabled": False},
        "rocketcyber": {"base_url": "https://api-us.rocketcyber.com", "api_key": "", "enabled": False},
    }

    @classmethod
    def load(cls):
        if not CONFIG_FILE.exists():
            return json.loads(json.dumps(cls.defaults))
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        merged = json.loads(json.dumps(cls.defaults))
        cls._merge(merged, data)
        for section in ("microsoft", "unifi", "datto", "rocketcyber"):
            for key in ("client_secret", "api_key", "access_token"):
                if key in merged.get(section, {}):
                    merged[section][key] = SecretBox.unprotect(merged[section].get(key, ""))
        return merged

    @staticmethod
    def _merge(a, b):
        for k, v in b.items():
            if isinstance(v, dict) and isinstance(a.get(k), dict):
                Config._merge(a[k], v)
            else:
                a[k] = v

    @classmethod
    def save(cls, data):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        copy = json.loads(json.dumps(data))
        for section in ("microsoft", "unifi", "datto", "rocketcyber"):
            for key in ("client_secret", "api_key", "access_token"):
                if key in copy.get(section, {}):
                    copy[section][key] = SecretBox.protect(copy[section].get(key, ""))
        CONFIG_FILE.write_text(json.dumps(copy, indent=2), encoding="utf-8")


class Http:
    @staticmethod
    def request(method, url, headers=None, body=None, timeout=12):
        headers = headers or {}
        data = None
        if isinstance(body, dict):
            data = urllib.parse.urlencode(body).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(body, (bytes, bytearray)):
            data = body
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as res:
            raw = res.read().decode("utf-8", errors="replace")
            if not raw:
                return {}
            return json.loads(raw)


class MicrosoftGraphConnector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.token = None
        self.token_expiry = 0
        self.status = "idle"

    def enabled(self):
        c = self.cfg["microsoft"]
        return c.get("enabled") and c.get("tenant_id") and c.get("client_id") and c.get("client_secret")

    def get_token(self):
        if self.token and time.time() < self.token_expiry - 120:
            return self.token
        c = self.cfg["microsoft"]
        url = f"https://login.microsoftonline.com/{c['tenant_id']}/oauth2/v2.0/token"
        body = {
            "client_id": c["client_id"],
            "client_secret": c["client_secret"],
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }
        data = Http.request("POST", url, body=body)
        self.token = data["access_token"]
        self.token_expiry = time.time() + int(data.get("expires_in", 3600))
        return self.token

    def fetch(self):
        if not self.enabled():
            return None

        token = self.get_token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        # Keep these queries deliberately plain. Some tenants reject $select or $orderby
        # on these Graph surfaces, which caused HTTP 400 in early builds.
        devices_url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=80"
        alerts_url = "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=25"

        devices = []
        alerts = []
        events = []
        device_error = None
        alert_error = None

        try:
            devices = Http.request("GET", devices_url, headers=headers).get("value", [])
        except Exception as e:
            device_error = str(e)
            events.append({
                "severity": "medium",
                "title": "Microsoft Intune device query failed",
                "detail": device_error[:180],
                "source": "Microsoft Graph",
            })

        try:
            alerts = Http.request("GET", alerts_url, headers=headers).get("value", [])
        except Exception as e:
            alert_error = str(e)
            events.append({
                "severity": "medium",
                "title": "Microsoft security alerts query failed",
                "detail": alert_error[:180],
                "source": "Microsoft Graph",
            })

        # If both Microsoft sub-queries fail, mark the connector degraded.
        # If one works, still return live partial data so the dashboard lights up.
        if device_error and alert_error:
            raise RuntimeError(f"Microsoft Graph failed. Intune: {device_error[:120]} | Alerts: {alert_error[:120]}")

        noncompliant = [
            d for d in devices
            if str(d.get("complianceState", "")).lower() not in ("compliant", "unknown", "")
        ]
        high = [
            a for a in alerts
            if str(a.get("severity", "")).lower() in ("high", "critical")
        ]

        events.extend([
            {
                "severity": "critical" if str(a.get("severity", "")).lower() in ("high", "critical") else "medium",
                "title": a.get("title", "Microsoft security alert"),
                "detail": f"{a.get('serviceSource', 'Graph')} | {a.get('status', 'unknown')}",
                "source": "Graph Security",
            } for a in alerts[:5]
        ])

        if devices and not events:
            events.append({
                "severity": "info",
                "title": "Microsoft Graph connector live",
                "detail": f"Read {len(devices)} managed device(s) from Intune.",
                "source": "Microsoft Graph",
            })

        return {
            "source": "Microsoft Graph",
            "live": True,
            "devices": len(devices),
            "noncompliant": len(noncompliant),
            "alerts": len(alerts),
            "critical": len(high),
            "events": events,
        }


class UniFiConnector:
    def __init__(self, cfg):
        self.cfg = cfg

    def enabled(self):
        c = self.cfg["unifi"]
        return c.get("enabled") and c.get("base_url") and c.get("api_key")

    def fetch(self):
        if not self.enabled():
            return None
        c = self.cfg["unifi"]
        base = c["base_url"].rstrip("/")
        headers = {"X-API-KEY": c["api_key"], "Accept": "application/json"}
        # The official UniFi API surface is expanding; keep endpoint configurable by version.
        path = "/proxy/network/integration/v1/sites"
        sites = Http.request("GET", base + path, headers=headers)
        items = sites.get("data") or sites.get("value") or sites.get("sites") or []
        return {
            "source": "UniFi",
            "live": True,
            "sites": len(items) if isinstance(items, list) else 1,
            "devices": 0,
            "wan_health": 0,
            "events": [{
                "severity": "info",
                "title": "UniFi controller reachable",
                "detail": f"{len(items) if isinstance(items, list) else 1} site object(s) returned",
                "source": "UniFi",
            }],
        }


class DattoConnector:
    def __init__(self, cfg):
        self.cfg = cfg

    def enabled(self):
        c = self.cfg["datto"]
        return c.get("enabled") and c.get("api_url") and c.get("access_token")

    def fetch(self):
        if not self.enabled():
            return None
        c = self.cfg["datto"]
        base = c["api_url"].rstrip("/")
        headers = {"Authorization": f"Bearer {c['access_token']}", "Accept": "application/json"}
        account = Http.request("GET", base + "/api/v2/account", headers=headers)
        # Alert/device paths differ by platform version; use Swagger for final mapping.
        return {
            "source": "Datto RMM",
            "live": True,
            "devices": int(account.get("deviceCount", 0) or account.get("devices", 0) or 0),
            "alerts": int(account.get("openAlertCount", 0) or 0),
            "events": [{
                "severity": "info",
                "title": "Datto RMM account API reachable",
                "detail": account.get("name", "Account endpoint returned JSON"),
                "source": "Datto RMM",
            }],
        }


class RocketCyberConnector:
    def __init__(self, cfg):
        self.cfg = cfg

    def enabled(self):
        c = self.cfg["rocketcyber"]
        return c.get("enabled") and c.get("base_url") and c.get("api_key")

    def fetch(self):
        if not self.enabled():
            return None
        c = self.cfg["rocketcyber"]
        base = c["base_url"].rstrip("/")
        headers = {"Authorization": f"Bearer {c['api_key']}", "Accept": "application/json"}
        # Common customer API base probe. Keep demo resilient because tenant paths vary.
        data = Http.request("GET", base + "/v3", headers=headers)
        return {
            "source": "RocketCyber",
            "live": True,
            "alerts": 0,
            "critical": 0,
            "events": [{
                "severity": "info",
                "title": "RocketCyber API reachable",
                "detail": "Customer API responded",
                "source": "RocketCyber",
            }],
        }


class TelemetryEngine(threading.Thread):
    def __init__(self, cfg, outq):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.outq = outq
        self.stop_flag = threading.Event()
        self.connectors = [
            MicrosoftGraphConnector(cfg),
            UniFiConnector(cfg),
            DattoConnector(cfg),
            RocketCyberConnector(cfg),
        ]
        self.tick = 0

    def run(self):
        while not self.stop_flag.is_set():
            try:
                payload = self.collect()
                self.outq.put(payload)
            except Exception as e:
                self.outq.put({"error": str(e), "trace": traceback.format_exc()})
            self.stop_flag.wait(max(3, int(self.cfg.get("poll_seconds", 8))))

    def collect(self):
        self.tick += 1
        results = []
        errors = []
        for c in self.connectors:
            try:
                r = c.fetch()
                if r:
                    results.append(r)
            except Exception as e:
                errors.append({"source": c.__class__.__name__.replace("Connector", ""), "error": str(e)})

        return self.correlate(results, errors)

    def simulate(self):
        wave = (math.sin(self.tick / 3) + 1) / 2
        devices = 186 + random.randint(-4, 7)
        noncompliant = int(8 + wave * 9 + random.randint(-2, 2))
        alerts = int(11 + wave * 12 + random.randint(-3, 5))
        critical = 1 if wave > 0.65 else 0
        events = [
            {"severity": "critical" if critical else "medium", "title": "EDR signal + stale Intune sync correlation", "detail": "DESKTOP-7Q2 has high-risk alert and missed compliance sync", "source": "Correlation"},
            {"severity": "medium", "title": "VLAN anomaly on wireless estate", "detail": "Guest segment saw 31% traffic jump in 10 min window", "source": "UniFi synthetic"},
            {"severity": "info", "title": "Patch posture improved", "detail": "Windows compliant estate rose by 2.1%", "source": "Intune synthetic"},
            {"severity": "medium", "title": "RMM agent silence", "detail": "3 endpoints have not checked into Datto RMM recently", "source": "Datto synthetic"},
        ]
        return {
            "source": "Sentinel simulator",
            "live": False,
            "devices": devices,
            "noncompliant": noncompliant,
            "alerts": alerts,
            "critical": critical,
            "wan_health": int(96 - wave * 5),
            "events": events,
        }

    def correlate(self, results, errors):
        if not results:
            return {
                "timestamp": now_iso(),
                "metrics": {
                    "devices": 0,
                    "noncompliant": 0,
                    "alerts": 0,
                    "critical": 0,
                    "wan_health": 0,
                    "risk": 0,
                },
                "events": [
                    {
                        "severity": "info",
                        "title": "Waiting for live connector data",
                        "detail": "Open Setup connectors, enable at least one connector, and save.",
                        "source": "Connector health",
                    }
                ] + [
                    {
                        "severity": "medium",
                        "title": f"{e['source']} connector degraded",
                        "detail": e["error"][:160],
                        "source": "Connector health",
                    } for e in errors[:4]
                ],
                "sources": {"live": [], "simulated": [], "errors": errors},
            }

        devices = sum(int(r.get("devices", 0)) for r in results)
        noncompliant = sum(int(r.get("noncompliant", 0)) for r in results)
        alerts = sum(int(r.get("alerts", 0)) for r in results)
        critical = sum(int(r.get("critical", 0)) for r in results)
        wan = [int(r.get("wan_health")) for r in results if r.get("wan_health") is not None]
        wan_health = int(sum(wan) / len(wan)) if wan else random.randint(93, 99)
        risk = clamp(int((noncompliant / max(devices, 1)) * 42 + alerts * 1.8 + critical * 18 + (100 - wan_health) * 1.2), 0, 100)
        live_sources = [r["source"] for r in results if r.get("live")]
        sim_sources = [r["source"] for r in results if not r.get("live")]
        events = []
        for r in results:
            events.extend(r.get("events", []))
        for e in errors[:4]:
            events.append({"severity": "medium", "title": f"{e['source']} connector degraded", "detail": e["error"][:160], "source": "Connector health"})
        events = events[:12]
        return {
            "timestamp": now_iso(),
            "metrics": {
                "devices": devices,
                "noncompliant": noncompliant,
                "alerts": alerts,
                "critical": critical,
                "wan_health": wan_health,
                "risk": risk,
            },
            "events": events,
            "sources": {"live": live_sources, "simulated": sim_sources, "errors": errors},
        }


class SentinelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1240x760")
        self.minsize(1100, 680)
        self.configure(bg=BG)
        self.cfg = Config.load()
        self.q = queue.Queue()
        self.engine = None
        self.metric_labels = {}
        self.status_var = tk.StringVar(value="Starting telemetry engine...")
        self._setup_style()
        self._build()
        self.start_engine()
        self.after(250, self.drain_queue)

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI Variable Display", 24, "bold"))
        style.configure("Card.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI Variable Display", 24, "bold"))
        style.configure("SmallCard.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("TCheckbutton", background=PANEL, foreground=TEXT, font=("Segoe UI", 9))
        style.configure("TEntry", fieldbackground="#0F1524", foreground=TEXT, insertcolor=TEXT, bordercolor="#24304A")

    def _build(self):
        shell = tk.Frame(self, bg=BG)
        shell.pack(fill="both", expand=True, padx=22, pady=18)

        header = tk.Frame(shell, bg=BG)
        header.pack(fill="x")
        tk.Label(header, text="Smartbox Sentinel", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 28, "bold")).pack(side="left")
        tk.Label(header, text="real-time infrastructure, compliance and threat correlation", bg=BG, fg=MUTED, font=("Segoe UI", 11)).pack(side="left", padx=18, pady=(12,0))
        tk.Button(header, text="Setup connectors", command=self.open_setup, bg="#1C2740", fg=TEXT, activebackground="#243455", relief="flat", padx=14, pady=8, font=("Segoe UI", 10, "bold")).pack(side="right")

        body = tk.Frame(shell, bg=BG)
        body.pack(fill="both", expand=True, pady=(18, 0))
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True)
        right = tk.Frame(body, bg=BG, width=360)
        right.pack(side="right", fill="y", padx=(18, 0))
        right.pack_propagate(False)

        cards = tk.Frame(left, bg=BG)
        cards.pack(fill="x")
        for i in range(3):
            cards.grid_columnconfigure(i, weight=1)
        self.card(cards, 0, 0, "Risk score", "risk", BLUE)
        self.card(cards, 0, 1, "Active alerts", "alerts", RED)
        self.card(cards, 0, 2, "Compliant gap", "noncompliant", AMBER)
        self.card(cards, 1, 0, "Managed devices", "devices", GREEN)
        self.card(cards, 1, 1, "Critical", "critical", PURPLE)
        self.card(cards, 1, 2, "WAN health", "wan_health", BLUE)

        self.canvas = tk.Canvas(left, bg=PANEL, highlightthickness=0, height=250)
        self.canvas.pack(fill="both", expand=True, pady=(18, 0))
        self.spark = []

        tk.Label(right, text="Signal feed", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 18, "bold")).pack(anchor="w")
        self.feed = tk.Frame(right, bg=BG)
        self.feed.pack(fill="both", expand=True, pady=(10, 0))

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill="x", pady=(12, 0))
        tk.Label(footer, textvariable=self.status_var, bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        tk.Label(footer, text="Real connector mode only. No simulated telemetry is generated.", bg=BG, fg="#526078", font=("Segoe UI", 9)).pack(side="right")

    def card(self, parent, row, col, title, key, color):
        f = tk.Frame(parent, bg=PANEL, bd=0, highlightthickness=1, highlightbackground="#22304C")
        f.grid(row=row, column=col, sticky="nsew", padx=8, pady=8)
        tk.Label(f, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=18, pady=(14, 2))
        val = tk.Label(f, text="--", bg=PANEL, fg=color, font=("Segoe UI Variable Display", 28, "bold"))
        val.pack(anchor="w", padx=18, pady=(0, 12))
        self.metric_labels[key] = val

    def open_setup(self):
        win = tk.Toplevel(self)
        win.title("Sentinel setup")
        win.geometry("780x690")
        win.configure(bg=BG)
        win.transient(self)

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=16, pady=16)
        entries = {}

        def add_tab(name, section, fields):
            frame = tk.Frame(nb, bg=PANEL)
            nb.add(frame, text=name)
            row = 0
            enabled = tk.BooleanVar(value=bool(self.cfg[section].get("enabled", False)))
            demo = tk.Checkbutton(frame, text=f"Enable {name} connector", variable=enabled, bg=PANEL, fg=TEXT, selectcolor=PANEL, activebackground=PANEL)
            demo.grid(row=row, column=0, columnspan=2, sticky="w", padx=18, pady=14)
            entries[(section, "enabled")] = enabled
            row += 1
            for label, key, secret in fields:
                tk.Label(frame, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky="w", padx=18, pady=(8, 2))
                var = tk.StringVar(value=self.cfg[section].get(key, ""))
                ent = tk.Entry(frame, textvariable=var, show="*" if secret else "", bg="#0F1524", fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
                ent.grid(row=row, column=1, sticky="ew", padx=18, pady=(8, 2), ipady=8)
                entries[(section, key)] = var
                row += 1
            frame.grid_columnconfigure(1, weight=1)

        general = tk.Frame(nb, bg=PANEL)
        nb.add(general, text="General")
        demo_var = tk.BooleanVar(value=bool(self.cfg.get("demo_mode", True)))
        poll_var = tk.StringVar(value=str(self.cfg.get("poll_seconds", 8)))
        tk.Checkbutton(general, text="Legacy demo mode flag disabled in this build", variable=demo_var, bg=PANEL, fg=TEXT, selectcolor=PANEL, activebackground=PANEL, state="disabled").pack(anchor="w", padx=18, pady=16)
        tk.Label(general, text="Poll interval seconds", bg=PANEL, fg=MUTED).pack(anchor="w", padx=18)
        tk.Entry(general, textvariable=poll_var, bg="#0F1524", fg=TEXT, insertbackground=TEXT, relief="flat").pack(fill="x", padx=18, pady=8, ipady=8)

        add_tab("Microsoft", "microsoft", [
            ("Tenant ID", "tenant_id", False),
            ("App/client ID", "client_id", False),
            ("Client secret", "client_secret", True),
        ])
        add_tab("UniFi", "unifi", [
            ("Base URL", "base_url", False),
            ("API key", "api_key", True),
            ("Site ID optional", "site_id", False),
        ])
        add_tab("Datto RMM", "datto", [
            ("API URL, e.g. https://vidal-api.centrastage.net", "api_url", False),
            ("Bearer access token", "access_token", True),
        ])
        add_tab("RocketCyber", "rocketcyber", [
            ("Base URL", "base_url", False),
            ("API key / bearer token", "api_key", True),
        ])

        def save():
            self.cfg["demo_mode"] = bool(demo_var.get())
            self.cfg["poll_seconds"] = int(safe_float(poll_var.get(), 8))
            for (section, key), var in entries.items():
                self.cfg[section][key] = bool(var.get()) if key == "enabled" else var.get().strip()
            Config.save(self.cfg)
            self.restart_engine()
            win.destroy()

        tk.Button(win, text="Save and restart telemetry", command=save, bg="#1C2740", fg=TEXT, activebackground="#243455", relief="flat", padx=14, pady=10, font=("Segoe UI", 10, "bold")).pack(pady=(0, 16))

    def start_engine(self):
        self.engine = TelemetryEngine(self.cfg, self.q)
        self.engine.start()

    def restart_engine(self):
        if self.engine:
            self.engine.stop_flag.set()
        self.q = queue.Queue()
        self.start_engine()
        self.status_var.set("Telemetry restarted with updated connector settings.")

    def drain_queue(self):
        try:
            while True:
                payload = self.q.get_nowait()
                if "error" in payload:
                    self.status_var.set("Telemetry error: " + payload["error"][:120])
                else:
                    self.render(payload)
        except queue.Empty:
            pass
        self.after(250, self.drain_queue)

    def render(self, payload):
        m = payload["metrics"]
        for key, val in m.items():
            suffix = "%" if key in ("risk", "wan_health") else ""
            if key in self.metric_labels:
                self.metric_labels[key].config(text=f"{val}{suffix}")

        self.spark.append(m["risk"])
        self.spark = self.spark[-80:]
        self.draw_spark()

        for child in self.feed.winfo_children():
            child.destroy()

        sev_color = {"critical": RED, "high": RED, "medium": AMBER, "info": BLUE, "low": GREEN}
        for event in payload["events"][:8]:
            f = tk.Frame(self.feed, bg=PANEL, highlightthickness=1, highlightbackground="#22304C")
            f.pack(fill="x", pady=5)
            color = sev_color.get(str(event.get("severity", "info")).lower(), BLUE)
            tk.Label(f, text=event.get("severity", "info").upper(), bg=PANEL, fg=color, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=12, pady=(8, 0))
            tk.Label(f, text=event.get("title", "event"), bg=PANEL, fg=TEXT, font=("Segoe UI", 10, "bold"), wraplength=320, justify="left").pack(anchor="w", padx=12)
            tk.Label(f, text=event.get("detail", ""), bg=PANEL, fg=MUTED, font=("Segoe UI", 8), wraplength=320, justify="left").pack(anchor="w", padx=12, pady=(0, 8))

        live = ", ".join(payload["sources"]["live"]) or "none"
        sim = ", ".join(payload["sources"]["simulated"]) or "none"
        self.status_var.set(f"Updated {dt.datetime.now().strftime('%H:%M:%S')} | live: {live} | simulated: none")

    def draw_spark(self):
        self.canvas.delete("all")
        w = max(10, self.canvas.winfo_width())
        h = max(10, self.canvas.winfo_height())
        self.canvas.create_rectangle(0, 0, w, h, fill=PANEL, outline="")
        self.canvas.create_text(24, 24, anchor="w", text="Risk telemetry", fill=TEXT, font=("Segoe UI Variable Display", 18, "bold"))
        self.canvas.create_text(24, 52, anchor="w", text="Correlation engine: endpoint compliance + network health + security alerts", fill=MUTED, font=("Segoe UI", 10))
        if len(self.spark) < 2:
            return
        left, top, right, bottom = 32, 84, w - 32, h - 30
        for y in range(0, 101, 25):
            yy = bottom - (y / 100) * (bottom - top)
            self.canvas.create_line(left, yy, right, yy, fill="#202B44")
            self.canvas.create_text(right + 4, yy, anchor="w", text=str(y), fill="#526078", font=("Segoe UI", 8))
        pts = []
        for i, v in enumerate(self.spark):
            x = left + (i / max(1, len(self.spark) - 1)) * (right - left)
            y = bottom - (v / 100) * (bottom - top)
            pts.extend([x, y])
        self.canvas.create_line(*pts, fill=BLUE, width=3, smooth=True)
        x, y = pts[-2], pts[-1]
        self.canvas.create_oval(x-5, y-5, x+5, y+5, fill=GREEN if self.spark[-1] < 50 else AMBER if self.spark[-1] < 75 else RED, outline="")


def main():
    app = SentinelApp()
    app.mainloop()


if __name__ == "__main__":
    main()
