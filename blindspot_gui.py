# blindspot_gui.py
# BlindSpot Crypter — GUI v3.2
# Работает и как .py, и как .exe (без subprocess)

import os
import sys
import json
import time
import ssl
import io
import shutil
import threading
import importlib.util
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
import tkinter as tk
from tkinter import filedialog, messagebox

try:
    import customtkinter as ctk
except ImportError:
    print("[!] Установи customtkinter: pip install customtkinter")
    sys.exit(1)

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.poolmanager import PoolManager
except ImportError:
    print("[!] Установи requests: pip install requests urllib3 certifi")
    sys.exit(1)


# === Универсальный PROJECT_ROOT ===
if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).parent.resolve()
else:
    PROJECT_ROOT = Path(__file__).parent.resolve()

SETTINGS_FILE = PROJECT_ROOT / "config" / "gui_settings.json"

# Добавляем корень в sys.path для импорта core.builder
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# НАСТРОЙКИ
# ============================================================
DEFAULT_SETTINGS = {
    "theme": "dark",
    "vt_enabled": False,
    "vt_api_key": "",
    "last_payload": "",
    "last_output": "",
    "opt_polymorph": True,
    "opt_pe_patch": True,
    "opt_strings": True,
}


def load_settings() -> dict:
    if not SETTINGS_FILE.exists():
        return DEFAULT_SETTINGS.copy()
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        result = DEFAULT_SETTINGS.copy()
        result.update(data)
        return result
    except Exception:
        return DEFAULT_SETTINGS.copy()


def save_settings(settings: dict) -> bool:
    try:
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


# ============================================================
# VIRUSTOTAL
# ============================================================
VT_API_URL = "https://www.virustotal.com/api/v3"


class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **kw):
        ctx = ssl.create_default_context()
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            pass
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, ssl_context=ctx,
        )


def _vt_session() -> requests.Session:
    s = requests.Session()
    s.mount("https://", TLSAdapter())
    return s


def vt_upload_file(file_path: str, api_key: str) -> dict:
    url = f"{VT_API_URL}/files"
    headers = {"x-apikey": api_key}
    session = _vt_session()
    for attempt in range(3):
        try:
            with open(file_path, "rb") as f:
                files = {"file": (Path(file_path).name, f)}
                resp = session.post(url, headers=headers, files=files, timeout=60)
            if resp.status_code == 200:
                return {"status": "ok", "analysis_id": resp.json()["data"]["id"]}
            if resp.status_code == 429:
                time.sleep(15 * (attempt + 1)); continue
            return {"status": "error", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            if attempt < 2:
                time.sleep(5 * (attempt + 1)); continue
            return {"status": "error", "error": str(e)}
    return {"status": "error", "error": "Upload failed after retries"}


def vt_get_analysis(analysis_id: str, api_key: str) -> dict:
    url = f"{VT_API_URL}/analyses/{analysis_id}"
    headers = {"x-apikey": api_key}
    session = _vt_session()
    for attempt in range(3):
        try:
            resp = session.get(url, headers=headers, timeout=30)
            if resp.status_code == 429:
                time.sleep(15 * (attempt + 1)); continue
            if resp.status_code != 200:
                return {"status": "error", "error": f"HTTP {resp.status_code}"}
            attrs = resp.json()["data"]["attributes"]
            st = attrs.get("status")
            if st == "completed":
                return {"status": "completed", "data": attrs}
            return {"status": "queued", "data": attrs}
        except Exception as e:
            if attempt < 2:
                time.sleep(5 * (attempt + 1)); continue
            return {"status": "error", "error": str(e)}
    return {"status": "error", "error": "Get analysis failed after retries"}


def vt_wait(analysis_id: str, api_key: str,
            max_wait: int = 180, interval: int = 6) -> dict:
    start = time.time()
    while time.time() - start < max_wait:
        r = vt_get_analysis(analysis_id, api_key)
        if r["status"] == "completed": return r
        if r["status"] == "error":     return r
        time.sleep(interval)
    return {"status": "error", "error": "Timeout (180s)"}


def vt_parse(attrs: dict) -> dict:
    stats = attrs.get("stats", {})
    results = attrs.get("results", {})
    engines = []
    for name, info in results.items():
        engines.append({"name": name,
                         "category": info.get("category", "unknown"),
                         "result": info.get("result", "")})
    engines.sort(key=lambda x: (
        0 if x["category"] == "malicious" else
        1 if x["category"] == "suspicious" else 2))
    return {"stats": {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total":      sum(stats.values())},
            "engines": engines}


def vt_check_file(file_path: str, api_key: str, log_callback=None) -> dict:
    if log_callback:
        log_callback("[*] Uploading to VirusTotal...", "info")
    up = vt_upload_file(file_path, api_key)
    if up["status"] != "ok":
        return {"status": "error", "error": up.get("error")}
    aid = up["analysis_id"]
    if log_callback:
        log_callback(f"[*] Analysis ID: {aid[:40]}...", "info")
        log_callback("[*] Waiting for report (30-60 sec)...", "info")
    res = vt_wait(aid, api_key)
    if res["status"] != "completed":
        return {"status": "error", "error": res.get("error", "Unknown")}
    return {"status": "ok", "report": vt_parse(res["data"])}


# ============================================================
# ВЫЗОВ BUILDER.PY КАК ФУНКЦИИ
# ============================================================
def run_builder(payload_path: str) -> tuple:
    """
    Запускает builder.py как функцию в текущем процессе.
    Возвращает (stdout_text, stderr_text, returncode).
    Работает и в .py, и в .exe (без subprocess).
    """
    builder_path = PROJECT_ROOT / "core" / "builder.py"
    if not builder_path.exists():
        return "", f"builder.py not found at {builder_path}", 1

    buf_out = io.StringIO()
    buf_err = io.StringIO()
    returncode = 0

    # Сохраняем старые argv и sys.path
    old_argv = sys.argv.copy()
    old_path = sys.path.copy()

    try:
        # Подменяем argv, чтобы builder.py думал, что запущен из CLI
        sys.argv = [str(builder_path), payload_path]

        # Добавляем корень проекта в path (чтобы работал "from core import ...")
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.insert(0, str(PROJECT_ROOT))

        # Загружаем builder.py как модуль
        spec = importlib.util.spec_from_file_location("__bs_builder", builder_path)
        builder_mod = importlib.util.module_from_spec(spec)

        # Перехватываем stdout/stderr
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            try:
                spec.loader.exec_module(builder_mod)
                builder_mod.main()
            except SystemExit as e:
                returncode = int(e.code) if e.code else 0

    except Exception as e:
        returncode = 1
        buf_err.write(str(e))

    finally:
        sys.argv = old_argv
        sys.path = old_path

    return buf_out.getvalue(), buf_err.getvalue(), returncode


# ============================================================
# ТЕМЫ
# ============================================================
class DarkTheme:
    name = "dark"
    BG_DARK="#050507"; BG_PANEL="#0C0C10"; BG_INPUT="#131318"; BG_HOVER="#1C1C22"
    BLUE="#2962FF"; BLUE_LIGHT="#5C8AFF"; BLUE_DARK="#0D3FAA"
    RED="#D32F2F"; RED_LIGHT="#EF5350"; RED_DARK="#8B0000"; RED_GLOW="#FF1744"
    BTN_RED="#C62828"; BTN_RED_HOVER="#8B0000"
    GREEN="#2E7D32"; GREEN_LIGHT="#4CAF50"
    WARN="#FFA726"
    TEXT="#E8E8E8"; TEXT_DIM="#6A6A75"; TEXT_BRIGHT="#FFFFFF"; BORDER="#1F1F28"


class LightTheme:
    name = "light"
    BG_DARK="#F0F0F5"; BG_PANEL="#FFFFFF"; BG_INPUT="#F5F5FA"; BG_HOVER="#E0E0E8"
    BLUE="#2962FF"; BLUE_LIGHT="#1565C0"; BLUE_DARK="#0D3FAA"
    RED="#D32F2F"; RED_LIGHT="#B71C1C"; RED_DARK="#8B0000"; RED_GLOW="#FF1744"
    BTN_RED="#C62828"; BTN_RED_HOVER="#8B0000"
    GREEN="#2E7D32"; GREEN_LIGHT="#388E3C"
    WARN="#E65100"
    TEXT="#1A1A1A"; TEXT_DIM="#666666"; TEXT_BRIGHT="#000000"; BORDER="#D0D0D8"


# ============================================================
# GUI
# ============================================================
class BlindSpotGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        self.theme = DarkTheme if self.settings["theme"] == "dark" else LightTheme

        self.title("BlindSpot Crypter v3.2")
        self.geometry("1150x820")
        self.resizable(False, False)
        ctk.set_appearance_mode(self.theme.name)
        self.configure(fg_color=self.theme.BG_DARK)

        ico = PROJECT_ROOT / "blindspot.ico"
        if ico.exists():
            try: self.iconbitmap(str(ico))
            except Exception: pass

        self._build_ui()

    def _build_ui(self):
        t = self.theme
        topbar = ctk.CTkFrame(self, height=60, fg_color=t.BG_PANEL, corner_radius=0)
        topbar.pack(fill="x"); topbar.pack_propagate(False)
        ctk.CTkFrame(self, height=2, fg_color=t.RED, corner_radius=0).pack(fill="x")

        tf = ctk.CTkFrame(topbar, fg_color="transparent")
        tf.pack(side="left", padx=20)
        ctk.CTkLabel(tf, text="◈", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=t.RED_LIGHT).pack(side="left")
        ctk.CTkLabel(tf, text="BlindSpot", font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=t.TEXT_BRIGHT).pack(side="left", padx=(8, 0))
        ctk.CTkLabel(tf, text="v3.2", font=ctk.CTkFont(size=11),
                     text_color=t.TEXT_DIM).pack(side="left", padx=(8, 0))

        bf = ctk.CTkFrame(topbar, fg_color="transparent")
        bf.pack(side="right", padx=20)
        self._topbar_btn(bf, "☀" if t.name == "dark" else "☾", self.toggle_theme)
        self._topbar_btn(bf, "⚙", self.on_settings_click)
        self._topbar_btn(bf, "?", self.on_about_click)
        self._topbar_btn(bf, "—", self.iconify)
        self._topbar_btn(bf, "✕", self.destroy, danger=True)

        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True)

        sb = ctk.CTkFrame(main, width=200, fg_color=t.BG_PANEL, corner_radius=0)
        sb.pack(side="left", fill="y"); sb.pack_propagate(False)
        self._sidebar_btn(sb, "◉  Dashboard", lambda: self._build_dashboard(), active=True)
        self._sidebar_btn(sb, "▶  Build",     self.start_build)
        self._sidebar_btn(sb, "📁  Output",    self.on_open_output)
        self._sidebar_btn(sb, "⚙  Settings",  self.on_settings_click)
        self._sidebar_btn(sb, "ℹ  About",     self.on_about_click)

        stf = ctk.CTkFrame(sb, fg_color="transparent")
        stf.pack(side="bottom", fill="x", pady=20, padx=15)
        self.status_dot = ctk.CTkLabel(stf, text="●", font=ctk.CTkFont(size=14),
                                        text_color=t.BLUE)
        self.status_dot.pack(side="left")
        self.status_label = ctk.CTkLabel(stf, text="Ready",
                                          font=ctk.CTkFont(size=11),
                                          text_color=t.TEXT_DIM)
        self.status_label.pack(side="left", padx=(5, 0))

        self.content = ctk.CTkFrame(main, fg_color="transparent")
        self.content.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        self._build_dashboard()

        bb = ctk.CTkFrame(self, height=28, fg_color=t.BG_PANEL, corner_radius=0)
        bb.pack(fill="x", side="bottom"); bb.pack_propagate(False)
        ctk.CTkLabel(bb, text="  BlindSpot Crypter — Educational Use Only",
                     font=ctk.CTkFont(size=10),
                     text_color=t.TEXT_DIM).pack(side="left", padx=10)
        ctk.CTkLabel(bb, text="For authorized testing only  ",
                     font=ctk.CTkFont(size=10),
                     text_color=t.RED_LIGHT).pack(side="right", padx=10)

    def _topbar_btn(self, parent, text, cmd, danger=False):
        t = self.theme
        color = t.RED if danger else t.BLUE_LIGHT
        hover = t.RED_DARK if danger else t.BLUE_DARK
        b = ctk.CTkButton(parent, text=text, width=36, height=30,
                           font=ctk.CTkFont(size=14), fg_color="transparent",
                           hover_color=hover, text_color=color,
                           corner_radius=6, command=cmd)
        b.pack(side="left", padx=2); return b

    def _sidebar_btn(self, parent, text, cmd, active=False):
        t = self.theme
        b = ctk.CTkButton(parent, text=text, anchor="w", height=40,
                           font=ctk.CTkFont(size=13),
                           fg_color=t.RED_DARK if active else "transparent",
                           hover_color=t.BG_HOVER,
                           text_color=t.TEXT_BRIGHT if active else t.TEXT_DIM,
                           corner_radius=6, command=cmd)
        b.pack(fill="x", padx=10, pady=3)

    def _card(self, title):
        t = self.theme
        c = ctk.CTkFrame(self.content, fg_color=t.BG_PANEL, corner_radius=10,
                          border_width=1, border_color=t.BORDER)
        ctk.CTkLabel(c, text=title, font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=t.RED_LIGHT).pack(anchor="w", padx=15, pady=(10, 0))
        return c

    def _checkbox(self, parent, text, var):
        t = self.theme
        cb = ctk.CTkCheckBox(parent, text=text, variable=var,
                              font=ctk.CTkFont(size=12),
                              fg_color=t.RED, hover_color=t.RED_LIGHT,
                              border_color=t.BORDER, text_color=t.TEXT)
        cb.pack(side="left", padx=(0, 20)); return cb

    def _build_dashboard(self):
        t = self.theme
        for w in self.content.winfo_children():
            w.destroy()

        head = ctk.CTkFrame(self.content, fg_color="transparent")
        head.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(head, text="Dashboard",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=t.TEXT_BRIGHT).pack(anchor="w")
        ctk.CTkLabel(head, text="Pack any PE file into an evasive in-memory loader",
                     font=ctk.CTkFont(size=12),
                     text_color=t.TEXT_DIM).pack(anchor="w", pady=(2, 0))

        pc = self._card("PAYLOAD (.exe)")
        pc.pack(fill="x", pady=(0, 10))
        row = ctk.CTkFrame(pc, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=(5, 15))
        self.payload_var = tk.StringVar(value=self.settings["last_payload"])
        ctk.CTkEntry(row, textvariable=self.payload_var,
                     placeholder_text="Выбери .exe для упаковки...",
                     height=38, font=ctk.CTkFont(size=12),
                     fg_color=t.BG_INPUT, border_color=t.BORDER,
                     text_color=t.TEXT).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(row, text="📂  Browse", width=110, height=38,
                      font=ctk.CTkFont(size=12),
                      fg_color=t.BLUE, hover_color=t.BLUE_DARK,
                      command=self.browse_payload).pack(side="left", padx=(10, 0))

        oc = self._card("OUTPUT (.exe)")
        oc.pack(fill="x", pady=(0, 10))
        row = ctk.CTkFrame(oc, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=(5, 15))
        self.output_var = tk.StringVar(value=self.settings["last_output"])
        ctk.CTkEntry(row, textvariable=self.output_var,
                     placeholder_text="Куда сохранить...",
                     height=38, font=ctk.CTkFont(size=12),
                     fg_color=t.BG_INPUT, border_color=t.BORDER,
                     text_color=t.TEXT).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(row, text="💾  Save As", width=110, height=38,
                      font=ctk.CTkFont(size=12),
                      fg_color=t.BLUE, hover_color=t.BLUE_DARK,
                      command=self.browse_output).pack(side="left", padx=(10, 0))

        opc = self._card("OPTIONS")
        opc.pack(fill="x", pady=(0, 10))
        opts = ctk.CTkFrame(opc, fg_color="transparent")
        opts.pack(fill="x", padx=15, pady=(5, 15))
        self.opt_polymorph = ctk.BooleanVar(value=self.settings["opt_polymorph"])
        self.opt_pe_patch  = ctk.BooleanVar(value=self.settings["opt_pe_patch"])
        self.opt_strings   = ctk.BooleanVar(value=self.settings["opt_strings"])
        self._checkbox(opts, "Polymorphism", self.opt_polymorph)
        self._checkbox(opts, "PE Patcher", self.opt_pe_patch)
        self._checkbox(opts, "String Encryption", self.opt_strings)

        vtc = self._card("VIRUSTOTAL (optional)")
        vtc.pack(fill="x", pady=(0, 10))
        vtr = ctk.CTkFrame(vtc, fg_color="transparent")
        vtr.pack(fill="x", padx=15, pady=(5, 15))
        self.vt_enabled = ctk.BooleanVar(value=self.settings["vt_enabled"])
        self._checkbox(vtr, "Check on VT after build", self.vt_enabled)

        self.build_btn = ctk.CTkButton(
            self.content, text="⚡  BUILD PAYLOAD", height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=t.BTN_RED, hover_color=t.BTN_RED_HOVER,
            text_color=t.TEXT_BRIGHT, corner_radius=8,
            border_width=1, border_color=t.RED_GLOW,
            command=self.start_build)
        self.build_btn.pack(fill="x", pady=(5, 10))

        pf = ctk.CTkFrame(self.content, fg_color="transparent")
        pf.pack(fill="x", pady=(0, 10))
        self.progress_label = ctk.CTkLabel(pf, text="0%",
                                             font=ctk.CTkFont(size=12, weight="bold"),
                                             text_color=t.TEXT_DIM, width=50)
        self.progress_label.pack(side="left", padx=(0, 10))
        self.progress = ctk.CTkProgressBar(pf, height=6,
                                             fg_color=t.BG_INPUT, progress_color=t.RED)
        self.progress.pack(side="left", fill="x", expand=True)
        self.progress.set(0)

        lc = self._card("BUILD LOG")
        lc.pack(fill="both", expand=True)
        lh = ctk.CTkFrame(lc, fg_color="transparent")
        lh.pack(fill="x", padx=15, pady=(5, 5))
        ctk.CTkButton(lh, text="🗑  Clear", width=80, height=24,
                      font=ctk.CTkFont(size=10), fg_color="transparent",
                      hover_color=t.BG_HOVER, text_color=t.TEXT_DIM,
                      command=self.clear_log).pack(side="right", padx=2)
        ctk.CTkButton(lh, text="📋  Copy", width=80, height=24,
                      font=ctk.CTkFont(size=10), fg_color="transparent",
                      hover_color=t.BG_HOVER, text_color=t.TEXT_DIM,
                      command=self.copy_log).pack(side="right", padx=2)
        ctk.CTkButton(lh, text="📂  Open Output", width=120, height=24,
                      font=ctk.CTkFont(size=10), fg_color="transparent",
                      hover_color=t.BG_HOVER, text_color=t.TEXT_DIM,
                      command=self.on_open_output).pack(side="right", padx=2)

        lcont = ctk.CTkFrame(lc, fg_color=t.BG_INPUT, corner_radius=6)
        lcont.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.log_box = tk.Text(lcont, height=10, bg=t.BG_INPUT, fg=t.TEXT,
                                font=("Consolas", 11), insertbackground=t.TEXT,
                                relief="flat", borderwidth=0, wrap="word",
                                state="disabled")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_box.tag_config("info", foreground=t.TEXT)
        self.log_box.tag_config("ok",   foreground=t.GREEN_LIGHT)
        self.log_box.tag_config("err",  foreground=t.RED_LIGHT)
        self.log_box.tag_config("warn", foreground=t.WARN)
        self.log_box.tag_config("head", foreground=t.BLUE_LIGHT)

        self.log("BlindSpot v3.2 — ready.", "head")
        self.log("Выбери payload, настрой опции и нажми BUILD PAYLOAD.", "info")

    def toggle_theme(self):
        self.settings["theme"] = "light" if self.theme.name == "dark" else "dark"
        save_settings(self.settings)
        ctk.set_appearance_mode(self.settings["theme"])
        self.theme = DarkTheme if self.settings["theme"] == "dark" else LightTheme
        for w in self.winfo_children(): w.destroy()
        self._build_ui()

    def on_settings_click(self):
        t = self.theme
        d = ctk.CTkToplevel(self)
        d.title("Settings"); d.geometry("520x240")
        d.configure(fg_color=t.BG_PANEL)
        d.transient(self); d.grab_set(); d.lift()
        d.after(100, lambda: d.focus_force())

        ctk.CTkLabel(d, text="VirusTotal API Key:",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=t.TEXT).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(d, text="Получить: https://www.virustotal.com/gui/my-apikey",
                     font=ctk.CTkFont(size=10),
                     text_color=t.TEXT_DIM).pack(anchor="w", padx=20)

        key_var = tk.StringVar(value=self.settings["vt_api_key"])
        entry = ctk.CTkEntry(d, textvariable=key_var,
                              placeholder_text="Вставь API key...",
                              height=35, font=ctk.CTkFont(size=11),
                              fg_color=t.BG_INPUT, text_color=t.TEXT)
        entry.pack(fill="x", padx=20, pady=(5, 15)); entry.focus_set()

        def _paste(event=None):
            try:
                text = d.clipboard_get()
                entry.delete(0, "end"); entry.insert(0, text.strip())
            except Exception: pass
            return "break"
        entry.bind("<Control-v>", _paste); entry.bind("<Control-V>", _paste)

        def _select_all(event=None):
            entry.select_range(0, "end"); entry.icursor("end"); return "break"
        entry.bind("<Control-a>", _select_all); entry.bind("<Control-A>", _select_all)

        def _save():
            self.settings["vt_api_key"] = key_var.get().strip()
            save_settings(self.settings)
            self.log("[+] VT API key saved", "ok")
            d.destroy()

        ctk.CTkButton(d, text="Сохранить", fg_color=t.BLUE, height=35,
                      command=_save).pack(fill="x", padx=20)

    def on_about_click(self):
        messagebox.showinfo("О программе",
            "BlindSpot Crypter v3.2\n\nEducational tool.\nFor authorized testing only.")

    def on_open_output(self):
        out = self.output_var.get()
        if out and Path(out).exists():
            os.startfile(str(Path(out).parent))
        elif (PROJECT_ROOT / "build").exists():
            os.startfile(str(PROJECT_ROOT / "build"))

    def clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def copy_log(self):
        text = self.log_box.get("1.0", "end")
        self.clipboard_clear(); self.clipboard_append(text)
        self.log("[*] Log copied to clipboard", "info")

    def browse_payload(self):
        p = filedialog.askopenfilename(title="Выбери payload",
                                        filetypes=[("Executable", "*.exe"),
                                                   ("All files", "*.*")])
        if p:
            self.payload_var.set(p)
            if not self.output_var.get():
                path = Path(p)
                self.output_var.set(str(path.parent / f"{path.stem}_packed.exe"))

    def browse_output(self):
        p = filedialog.asksaveasfilename(title="Сохранить как",
                                          defaultextension=".exe",
                                          filetypes=[("Executable", "*.exe")])
        if p: self.output_var.set(p)

    def log(self, msg, tag="info"):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", msg + "\n", tag)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def set_status(self, text, color=None):
        if color is None: color = self.theme.BLUE
        self.status_label.configure(text=text)
        self.status_dot.configure(text_color=color)

    def set_progress(self, percent, text=""):
        self.progress.set(percent / 100.0)
        self.progress_label.configure(text=f"{percent}%")
        if text: self.set_status(text)

    # ------------------------------------------------------------
    # BUILD
    # ------------------------------------------------------------
    def start_build(self):
        payload = self.payload_var.get().strip()
        output = self.output_var.get().strip()
        if not payload:
            messagebox.showerror("Ошибка", "Выбери payload"); return
        if not Path(payload).exists():
            messagebox.showerror("Ошибка", f"Файл не найден:\n{payload}"); return

        self.settings["last_payload"] = payload
        self.settings["last_output"] = output
        self.settings["opt_polymorph"] = self.opt_polymorph.get()
        self.settings["opt_pe_patch"] = self.opt_pe_patch.get()
        self.settings["opt_strings"] = self.opt_strings.get()
        self.settings["vt_enabled"] = self.vt_enabled.get()
        save_settings(self.settings)

        self.build_btn.configure(state="disabled", text="BUILDING...")
        self.set_progress(5, "Building...")

        threading.Thread(target=self.run_build, args=(payload, output),
                          daemon=True).start()

    def run_build(self, payload, output):
        try:
            self.log(""); self.log("=" * 60, "head")
            self.log("[*] Starting build...", "info")
            self.log(f"[*] Payload: {payload}", "info")
            self.set_progress(15)

            # ВЫЗОВ BUILDER.PY КАК ФУНКЦИИ (без subprocess)
            stdout_text, stderr_text, returncode = run_builder(payload)

            self.set_progress(75)

            if stdout_text:
                for line in stdout_text.strip().split("\n"):
                    tag = "info"
                    if "[+]" in line: tag = "ok"
                    elif "[!]" in line: tag = "err"
                    elif line.startswith("==="): tag = "head"
                    self.log(line, tag)

            if returncode != 0:
                if stderr_text:
                    self.log(f"[!] STDERR: {stderr_text}", "err")
                self.set_status("Build failed", self.theme.RED)
                self.set_progress(0)
                messagebox.showerror("Ошибка", "Сборка не удалась")
                return

            built = PROJECT_ROOT / "build" / "loader.exe"
            if output and built.exists():
                shutil.copy(str(built), output)
                self.log(f"[+] Saved to: {output}", "ok")

            self.set_progress(85, "Build OK")

            # VT-проверка
            if self.vt_enabled.get():
                api_key = self.settings.get("vt_api_key", "")
                if not api_key:
                    self.log("[!] VT включён, но API key не задан", "err")
                    self.log("[*] Открой Settings (⚙)", "warn")
                else:
                    self.log(""); self.log("[*] Checking on VirusTotal...", "head")
                    vt_res = vt_check_file(output or str(built), api_key,
                                            log_callback=lambda m, tag: self.log(m, tag))
                    if vt_res["status"] == "ok":
                        # Окно отчёта — через self.after (безопасно для Tkinter)
                        report = vt_res["report"]
                        self.after(0, lambda r=report: self._show_vt_report(r))
                    else:
                        self.log(f"[!] VT error: {vt_res['error']}", "err")

            self.set_progress(100, "Done")
            self.log("[+] BUILD COMPLETE", "ok")
            self.set_status("Build OK", self.theme.BLUE_LIGHT)
            messagebox.showinfo("Готово", f"Собрано:\n{output or built}")

        except Exception as e:
            self.log(f"[!] Exception: {e}", "err")
            self.set_status("Error", self.theme.RED)
            self.set_progress(0)
            messagebox.showerror("Ошибка", str(e))
        finally:
            self.build_btn.configure(state="normal", text="⚡  BUILD PAYLOAD")

    def _show_vt_report(self, report):
        t = self.theme
        d = ctk.CTkToplevel(self)
        d.title("VirusTotal Report"); d.geometry("720x620")
        d.configure(fg_color=t.BG_PANEL)
        d.transient(self); d.grab_set(); d.lift()
        d.after(100, lambda: d.focus_force())

        stats = report["stats"]; mal = stats["malicious"]
        if mal == 0: color = t.GREEN_LIGHT
        elif mal <= 5: color = t.WARN
        else: color = t.RED_LIGHT

        head = ctk.CTkFrame(d, fg_color=t.BG_INPUT, corner_radius=8)
        head.pack(fill="x", padx=15, pady=15)
        ctk.CTkLabel(head, text=f"{mal} / {stats['total']}",
                     font=ctk.CTkFont(size=32, weight="bold"),
                     text_color=color).pack(pady=(15, 0))
        ctk.CTkLabel(head, text="detections",
                     font=ctk.CTkFont(size=12),
                     text_color=t.TEXT_DIM).pack(pady=(0, 15))

        scroll = ctk.CTkScrollableFrame(d, fg_color=t.BG_INPUT)
        scroll.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        for eng in report["engines"]:
            cat = eng["category"]
            if cat == "malicious":    icon, c = "⚠", t.RED_LIGHT
            elif cat == "suspicious": icon, c = "?", t.WARN
            else:                     icon, c = "✓", t.GREEN_LIGHT
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=icon, width=30,
                          font=ctk.CTkFont(size=14, weight="bold"),
                          text_color=c).pack(side="left")
            ctk.CTkLabel(row, text=eng["name"], width=170, anchor="w",
                          font=ctk.CTkFont(size=11),
                          text_color=t.TEXT).pack(side="left")
            ctk.CTkLabel(row, text=eng["result"] or cat, anchor="w",
                          font=ctk.CTkFont(size=11),
                          text_color=c).pack(side="left", padx=(10, 0))

        self.log("[+] VT report displayed", "ok")


if __name__ == "__main__":
    app = BlindSpotGUI()
    app.mainloop()



