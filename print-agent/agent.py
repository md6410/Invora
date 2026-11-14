# -*- coding: utf-8 -*-
"""
Invora — ایستگاه چاپ (چاپگر مرکزی)

این برنامه روی کامپیوتری اجرا می‌شود که چاپگر به آن وصل است (دفتر، انبار…).
هر چند ثانیه از سایت Invora می‌پرسد «کار چاپی داری؟»؛ پس هیچ پورتی روی مودم باز نمی‌شود
و IP ثابت لازم نیست. اگر اینترنت قطع شود، کارها در صف سایت می‌مانند.

  اجرا:                    python agent.py
  تنظیم (مرورگر):           http://localhost:8766
  نصب به‌صورت سرویس ویندوز:  install-windows.bat   (یا: python agent.py --startup auto install)
  حذف سرویس:               python agent.py stop  &&  python agent.py remove

محتوای هر کار روی سرور رمزشده است (AES-256-GCM) و فقط با توکن همین ایستگاه باز می‌شود.
روش چاپ از پروژه‌ی وبی گرفته شده: صفحه با Edge/Chrome خودِ سیستم به PDF تبدیل می‌شود و بعد
  - ویندوز: با SumatraPDF (اگر نصب باشد) یا مستقیم با GDI ویندوز و اندازه‌ی دقیق کاغذ (DEVMODE)؛
  - چاپگر حرارتی برچسب: اختیاری با زبان خود چاپگر (TSPL) برای دقیق‌ترین اندازه؛
  - لینوکس و مک: با lp.
"""
import base64
import hashlib
import hmac
import html as htmlmod
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "2.1"
FROZEN = bool(getattr(sys, "frozen", False))          # the ready-made InvoraPrint.exe (PyInstaller)
HERE = os.path.dirname(os.path.abspath(sys.executable if FROZEN else __file__))
INSTALL_DIR = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "InvoraPrint")
TASK_NAME = "Invora Print Station"
CONFIG_PATH = os.path.join(HERE, "config.json")
LOG_PATH = os.path.join(HERE, "agent.log")
IS_WINDOWS = os.name == "nt"

DEFAULTS = {
    "sites": [],             # چند سایت Invora: [{id, name, api_url, token, enabled, printer}] — همه با همین یک برنامه
    "api_url": "",           # (قدیمی: اگر sites خالی باشد به‌عنوان نخستین سایت منتقل می‌شود)
    "token": "",
    "poll_seconds": 4,
    "web_port": 8766,
    "web_bind": "127.0.0.1",
    "chrome_path": "",
    "sumatra_path": "",
    "printers": {},          # name -> {paper, w, h, kind, method, rotate, default, enabled}
}
PAPERS = [
    ("A4", 210, 297), ("A5", 148, 210), ("A5 افقی", 210, 148), ("A6", 105, 148), ("Letter", 215.9, 279.4),
    ("پاکت DL", 220, 110), ("پاکت C5", 229, 162),
    ("برچسب ۱۰۰×۱۵۰", 100, 150), ("برچسب ۱۰۰×۱۰۰", 100, 100), ("برچسب ۱۰۰×۷۰", 100, 70), ("برچسب ۱۰۰×۵۰", 100, 50),
    ("برچسب ۸۰×۵۰", 80, 50), ("برچسب ۷۰×۴۰", 70, 40), ("برچسب ۶۰×۴۰", 60, 40), ("برچسب ۵۰×۳۰", 50, 30),
    ("برچسب ۴۰×۳۰", 40, 30), ("حرارتی ۸۰ میلی‌متر", 80, 60), ("حرارتی ۵۸ میلی‌متر", 58, 40),
]
STD_DM = ((297, 420, 8), (210, 297, 9), (148, 210, 11), (105, 148, 70), (182, 257, 13), (215.9, 279.4, 1), (215.9, 355.6, 5))

AS_SERVICE = False
STATE = {"station": "", "connected": False, "last_error": "", "last_contact": 0, "jobs_done": 0, "log": [], "sites": {}}
PRINT_LOCK = threading.Lock()   # چند سایت هم‌زمان کار می‌فرستند ولی چاپگرها یکی‌یکی چاپ می‌کنند
LOCK = threading.RLock()   # log() is also called while holding it
STOP = threading.Event()


# ------------------------------------------------------------ پایه
def log(msg, kind="info"):
    line = time.strftime("%Y-%m-%d %H:%M:%S") + "  " + {"ok": "✓", "warn": "!", "err": "✗"}.get(kind, "·") + "  " + str(msg)
    with LOCK:
        STATE["log"].append(line)
        STATE["log"] = STATE["log"][-200:]
    try:
        if sys.stdout:
            print(line, flush=True)
    except Exception:
        pass
    try:
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 2_000_000:
            os.replace(LOG_PATH, LOG_PATH + ".old")
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            cfg.update(json.load(f) or {})
    except FileNotFoundError:
        pass
    except Exception as e:
        log("config.json خوانده نشد: %s" % e, "err")
    if not isinstance(cfg.get("printers"), dict):
        cfg["printers"] = {}
    return normalize_sites(cfg)


def normalize_sites(cfg):
    """کلید قدیمیِ api_url/token را به فهرست sites می‌برد و به هر سایت شناسه می‌دهد."""
    sites = cfg.get("sites")
    if not isinstance(sites, list):
        sites = []
    if not sites and str(cfg.get("api_url") or "").strip() and str(cfg.get("token") or "").strip():
        sites.append({"name": "", "api_url": cfg["api_url"], "token": cfg["token"], "enabled": True})
    out, seen = [], set()
    for s_ in sites:
        if not isinstance(s_, dict):
            continue
        url, tok = str(s_.get("api_url") or "").strip(), str(s_.get("token") or "").strip()
        if not url and not tok:
            continue
        sid = str(s_.get("id") or "") or uuid.uuid4().hex[:8]
        if sid in seen:
            sid = uuid.uuid4().hex[:8]
        seen.add(sid)
        out.append({"id": sid, "name": str(s_.get("name") or "").strip(), "api_url": url, "token": tok,
                    "enabled": s_.get("enabled", True) is not False, "printer": str(s_.get("printer") or "")})
    cfg["sites"] = out
    cfg["api_url"] = cfg["token"] = ""
    return cfg


def add_site(cfg, url, token, name="", printer=""):
    """سایت تازه را اضافه می‌کند؛ اگر همان نشانی یا همان توکن از قبل هست، همان را به‌روز می‌کند."""
    url, token = str(url or "").strip(), str(token or "").strip()
    if not url or not token:
        return False
    for s_ in cfg["sites"]:
        if s_["token"] == token or s_["api_url"].rstrip("/") == url.rstrip("/"):
            s_.update(api_url=url, token=token, enabled=True)
            if name:
                s_["name"] = name
            return True
    cfg["sites"].append({"id": uuid.uuid4().hex[:8], "name": str(name or "").strip(), "api_url": url, "token": token, "enabled": True, "printer": printer})
    return True


def site_label(site):
    if site.get("name"):
        return site["name"]
    u = urllib.parse.urlparse(site.get("api_url") or "")
    return u.netloc or site.get("id") or "سایت"


def site_state(site):
    with LOCK:
        return STATE["sites"].setdefault(site["id"], {"station": "", "connected": False, "last_error": "", "last_contact": 0, "jobs_done": 0})


def save_config(cfg):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG_PATH)


CONFIG = load_config()


def num(v, d=0.0):
    try:
        return float(str(v).strip() or d)
    except Exception:
        return d


# ------------------------------------------------------------ رمزگشایی کار (همان قالب df_enc در PHP)
def job_key(token):
    return hmac.new(token.encode(), b"df-print-job", hashlib.sha256).digest()


def decrypt_job(blob_b64, token):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    blob = base64.b64decode(blob_b64)
    if blob[:4] != b"DFE1" or len(blob) < 33:
        raise RuntimeError("قالب کار چاپ شناخته نشد")
    iv, tag, ct = blob[4:16], blob[16:32], blob[32:]
    plain = AESGCM(job_key(token)).decrypt(iv, ct + tag, b"pjob")
    body = zlib.decompress(plain[1:], -15) if plain[:1] == b"\x01" else plain[1:]
    return json.loads(body.decode("utf-8"))


# ------------------------------------------------------------ چاپگرهای سیستم
def system_printers():
    names, default = [], ""
    if IS_WINDOWS:
        try:
            import win32print
            flags = win32print.PRINTER_ENUM_LOCAL | win32print.PRINTER_ENUM_CONNECTIONS
            names = [p[2] for p in win32print.EnumPrinters(flags)]
            default = win32print.GetDefaultPrinter()
        except Exception as e:
            log("فهرست چاپگرها خوانده نشد (pywin32 نصب است؟): %s" % e, "warn")
    else:
        try:
            out = subprocess.run(["lpstat", "-e"], capture_output=True, text=True, timeout=10).stdout
            names = [x.strip() for x in out.splitlines() if x.strip()]
            d = subprocess.run(["lpstat", "-d"], capture_output=True, text=True, timeout=10).stdout
            if ":" in d:
                default = d.split(":", 1)[1].strip()
        except Exception:
            pass
    return names, default


def printer_cfg(name):
    p = dict({"paper": "", "w": 0, "h": 0, "kind": "paper", "method": "auto", "rotate": 0, "default": False, "enabled": True},
             **(CONFIG["printers"].get(name) or {}))
    return p


def printers_report():
    names, sysdef = system_printers()
    out = []
    any_def = any((CONFIG["printers"].get(n) or {}).get("default") for n in names)
    for n in names:
        p = printer_cfg(n)
        if not p["enabled"]:
            continue
        out.append({"name": n, "paper": p["paper"], "w": num(p["w"]), "h": num(p["h"]), "kind": p["kind"],
                    "default": bool(p["default"]) if any_def else n == sysdef})
    return out


def pick_printer(wanted):
    names, sysdef = system_printers()
    if wanted and wanted in names:
        return wanted
    for n in names:
        if printer_cfg(n)["default"]:
            return n
    if sysdef:
        return sysdef
    if names:
        return names[0]
    raise RuntimeError("هیچ چاپگری روی این کامپیوتر پیدا نشد.")


def paper_ok(p, w, h, tol=3.0):
    pw, ph = num(p.get("w")), num(p.get("h"))
    if not pw or not ph or not w or not h:
        return True
    return (abs(pw - w) <= tol and abs(ph - h) <= tol) or (abs(pw - h) <= tol and abs(ph - w) <= tol)


# ------------------------------------------------------------ HTML → PDF با مرورگر خود سیستم
def find_chrome():
    manual = (CONFIG.get("chrome_path") or "").strip()
    if manual and os.path.isfile(manual):
        return manual
    cands = []
    if IS_WINDOWS:
        for b in (os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"), os.environ.get("PROGRAMFILES", r"C:\Program Files"), os.environ.get("LOCALAPPDATA", "")):
            if b:
                for r in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe", r"Chromium\Application\chrome.exe"):
                    cands.append(os.path.join(b, r))
    elif sys.platform == "darwin":
        cands += ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "/Applications/Chromium.app/Contents/MacOS/Chromium"]
    for n in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "msedge", "chrome"):
        w = shutil.which(n)
        if w:
            cands.append(w)
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def _is_system_account():
    u = (os.environ.get("USERNAME") or "").lower()
    return IS_WINDOWS and (u.endswith("$") or u == "system" or "systemprofile" in (os.environ.get("USERPROFILE") or "").lower())


def _work_dir():
    """پوشه‌ی کار موقت: زیر پوشه‌ی برنامه (برای حساب SYSTEM که Temp ویندوز را محدود دارد)، وگرنه Temp معمول."""
    for d in ((os.path.join(INSTALL_DIR, "tmp"),) if IS_WINDOWS and os.path.isdir(INSTALL_DIR) else ()) + (tempfile.gettempdir(),):
        try:
            os.makedirs(d, exist_ok=True)
            t = os.path.join(d, ".w%d" % os.getpid())
            open(t, "w").close()
            os.remove(t)
            return d
        except Exception:
            continue
    return None


BROWSER_MODE = {"ok": None}   # the first set of flags that worked on this computer is reused


def html_to_pdf(html, pdf_path):
    exe = find_chrome()
    if not exe:
        raise RuntimeError("Edge یا Chrome روی این کامپیوتر پیدا نشد (مسیرش را در تنظیمات بنویسید).")
    if _is_system_account() and "msedge" in os.path.basename(exe).lower():
        raise RuntimeError("Microsoft Edge در حساب SYSTEM اجرا نمی‌شود؛ ایستگاه چاپ باید در حساب کاربر ویندوز اجرا شود (InvoraPrint.exe را دوباره اجرا کنید تا درست نصب شود).")
    wd = _work_dir()
    fd, tmp_html = tempfile.mkstemp(suffix=".html", prefix="invora-", dir=wd)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(html)
    url = "file:///" + tmp_html.replace("\\", "/").lstrip("/")
    base = ["--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-sync",
            "--disable-background-networking", "--disable-component-update", "--disable-crash-reporter", "--no-pdf-header-footer",
            "--print-to-pdf-no-header", "--virtual-time-budget=10000", "--run-all-compositor-stages-before-draw"]
    # Chrome/Edge do not start as root on Linux, nor in the SYSTEM account / a service (session 0), with their sandbox.
    # The page is our own document from the site, not arbitrary web content.
    nosb = AS_SERVICE or _is_system_account() or (not IS_WINDOWS and hasattr(os, "geteuid") and os.geteuid() == 0)
    modes = [["--headless=new"] + (["--no-sandbox"] if nosb else []), ["--headless=new", "--no-sandbox"], ["--headless=old", "--no-sandbox"],
             ["--headless", "--no-sandbox", "--disable-features=RendererCodeIntegrity"]]
    if BROWSER_MODE["ok"]:
        modes.insert(0, BROWSER_MODE["ok"])
    seen, errors = [], []
    try:
        for m in modes:
            if m in seen:
                continue
            seen.append(m)
            profile = tempfile.mkdtemp(prefix="invora-chrome-", dir=wd)
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
                r = subprocess.run([exe] + m + base + ["--user-data-dir=" + profile, "--print-to-pdf=" + pdf_path, url],
                                   capture_output=True, text=True, timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                if os.path.isfile(pdf_path) and os.path.getsize(pdf_path) >= 400:
                    if BROWSER_MODE["ok"] != m:
                        BROWSER_MODE["ok"] = m
                        log("موتور چاپ: %s با %s" % (os.path.basename(exe), " ".join(m)), "ok")
                    return " ".join(m)
                errors.append("%s → %s" % (" ".join(m), ((r.stderr or r.stdout or "").strip().splitlines() or ["بدون پیام"])[-1][:200]))
            except subprocess.TimeoutExpired:
                errors.append("%s → زمان تمام شد" % " ".join(m))
            finally:
                shutil.rmtree(profile, ignore_errors=True)
        raise RuntimeError("PDF ساخته نشد (%s): %s" % (os.path.basename(exe), " | ".join(errors)))
    finally:
        try:
            os.remove(tmp_html)
        except Exception:
            pass


def pdf_pages(pdf_path, dpi):
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(pdf_path)
    try:
        return [doc[i].render(scale=dpi / 72.0).to_pil().convert("RGB") for i in range(len(doc))]
    finally:
        doc.close()


# ------------------------------------------------------------ چاپ
def find_sumatra():
    manual = (CONFIG.get("sumatra_path") or "").strip()
    if manual and os.path.isfile(manual):
        return manual
    c = [shutil.which("SumatraPDF.exe") or "", os.path.join(HERE, "SumatraPDF.exe"),
         r"C:\Program Files\SumatraPDF\SumatraPDF.exe", r"C:\Program Files (x86)\SumatraPDF\SumatraPDF.exe"]
    if os.environ.get("LOCALAPPDATA"):
        c.append(os.path.join(os.environ["LOCALAPPDATA"], "SumatraPDF", "SumatraPDF.exe"))
    for x in c:
        if x and os.path.isfile(x):
            return x
    return None


def _devmode(printer, w_mm, h_mm):
    """اندازه‌ی کاغذ این کار را به درایور تحمیل می‌کند (روش وبی/NiceLabel)."""
    import win32print, win32con
    h = win32print.OpenPrinter(printer)
    try:
        dm = win32print.GetPrinter(h, 2)["pDevMode"]
        if dm is None:
            return None
        std = None
        for pw, ph, code in STD_DM:
            if abs(w_mm - pw) <= 2 and abs(h_mm - ph) <= 2:
                std = (code, False)
            elif abs(w_mm - ph) <= 2 and abs(h_mm - pw) <= 2:
                std = (code, True)
        if std:
            dm.PaperSize = std[0]
            dm.Orientation = 2 if std[1] else 1
            dm.Fields |= win32con.DM_PAPERSIZE | win32con.DM_ORIENTATION
        else:
            dm.PaperSize = 256
            dm.PaperWidth = int(round(w_mm * 10))
            dm.PaperLength = int(round(h_mm * 10))
            dm.Orientation = 1
            dm.Fields |= win32con.DM_PAPERSIZE | win32con.DM_PAPERWIDTH | win32con.DM_PAPERLENGTH | win32con.DM_ORIENTATION
        win32print.DocumentProperties(0, h, printer, dm, dm, win32con.DM_IN_BUFFER | win32con.DM_OUT_BUFFER)
        return dm
    finally:
        win32print.ClosePrinter(h)


def print_gdi(images, printer, copies, w_mm, h_mm, pcfg, title):
    """صفحه‌ها را مستقیم و با اندازه‌ی واقعی روی چاپگر ویندوز می‌کشد؛ وسط کاغذ اگر کاغذ بزرگ‌تر باشد."""
    import win32ui, win32con, win32gui
    from PIL import ImageWin
    rot = int(pcfg.get("rotate") or 0) % 360
    if rot:
        images = [im.rotate(-rot, expand=True) for im in images]
        if rot in (90, 270):
            w_mm, h_mm = h_mm, w_mm
    dm = None
    try:
        dm = _devmode(printer, w_mm, h_mm)
    except Exception as e:
        log("اندازه‌ی کاغذ به درایور داده نشد (%s)؛ با تنظیم فعلی درایور چاپ می‌شود." % e, "warn")
    for _ in range(max(1, copies)):
        hdc = win32ui.CreateDCFromHandle(win32gui.CreateDC("WINSPOOL", printer, dm)) if dm is not None else win32ui.CreateDC()
        if dm is None:
            hdc.CreatePrinterDC(printer)
        try:
            dx, dy = hdc.GetDeviceCaps(win32con.LOGPIXELSX), hdc.GetDeviceCaps(win32con.LOGPIXELSY)
            pw, ph = hdc.GetDeviceCaps(win32con.HORZRES), hdc.GetDeviceCaps(win32con.VERTRES)
            offx, offy = hdc.GetDeviceCaps(112), hdc.GetDeviceCaps(113)       # PHYSICALOFFSET
            physw, physh = hdc.GetDeviceCaps(110), hdc.GetDeviceCaps(111)     # PHYSICALWIDTH/HEIGHT
            ww, wh = int(round(w_mm / 25.4 * dx)), int(round(h_mm / 25.4 * dy))
            k = min(pw / ww, ph / wh, 1.0) if pcfg.get("kind") == "thermal" else min(physw / ww, physh / wh, 1.0)
            dw, dh = max(1, int(ww * k)), max(1, int(wh * k))
            x0 = -offx + max(0, (physw - dw) // 2)      # وسط کاغذِ واقعی، نه گوشه‌ی ناحیه‌ی قابل چاپ
            y0 = -offy + (max(0, (physh - dh) // 2) if pcfg.get("kind") != "thermal" else 0)
            hdc.StartDoc(title or "Invora")
            for im in images:
                hdc.StartPage()
                ImageWin.Dib(im).draw(hdc.GetHandleOutput(), (x0, y0, x0 + dw, y0 + dh))
                hdc.EndPage()
            hdc.EndDoc()
        finally:
            try:
                hdc.DeleteDC()
            except Exception:
                pass


def send_raw(printer, data):
    if IS_WINDOWS:
        import win32print
        h = win32print.OpenPrinter(printer)
        try:
            win32print.StartDocPrinter(h, 1, ("Invora Label", None, "RAW"))
            try:
                win32print.StartPagePrinter(h)
                win32print.WritePrinter(h, data)
                win32print.EndPagePrinter(h)
            finally:
                win32print.EndDocPrinter(h)
        finally:
            win32print.ClosePrinter(h)
    else:
        r = subprocess.run(["lp", "-d", printer, "-o", "raw"], input=data, capture_output=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or b"").decode(errors="ignore")[:300])


def print_tspl(images, printer, copies, w_mm, h_mm, pcfg):
    """چاپگر حرارتی سازگار با TSC/TSPL (مثل ZEC و Xprinter): اندازه و فاصله‌ی برچسب را خودمان به چاپگر می‌گوییم."""
    from PIL import Image
    dpi = int(pcfg.get("tspl_dpi") or 203)
    gap = num(pcfg.get("gap_mm"), 3.0)
    density = min(15, max(0, int(num(pcfg.get("density"), 8))))
    rot = int(pcfg.get("rotate") or 0) % 360
    for im in images:
        if rot:
            im = im.rotate(-rot, expand=True)
        w, h = (h_mm, w_mm) if rot in (90, 270) else (w_mm, h_mm)
        dw = max(8, int(round(w / 25.4 * dpi)))
        dw -= dw % 8
        dh = max(8, int(round(h / 25.4 * dpi)))
        bw = im.convert("L").resize((dw, dh), Image.LANCZOS).point(lambda v: 255 if v >= 160 else 0, mode="1")
        head = ("SIZE %g mm,%g mm\r\nGAP %g mm,0 mm\r\nDIRECTION 0\r\nREFERENCE 0,0\r\nDENSITY %d\r\nSPEED 4\r\nCLS\r\n" % (w, h, gap, density)).encode()
        body = b"BITMAP 0,0,%d,%d,0," % (dw // 8, dh) + bw.tobytes() + b"\r\n"
        send_raw(printer, head + body + ("PRINT %d,1\r\n" % max(1, copies)).encode())


def print_pdf(pdf_path, printer, copies, w_mm, h_mm, title):
    pcfg = printer_cfg(printer)
    method = pcfg.get("method") or "auto"
    if IS_WINDOWS:
        if method == "tspl":
            return print_tspl(pdf_pages(pdf_path, int(pcfg.get("tspl_dpi") or 203)), printer, copies, w_mm, h_mm, pcfg)
        sumatra = find_sumatra() if method in ("auto", "sumatra") else None
        if method == "sumatra" and not sumatra:
            raise RuntimeError("SumatraPDF پیدا نشد؛ روش چاپ این چاپگر را «مستقیم» بگذارید یا SumatraPDF را نصب کنید.")
        if sumatra and (method == "sumatra" or pcfg.get("kind") != "thermal"):
            r = subprocess.run([sumatra, "-print-to", printer, "-print-settings", "noscale,%dx" % max(1, copies), "-silent", pdf_path],
                               capture_output=True, text=True, timeout=240)
            if r.returncode != 0:
                raise RuntimeError("SumatraPDF: " + (r.stderr or r.stdout or "")[:300])
            return
        return print_gdi(pdf_pages(pdf_path, 300 if pcfg.get("kind") == "thermal" else 200), printer, copies, w_mm, h_mm, pcfg, title)
    if method == "tspl":
        return print_tspl(pdf_pages(pdf_path, int(pcfg.get("tspl_dpi") or 203)), printer, copies, w_mm, h_mm, pcfg)
    media = "A4" if abs(w_mm - 210) < 2 and abs(h_mm - 297) < 2 else "Custom.%gx%gmm" % (w_mm, h_mm)
    r = subprocess.run(["lp", "-d", printer, "-n", str(max(1, copies)), "-o", "media=" + media, "-o", "fit-to-page=false", pdf_path],
                       capture_output=True, text=True, timeout=240)
    if r.returncode != 0:
        raise RuntimeError("lp: " + (r.stderr or r.stdout or "")[:300])


def print_html(html, printer, copies, w_mm, h_mm, title):
    fd, pdf = tempfile.mkstemp(suffix=".pdf", prefix="invora-")
    os.close(fd)
    try:
        html_to_pdf(html, pdf)
        print_pdf(pdf, printer, copies, w_mm, h_mm, title)
    finally:
        try:
            os.remove(pdf)
        except Exception:
            pass


# ------------------------------------------------------------ گفت‌وگو با سایت
def api(do, payload=None, site=None):
    url = ((site or {}).get("api_url") or "").strip()
    tok = ((site or {}).get("token") or "").strip()
    if not url or not tok:
        raise RuntimeError("نشانی سایت یا توکن ایستگاه تنظیم نشده است (http://localhost:%s)." % CONFIG.get("web_port", 8766))
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(url + sep + "do=" + do, data=json.dumps(payload or {}).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Print-Token": tok, "User-Agent": "InvoraPrint/" + VERSION})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            data = json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode("utf-8") or "{}")
        except Exception:
            data = {}
        raise RuntimeError(data.get("error") or ("HTTP %s" % e.code))
    if not data.get("ok"):
        raise RuntimeError(data.get("error") or "پاسخ نامعتبر از سایت")
    return data


def report(job_id, status, error="", site=None):
    for i in range(5):
        try:
            api("status", {"id": job_id, "status": status, "error": error}, site)
            return
        except Exception as e:
            log("اعلام نتیجه نشد (%s)؛ دوباره…" % e, "warn")
            time.sleep(2 * (i + 1))


def handle_job(job, site):
    jid = job["id"]
    w, h, copies = num(job.get("w")), num(job.get("h")), int(job.get("copies") or 1)
    data = decrypt_job(job["blob"], site["token"].strip())
    title = data.get("title") or "Invora"
    printer = pick_printer(job.get("printer") or site.get("printer") or "")
    pcfg = printer_cfg(printer)
    if not paper_ok(pcfg, w, h):
        raise RuntimeError("کاغذ چاپگر «%s» (%g×%g) با اندازه‌ی این کار (%g×%g میلی‌متر) نمی‌خواند؛ کاغذ را عوض کنید یا در تنظیمات ایستگاه درستش کنید."
                           % (printer, num(pcfg["w"]), num(pcfg["h"]), w, h))
    log("[%s] چاپ «%s» روی «%s» (%g×%g، %d نسخه)" % (site_label(site), title, printer, w, h, copies))
    report(jid, "printing", "", site)
    with PRINT_LOCK:
        print_html(data.get("html") or "", printer, copies, w, h, title)


def poll_loop(site, stop):
    """برای هر سایت یک رشته: از همان سایت کار می‌گیرد و نتیجه را به همان سایت می‌گوید."""
    last_hello = 0
    name = site_label(site)
    while not STOP.is_set() and not stop.is_set():
        ss = site_state(site)
        wait = max(2, int(num(CONFIG.get("poll_seconds"), 4)))
        try:
            if time.time() - last_hello > 60:
                r = api("hello", {"printers": printers_report(), "version": VERSION, "host": socket.gethostname()}, site)
                with LOCK:
                    if not ss["connected"]:
                        log("[%s] به سایت وصل شد — ایستگاه «%s»" % (name, r.get("station", "")), "ok")
                    ss.update(connected=True, station=r.get("station", ""), last_error="")
                last_hello = time.time()
            r = api("claim", None, site)
            with LOCK:
                ss.update(connected=True, last_contact=time.time(), last_error="")
            job = r.get("job")
            if job:
                try:
                    handle_job(job, site)
                    report(job["id"], "done", "", site)
                    with LOCK:
                        ss["jobs_done"] += 1
                    log("[%s] چاپ شد" % name, "ok")
                except Exception as e:
                    log("[%s] خطای چاپ: %s" % (name, e), "err")
                    report(job["id"], "error", str(e), site)
                continue      # شاید کار دیگری هم در صف باشد
        except Exception as e:
            with LOCK:
                if ss["last_error"] != str(e):
                    log("[%s] %s" % (name, e), "err")
                ss.update(connected=False, last_error=str(e))
            wait = max(wait, 15)
        stop.wait(wait)


def site_manager():
    """سایت‌های فعالِ config را راه می‌اندازد؛ سایتی که حذف یا خاموش شود، رشته‌اش بسته می‌شود (بدون راه‌اندازی دوباره)."""
    running = {}   # id -> (امضا، stop-event)
    while not STOP.is_set():
        want = {}
        for s_ in CONFIG.get("sites") or []:
            if s_.get("enabled", True) and s_.get("api_url") and s_.get("token"):
                want[s_["id"]] = s_
        for sid in list(running):
            sig, ev = running[sid]
            s_ = want.get(sid)
            if s_ is None or (s_["api_url"], s_["token"], s_.get("name")) != sig:
                ev.set()
                del running[sid]
        for sid, s_ in want.items():
            if sid not in running:
                ev = threading.Event()
                running[sid] = ((s_["api_url"], s_["token"], s_.get("name")), ev)
                threading.Thread(target=poll_loop, args=(s_, ev), daemon=True).start()
        STOP.wait(3)
    for _, ev in running.values():
        ev.set()


# ------------------------------------------------------------ صفحه‌ی تنظیمات (روی همین کامپیوتر)
def esc(s):
    return htmlmod.escape(str(s if s is not None else ""), quote=True)


def page_html(msg=""):
    names, sysdef = system_printers()
    with LOCK:
        logs = "\n".join(reversed(STATE["log"][-80:]))
    srows = ""
    for x in CONFIG.get("sites") or []:
        ss = site_state(x)
        k = esc(x["id"])
        stt = ('<b class="ok">وصل — «%s»</b>' % esc(ss["station"])) if ss["connected"] else ('<b class="err">وصل نیست</b>' + ((' <small class="err">%s</small>' % esc(ss["last_error"])) if ss["last_error"] else ""))
        srows += ('<tr><td><input name="s_name::%s" value="%s" size="14" placeholder="نام سایت"></td><td><input name="s_url::%s" value="%s" size="38" dir="ltr"></td>'
                  '<td><input name="s_tok::%s" value="%s" size="26" dir="ltr"></td><td><input name="s_prn::%s" value="%s" size="14" placeholder="پیش‌فرض"></td>'
                  '<td><input type="checkbox" name="s_on::%s"%s></td><td>%s<br><small>%d چاپ</small></td><td><label><input type="checkbox" name="s_del::%s"> حذف</label></td></tr>') % (
            k, esc(x["name"]), k, esc(x["api_url"]), k, esc(x["token"]), k, esc(x.get("printer")), k, " checked" if x["enabled"] else "", stt, ss["jobs_done"], k)
    total_done = sum(site_state(x)["jobs_done"] for x in CONFIG.get("sites") or [])
    n_on = sum(1 for x in CONFIG.get("sites") or [] if site_state(x)["connected"])
    rows = ""
    for n in names:
        p = printer_cfg(n)
        opts = '<option value="">— نامشخص —</option>' + "".join(
            '<option value="%s"%s>%s (%g×%g)</option>' % (esc(nm), " selected" if p["paper"] == nm else "", esc(nm), w, h) for nm, w, h in PAPERS)
        opts += '<option value="custom"%s>اندازه‌ی دلخواه…</option>' % (" selected" if p["paper"] == "custom" else "")
        sel = lambda k, items: "".join('<option value="%s"%s>%s</option>' % (v, " selected" if str(p.get(k)) == v else "", t) for v, t in items)
        key = esc(n)
        rows += ('<tr><td><b>%s</b>%s</td><td><select name="paper::%s">%s</select><br><input name="w::%s" value="%s" size="4" placeholder="عرض"> × <input name="h::%s" value="%s" size="4" placeholder="ارتفاع"> mm</td>'
                 '<td><select name="kind::%s">%s</select></td><td><select name="method::%s">%s</select></td><td><select name="rotate::%s">%s</select></td>'
                 '<td><input type="radio" name="default" value="%s"%s></td><td><input type="checkbox" name="enabled::%s"%s></td>'
                 '<td><button name="test" value="%s">چاپ آزمایشی</button></td></tr>') % (
            esc(n), " <small>(پیش‌فرض ویندوز)</small>" if n == sysdef else "", key, opts, key, esc(p["w"] or ""), key, esc(p["h"] or ""),
            key, sel("kind", [("paper", "کاغذی (A4، A5…)"), ("thermal", "حرارتی / برچسب")]),
            key, sel("method", [("auto", "خودکار"), ("gdi", "مستقیم (بدون برنامه‌ی جانبی)"), ("sumatra", "SumatraPDF"), ("tspl", "زبان TSPL (حرارتی)")]),
            key, sel("rotate", [("0", "۰°"), ("90", "۹۰°"), ("180", "۱۸۰°"), ("270", "۲۷۰°")]),
            key, " checked" if p["default"] else "", key, " checked" if p["enabled"] else "", key)
    return """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><title>ایستگاه چاپ Invora</title>
<style>body{font:14px/1.8 Tahoma,Vazirmatn,sans-serif;background:#eef0ee;color:#1d2321;margin:0;padding:16px}.box{background:#fff;border:1px solid #d7dbd7;border-radius:12px;padding:16px;margin:0 auto 14px;max-width:1100px}
h1{font-size:19px;margin:0 0 8px}h2{font-size:16px;margin:0 0 8px}table{width:100%%;border-collapse:collapse}td,th{border-bottom:1px solid #e3e6e3;padding:6px;text-align:right;vertical-align:top}
input,select,button{font:inherit;padding:4px 8px;border:1px solid #c9cfcb;border-radius:7px}button{background:#1e5a55;color:#fff;border:0;cursor:pointer}.ok{color:#2c7149}.err{color:#a8261b}
pre{background:#f6f7f5;border-radius:8px;padding:8px;max-height:300px;overflow:auto;direction:ltr;text-align:left;font-size:12px;white-space:pre-wrap}.msg{background:#e1edeb;border-radius:8px;padding:6px 10px}</style></head><body>
<div class="box"><h1>ایستگاه چاپ Invora <small>نسخه %s</small></h1>%s
<p>%d سایت تعریف شده، %d وصل · کارهای چاپ‌شده از روشن شدن: %d</p>
<form method="post" action="/save"><h2>سایت‌هایی که به این ایستگاه چاپ وصل‌اند</h2>
<table><tr><th>نام</th><th>نشانی API سایت</th><th>توکن ایستگاه</th><th>چاپگر پیش‌فرضِ این سایت</th><th>فعال</th><th>وضعیت</th><th></th></tr>%s
<tr><td><input name="new_name" size="14" placeholder="سایت تازه"></td><td><input name="new_url" size="38" dir="ltr" placeholder="https://example.com/print-api.php"></td><td><input name="new_token" size="26" dir="ltr" placeholder="توکن ایستگاه"></td><td colspan="4"><small>برای اضافه کردن سایت دیگر، نشانی و توکن را اینجا بنویسید و «ذخیره» بزنید. (یا فایل ZIP همان سایت را اجرا کنید؛ به همین فهرست اضافه می‌شود.)</small></td></tr></table>
<p><label>مسیر Edge/Chrome (اگر خودکار پیدا نشد)<br><input name="chrome_path" value="%s" size="70" dir="ltr" placeholder="%s"></label></p>
<h2>چاپگرهای این کامپیوتر و کاغذ داخل هرکدام</h2>
<table><tr><th>چاپگر</th><th>کاغذ</th><th>نوع</th><th>روش چاپ</th><th>چرخش</th><th>پیش‌فرض</th><th>فعال</th><th></th></tr>%s</table>
<p><button>ذخیره</button></p></form>
<p><small>کاغذ هر چاپگر را درست بگذارید: کاری که اندازه‌اش با کاغذ نخواند چاپ نمی‌شود و خطایش در سایت دیده می‌شود. «مستقیم» یعنی بدون برنامه‌ی جانبی و با اندازه‌ی دقیق (روی ویندوز pywin32 و pypdfium2 لازم است). برای چاپگر حرارتی برچسب اگر اندازه‌ها جابه‌جا شد، «زبان TSPL» را امتحان کنید.</small></p></div>
<div class="box"><h2>گزارش</h2><pre>%s</pre></div></body></html>""" % (
        VERSION, '<p class="msg">%s</p>' % esc(msg) if msg else "",
        len(CONFIG.get("sites") or []), n_on, total_done, srows,
        esc(CONFIG.get("chrome_path")), esc(find_chrome() or "پیدا نشد"), rows or '<tr><td colspan="8">چاپگری پیدا نشد.</td></tr>', esc(logs))


TEST_HTML = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>@page{size:%(w)smm %(h)smm;margin:0}html,body{margin:0}
.p{width:%(w)smm;height:%(h)smm;box-sizing:border-box;border:.5mm dashed #000;display:flex;flex-direction:column;align-items:center;justify-content:center;font:%(fs)spt Tahoma,sans-serif;text-align:center}</style></head>
<body><div class="p"><b>آزمایش چاپ Invora</b><div>%(name)s</div><div dir="ltr">%(w)s × %(h)s mm</div><div>%(t)s</div></div></body></html>"""


class UI(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/state"):
            with LOCK:
                sites = [dict(site_state(x), id=x["id"], name=site_label(x)) for x in CONFIG.get("sites") or []]
                agg = {"station": ", ".join(x["station"] for x in sites if x.get("station")), "connected": any(x["connected"] for x in sites),
                       "last_error": next((x["last_error"] for x in sites if x["last_error"]), ""), "jobs_done": sum(x["jobs_done"] for x in sites), "sites": sites}
                return self._send(json.dumps(agg, ensure_ascii=False), ctype="application/json")
        self._send(page_html())

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8"), keep_blank_values=True)
        g = lambda k, d="": (form.get(k) or [d])[0]
        msg = ""
        names, _ = system_printers()
        CONFIG["chrome_path"] = g("chrome_path").strip()
        keep = []
        for x in CONFIG.get("sites") or []:      # همان دیکشنری‌ها به‌روز می‌شوند تا رشته‌های در حال کار مقدار تازه را ببینند
            i = x["id"]
            if ("s_del::" + i) in form:
                continue
            x["name"] = g("s_name::" + i).strip()
            x["api_url"] = g("s_url::" + i).strip()
            x["token"] = g("s_tok::" + i).strip()
            x["printer"] = g("s_prn::" + i).strip()
            x["enabled"] = ("s_on::" + i) in form
            keep.append(x)
        CONFIG["sites"] = keep
        if g("new_url").strip() or g("new_token").strip():
            if not add_site(CONFIG, g("new_url"), g("new_token"), g("new_name")):
                self._send(page_html("برای سایت تازه هم نشانی و هم توکن لازم است."))
                return
        default = g("default")
        for nm in names:
            p = printer_cfg(nm)
            paper = g("paper::" + nm)
            p["paper"] = paper
            pre = next(((w, h) for t, w, h in PAPERS if t == paper), None)
            p["w"], p["h"] = (pre if pre else (num(g("w::" + nm)), num(g("h::" + nm)))) if paper else (0, 0)
            p["kind"] = g("kind::" + nm, "paper")
            p["method"] = g("method::" + nm, "auto")
            p["rotate"] = int(num(g("rotate::" + nm), 0))
            p["default"] = nm == default
            p["enabled"] = ("enabled::" + nm) in form
            CONFIG["printers"][nm] = p
        save_config(CONFIG)
        msg = "ذخیره شد."
        test = g("test")
        if test:
            p = printer_cfg(test)
            w, h = (num(p["w"]) or 210, num(p["h"]) or 297)
            try:
                print_html(TEST_HTML % {"w": "%g" % w, "h": "%g" % h, "fs": 9 if w < 120 else 16, "name": esc(test), "t": time.strftime("%Y-%m-%d %H:%M")}, test, 1, w, h, "Invora test")
                msg = "صفحه‌ی آزمایشی به «%s» فرستاده شد." % test
                log(msg, "ok")
            except Exception as e:
                msg = "چاپ آزمایشی نشد: %s" % e
                log(msg, "err")
        self._send(page_html(msg))


def start_ui():
    port = int(num(CONFIG.get("web_port"), 8766))
    try:
        srv = ThreadingHTTPServer((CONFIG.get("web_bind") or "127.0.0.1", port), UI)
    except OSError as e:
        log("صفحه‌ی تنظیمات روی پورت %d باز نشد: %s" % (port, e), "warn")
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log("صفحه‌ی تنظیمات: http://localhost:%d" % port, "ok")
    return srv


def run():
    log("ایستگاه چاپ Invora %s روی %s (%s)" % (VERSION, socket.gethostname(), platform.platform()))
    if not find_chrome():
        log("Edge/Chrome پیدا نشد؛ بدون آن صفحه به PDF تبدیل نمی‌شود.", "warn")
    srv = start_ui()
    try:
        site_manager()
    finally:
        if srv:
            srv.shutdown()


# ------------------------------------------------------------ سرویس ویندوز
SERVICE_CMDS = {"service-install", "remove", "start", "stop", "restart", "update", "debug"}  # pywin32 service (python agent.py only)
if IS_WINDOWS:
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil

        class InvoraPrintService(win32serviceutil.ServiceFramework):
            _svc_name_ = "InvoraPrint"
            _svc_display_name_ = "Invora Print Station"
            _svc_description_ = "ایستگاه چاپ Invora: کارهای چاپ سایت را می‌گیرد و چاپ می‌کند."

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.h = win32event.CreateEvent(None, 0, 0, None)

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                STOP.set()
                win32event.SetEvent(self.h)

            def SvcDoRun(self):
                global AS_SERVICE
                AS_SERVICE = True
                os.chdir(HERE)
                servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
                try:
                    run()
                except Exception:
                    log(traceback.format_exc(), "err")
    except ImportError:
        InvoraPrintService = None


# ------------------------------------------------------------ نصب خودکار روی ویندوز (برای InvoraPrint.exe)
#
# دوبار کلیک روی InvoraPrint.exe:
#   - اگر نصب نشده: اجازه‌ی Administrator می‌گیرد، خودش را در C:\ProgramData\InvoraPrint کپی می‌کند،
#     config.json کنارش (نشانی سایت و توکن) را برمی‌دارد، در Task Scheduler طوری ثبت می‌شود که با ورود هر
#     کاربر به ویندوز (در حساب همان کاربر) اجرا شود و اگر بسته شد هر ۵ دقیقه دوباره بالا بیاید،
#     — نه با حساب SYSTEM: Microsoft Edge در حساب SYSTEM اصلاً اجرا نمی‌شود (کد ۱۰۰۲) و چاپگرهای اشتراکیِ کاربر را هم
#       نمی‌بیند. کارهای چاپ تا ورود کسی به ویندوز در صف سایت می‌مانند و بعد چاپ می‌شوند. —
#     همان لحظه روشن می‌شود و صفحه‌ی تنظیمات را باز می‌کند؛
#   - اگر نصب شده و روشن است: صفحه‌ی تنظیمات را باز می‌کند (و اگر نسخه‌ی تازه‌تر است، جایگزین می‌کند).
# فرمان‌ها: InvoraPrint.exe install | uninstall | run | selftest --out file.json

def _msg(text, title="Invora Print Station", err=False):
    if not IS_WINDOWS:
        print(text)
        return
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x10 if err else 0x40)
    except Exception:
        print(text)


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _elevate(args):
    """همین برنامه را با اجازه‌ی Administrator دوباره اجرا می‌کند."""
    import ctypes
    exe = sys.executable
    params = " ".join('"%s"' % a for a in ([] if FROZEN else [os.path.abspath(__file__)]) + args)
    r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, HERE, 1)
    return r > 32


def _single_instance():
    """فقط یک نسخه‌ی در حال اجرا (کار چاپی دو بار چاپ نشود)."""
    if not IS_WINDOWS:
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.CreateMutexW.restype = ctypes.c_void_p
        h = k.CreateMutexW(None, False, "Global\\InvoraPrintStation")
        err = k.GetLastError()
        globals()["_MUTEX"] = h
        return bool(h) and err not in (183, 5)          # ERROR_ALREADY_EXISTS / ACCESS_DENIED
    except Exception:
        return True


def _ui_alive(timeout=1.5):
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                "http://127.0.0.1:%d/state" % int(num(CONFIG.get("web_port"), 8766)), timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def _open_ui():
    import webbrowser
    webbrowser.open("http://localhost:%d" % int(num(CONFIG.get("web_port"), 8766)))


def _run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return -1, str(e)


def _task_xml(exe):
    esc_ = htmlmod.escape
    return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Invora print station: prints documents and labels sent from the Invora website.</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></LogonTrigger>
    <TimeTrigger><StartBoundary>2024-01-01T00:00:00</StartBoundary><Enabled>true</Enabled>
      <Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><GroupId>S-1-5-32-545</GroupId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>6</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>run</Arguments><WorkingDirectory>%s</WorkingDirectory></Exec></Actions>
</Task>
""" % (esc_(exe), esc_(os.path.dirname(exe)))


def _kill_others():
    """نسخه‌های دیگرِ در حال اجرا را می‌بندد. InvoraPrint.exe (تک‌فایلی) دو پردازش دارد: راه‌انداز و خود برنامه؛
    هر دوی خودمان (این پردازش و پدرش) باید از کشتن معاف باشند، وگرنه راه‌اندازِ خودمان بسته می‌شود."""
    me = {os.getpid()}
    try:
        me.add(os.getppid())
    except Exception:
        pass
    cmd = ["taskkill", "/F", "/IM", "InvoraPrint.exe"]
    for pid in me:
        cmd += ["/FI", "PID ne %d" % pid]
    _run_cmd(cmd)


def _task_exists():
    return _run_cmd(["schtasks", "/Query", "/TN", TASK_NAME])[0] == 0


def _merge_config(src_dir, dst_path):
    """config.json کنار فایل دانلودشده (نشانی سایت، توکن) را با تنظیمات قبلیِ نصب‌شده یکی می‌کند."""
    old = {}
    try:
        with open(dst_path, "r", encoding="utf-8-sig") as f:
            old = json.load(f) or {}
    except Exception:
        pass
    new = {}
    try:
        with open(os.path.join(src_dir, "config.json"), "r", encoding="utf-8-sig") as f:
            new = json.load(f) or {}
    except Exception:
        pass
    cfg = dict(DEFAULTS)
    cfg.update(old)
    if not isinstance(cfg.get("printers"), dict):
        cfg["printers"] = {}
    normalize_sites(cfg)
    normalize_sites(new)     # سایتِ فایل دانلودشده به فهرست سایت‌های نصب‌شده اضافه می‌شود (جایگزین نمی‌شود)
    for s_ in new["sites"]:
        add_site(cfg, s_["api_url"], s_["token"], s_["name"], s_.get("printer", ""))
    with open(dst_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return cfg


def _ilog(msg):
    """گزارش نصب: کنار فایل دانلودشده و در پوشه‌ی نصب (برنامه پنجره‌ی متنی ندارد)."""
    line = time.strftime("%Y-%m-%d %H:%M:%S") + "  " + str(msg) + "\n"
    for d in (HERE, INSTALL_DIR):
        try:
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "install.log"), "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass


def install(quiet=False):
    if not IS_WINDOWS:
        print("نصب خودکار فقط روی ویندوز است. روی لینوکس/مک: python3 agent.py")
        return 1
    if not _is_admin():
        if _elevate(["install"] + (["--quiet"] if quiet else [])):
            return 0
        _msg("برای نصب، اجازه‌ی Administrator لازم است. دوباره اجرا کنید و «Yes» را بزنید.", err=True)
        return 1
    steps = []
    _ilog("install %s (frozen=%s, admin=%s, from %s)" % (VERSION, FROZEN, _is_admin(), HERE))
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        _ilog("icacls -> %s" % (_run_cmd(["icacls", INSTALL_DIR, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/T", "/C", "/Q"]),))
        exe_dst = os.path.join(INSTALL_DIR, "InvoraPrint.exe" if FROZEN else "agent.py")
        # نسخه‌ی قبلی را ببند تا فایل آزاد شود
        _run_cmd(["schtasks", "/End", "/TN", TASK_NAME])
        if FROZEN:
            _kill_others()
        time.sleep(1.5)
        src = sys.executable if FROZEN else os.path.abspath(__file__)
        if os.path.normcase(os.path.abspath(src)) != os.path.normcase(os.path.abspath(exe_dst)):
            for _ in range(10):
                try:
                    shutil.copy2(src, exe_dst)
                    break
                except PermissionError:
                    time.sleep(1)
            else:
                raise RuntimeError("فایل قبلی برنامه آزاد نشد؛ رایانه را یک بار ری‌استارت کنید و دوباره اجرا کنید.")
        steps.append("copied")
        cfg = _merge_config(HERE, os.path.join(INSTALL_DIR, "config.json"))
        _run_cmd(["icacls", INSTALL_DIR, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/T", "/C", "/Q"])
        steps.append("config")
        cmd_exe = exe_dst if FROZEN else '"%s" "%s"' % (sys.executable.replace("python.exe", "pythonw.exe"), exe_dst)
        xml_path = os.path.join(INSTALL_DIR, "task.xml")
        with open(xml_path, "w", encoding="utf-16") as f:
            f.write(_task_xml(exe_dst if FROZEN else sys.executable.replace("python.exe", "pythonw.exe")))
        if not FROZEN:   # python agent.py: the task runs pythonw with the script
            with open(xml_path, "r", encoding="utf-16") as f:
                x = f.read().replace("<Arguments>run</Arguments>", "<Arguments>\"%s\" run</Arguments>" % htmlmod.escape(exe_dst))
            with open(xml_path, "w", encoding="utf-16") as f:
                f.write(x)
        rc, out = _run_cmd(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", xml_path, "/F"])
        _ilog("schtasks /Create -> %s %s" % (rc, out.strip()))
        if rc != 0:
            raise RuntimeError("ثبت در Task Scheduler نشد: " + out.strip()[:300])
        steps.append("task")
        _ilog("schtasks /Run -> %s" % (_run_cmd(["schtasks", "/Run", "/TN", TASK_NAME]),))
        try:   # میان‌بر صفحه‌ی تنظیمات روی دسکتاپ همه‌ی کاربران
            pub = os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "Desktop", "Invora Print Station.url")
            with open(pub, "w", encoding="utf-8") as f:
                f.write("[InternetShortcut]\nURL=http://localhost:%d\n" % int(num(cfg.get("web_port"), 8766)))
        except Exception:
            pass
        ok = False
        for i in range(30):
            if _ui_alive():
                ok = True
                break
            if i == 8:   # the task did not start (e.g. no interactive session): start it here, in this user's session
                _ilog("task did not start; starting directly")
                try:
                    subprocess.Popen(([exe_dst] if FROZEN else [sys.executable, exe_dst]) + ["run"], cwd=INSTALL_DIR, close_fds=True,
                                     creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0))
                except Exception as e:
                    _ilog("direct start failed: %s" % e)
            time.sleep(1)
        steps.append("running" if ok else "not-yet")
        _ilog("done: " + ", ".join(steps))
        if not quiet:
            if ok:
                _open_ui()
                _msg("ایستگاه چاپ Invora نصب و روشن شد.\n\nاز این به بعد با ورود به ویندوز خودش اجرا می‌شود و اگر بسته شود خودش دوباره بالا می‌آید. (کارهای چاپی که وقتی کسی وارد ویندوز نشده برسند، در صف می‌مانند و بعد چاپ می‌شوند.)\n\nدر صفحه‌ای که باز شد، کاغذ هر چاپگر را تعیین کنید و «چاپ آزمایشی» بزنید.\nمیان‌بر «Invora Print Station» هم روی دسکتاپ گذاشته شد.")
            else:
                _msg("نصب انجام شد ولی برنامه هنوز جواب نمی‌دهد. چند ثانیه بعد میان‌بر «Invora Print Station» روی دسکتاپ را باز کنید.\nجزئیات: " + os.path.join(INSTALL_DIR, "agent.log"))
        return 0
    except Exception as e:
        _ilog("FAILED after %s: %s\n%s" % (steps, e, traceback.format_exc()))
        if not quiet:
            _msg("نصب کامل نشد:\n%s\n\nمراحل انجام‌شده: %s" % (e, ", ".join(steps) or "-"), err=True)
        print("install failed:", e, steps)
        return 1


def uninstall(quiet=False):
    if IS_WINDOWS and not _is_admin():
        if _elevate(["uninstall"] + (["--quiet"] if quiet else [])):
            return 0
        return 1
    _run_cmd(["schtasks", "/End", "/TN", TASK_NAME])
    _run_cmd(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    if FROZEN:
        _kill_others()
    try:
        os.remove(os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "Desktop", "Invora Print Station.url"))
    except Exception:
        pass
    if not quiet:
        _msg("ایستگاه چاپ Invora حذف شد. (تنظیمات در %s ماند)" % INSTALL_DIR)
    return 0


def browsertest(out_path):
    """عیب‌یابی: ترکیب‌های مختلف اجرای Edge/Chrome را امتحان می‌کند و نتیجه و گزارش داخلی هرکدام را می‌نویسد."""
    exe = find_chrome()
    wd = _work_dir() or tempfile.gettempdir()
    html = "<!doctype html><html><head><meta charset='utf-8'><style>@page{size:100mm 150mm;margin:0}</style></head><body>test</body></html>"
    fd, h = tempfile.mkstemp(suffix=".html", dir=wd)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(html)
    url = "file:///" + h.replace("\\", "/").lstrip("/")
    combos = [["--headless=new"], ["--headless=new", "--no-sandbox"], ["--headless=new", "--no-sandbox", "--single-process"],
              ["--headless=new", "--no-sandbox", "--no-zygote", "--single-process"], ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-software-rasterizer"],
              ["--headless=old", "--no-sandbox"], ["--headless=old", "--no-sandbox", "--single-process"],
              ["--headless=new", "--no-sandbox", "--disable-features=RendererAppContainer,RendererCodeIntegrity,NetworkServiceSandbox"],
              ["--headless=new", "--no-sandbox", "--disable-features=RendererAppContainer,RendererCodeIntegrity", "--single-process"],
              ["--headless=new", "--no-sandbox", "--disable-gpu", "--use-angle=swiftshader", "--in-process-gpu"]]
    out = {"exe": exe, "user": os.environ.get("USERNAME", ""), "system": _is_system_account(), "workdir": wd, "results": []}
    for i, m in enumerate(combos):
        pdf = os.path.join(wd, "bt%d.pdf" % i)
        prof = tempfile.mkdtemp(prefix="bt-", dir=wd)
        rec = {"flags": " ".join(m)}
        try:
            t0 = time.time()
            r = subprocess.run([exe] + m + ["--disable-extensions", "--no-first-run", "--enable-logging", "--v=0", "--user-data-dir=" + prof,
                                            "--print-to-pdf=" + pdf, url], capture_output=True, text=True, timeout=60,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            rec.update(rc=r.returncode, sec=round(time.time() - t0, 1), pdf=os.path.getsize(pdf) if os.path.isfile(pdf) else 0,
                       err=(r.stderr or r.stdout or "")[-400:])
        except Exception as e:
            rec["exc"] = str(e)[:300]
        try:
            with open(os.path.join(prof, "chrome_debug.log"), "r", encoding="utf-8", errors="replace") as f:
                rec["log"] = f.read()[-1200:]
        except Exception:
            pass
        shutil.rmtree(prof, ignore_errors=True)
        out["results"].append(rec)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    return 0


def selftest(out_path):
    """برای آزمون خودکار در GitHub Actions و عیب‌یابی: همه‌ی بخش‌های لازم را امتحان می‌کند."""
    res = {"version": VERSION, "frozen": FROZEN, "python": sys.version.split()[0], "user": os.environ.get("USERNAME", ""), "ok": True, "checks": {}}

    def chk(name, fn):
        try:
            res["checks"][name] = {"ok": True, "info": fn()}
        except Exception as e:
            res["checks"][name] = {"ok": False, "info": "%s: %s" % (type(e).__name__, e)}
            res["ok"] = False
    chk("cryptography", lambda: __import__("cryptography").__version__)
    chk("decrypt", _selftest_decrypt)
    chk("pypdfium2", lambda: __import__("pypdfium2").V_PDFIUM if hasattr(__import__("pypdfium2"), "V_PDFIUM") else "ok")
    chk("pillow", lambda: __import__("PIL").__version__)
    if IS_WINDOWS:
        chk("pywin32", lambda: "%d printer(s)" % len(__import__("win32print").EnumPrinters(6)))
    chk("printers", lambda: system_printers()[0])
    chk("browser", lambda: find_chrome() or (_ for _ in ()).throw(RuntimeError("Edge/Chrome not found")))
    chk("html_to_pdf_and_render", _selftest_render)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    return 0 if res["ok"] else 1


def _selftest_decrypt():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    tok = "selftest-token-0123456789"
    body = json.dumps({"title": "t", "html": "<b>ok</b>"}).encode()
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    plain = b"\x01" + comp.compress(body) + comp.flush()
    iv = os.urandom(12)
    ct = AESGCM(job_key(tok)).encrypt(iv, plain, b"pjob")
    blob = b"DFE1" + iv + ct[-16:] + ct[:-16]
    return decrypt_job(base64.b64encode(blob).decode(), tok)["html"]


def _selftest_render():
    html = ("<!doctype html><html lang='fa' dir='rtl'><head><meta charset='utf-8'><style>@page{size:100mm 150mm;margin:0}"
            "body{margin:0;font:14pt Tahoma}</style></head><body><div style='padding:10mm'>آزمون چاپ ۱۲۳</div></body></html>")
    fd, pdf = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    try:
        mode = html_to_pdf(html, pdf)
        pages = pdf_pages(pdf, 100)
        return "pdf %d bytes, %d page(s), %dx%d px, browser flags: %s, system account: %s" % (os.path.getsize(pdf), len(pages), pages[0].size[0], pages[0].size[1], mode, _is_system_account())
    finally:
        try:
            os.remove(pdf)
        except Exception:
            pass


def main():
    args = sys.argv[1:]
    quiet = "--quiet" in args
    cmd = next((a for a in args if not a.startswith("-")), "")
    if cmd == "selftest":
        out = args[args.index("--out") + 1] if "--out" in args else os.path.join(HERE, "selftest.json")
        sys.exit(selftest(out))
    if cmd == "browsertest":
        out = args[args.index("--out") + 1] if "--out" in args else os.path.join(HERE, "browsertest.json")
        sys.exit(browsertest(out))
    if cmd == "install":
        sys.exit(install(quiet))
    if cmd == "uninstall":
        sys.exit(uninstall(quiet))
    if cmd in SERVICE_CMDS:
        if not IS_WINDOWS or InvoraPrintService is None:
            print("سرویس ویندوز فقط روی ویندوز و با pywin32 ممکن است: pip install pywin32")
            sys.exit(1)
        sys.argv = [sys.argv[0]] + ["install" if a == "service-install" else a for a in args]
        win32serviceutil.HandleCommandLine(InvoraPrintService)
        return
    if cmd == "" and FROZEN and IS_WINDOWS:
        # دوبار کلیک روی InvoraPrint.exe
        installed = os.path.isfile(os.path.join(INSTALL_DIR, "InvoraPrint.exe")) and _task_exists()
        here_is_installed = os.path.normcase(HERE) == os.path.normcase(INSTALL_DIR)
        if installed and (here_is_installed or not os.path.isfile(os.path.join(HERE, "config.json"))):
            if not _ui_alive():
                _run_cmd(["schtasks", "/Run", "/TN", TASK_NAME])
                for _ in range(15):
                    if _ui_alive():
                        break
                    time.sleep(1)
            _open_ui()
            return
        sys.exit(install(quiet))
    # cmd == "run" (Task Scheduler) or "python agent.py"
    if not _single_instance():
        return
    try:
        run()
    except KeyboardInterrupt:
        STOP.set()
        log("بسته شد.")


if __name__ == "__main__":
    main()
