#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
import json
import time
import textwrap
import base64
import hashlib
import ssl
import socket
import struct
import urllib.parse
import os
import sys
import re
from textwrap import wrap
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from datetime import datetime
from dataclasses import dataclass, asdict
from collections import defaultdict
import threading
import uuid
from datetime import timezone, timedelta
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

# ==========================
# ✅ Logging (ezviz_log)
# ==========================
class TeeStdIO:
    """
    Record stdout/stderr to both the console and a file at the same time.
    - The console (terminal) shows the original output as-is (no timestamp/prefix).
    - The log file records each line with a timestamp prefix.
    - A shared lock is used to preserve output order and prevent interleaving.
    """
    def __init__(self, stream, file_obj, prefix_ts=True, lock=None):
        self.stream = stream
        self.file_obj = file_obj
        self.prefix_ts = prefix_ts
        self._lock = lock or threading.Lock()
        self._buf = ""

    def _ts(self):
        tz_kst = timezone(timedelta(hours=9))
        return datetime.now(tz_kst).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def write(self, data):
        if not data:
            return
        with self._lock:
            self.stream.write(data)
            self.stream.flush()

            if not self.prefix_ts:
                self.file_obj.write(data)
                self.file_obj.flush()
                return

            self._buf += data
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                self.file_obj.write(f"[{self._ts()}] {line}\n")
                self.file_obj.flush()

    def flush(self):
        with self._lock:
            if self.prefix_ts and self._buf:
                self.file_obj.write(f"[{self._ts()}] {self._buf}")
                self._buf = ""
                self.file_obj.flush()
            self.stream.flush()
            self.file_obj.flush()

def _open_run_log_file(log_dir="ezviz_log"):
    os.makedirs(log_dir, exist_ok=True)
    tz_kst = timezone(timedelta(hours=9))
    ts = datetime.now(tz_kst).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(log_dir, f"{ts}.log")
    f = open(path, "a", encoding="utf-8", buffering=1)
    return f, path

# debug-only logger (file only)
DEBUG_LOG_F = None
DEBUG_LOG_LOCK = None
SSLCTX = None
DEVICE_TZ_MAP = {}  # {deviceSerial: "UTC+09:00"}
SHOW_UTC = True
FILTER_UTC_SAME_DAY = True
SELECT_BY_UTC_DAY = True
UTC_QUERY_ADJACENT_DAYS = True



def _ts_kst():
    tz_kst = timezone(timedelta(hours=9))
    return datetime.now(tz_kst).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def bind_debug_logger(log_f, log_lock):
    global DEBUG_LOG_F, DEBUG_LOG_LOCK
    DEBUG_LOG_F = log_f
    DEBUG_LOG_LOCK = log_lock

def dlog(*args, sep=" ", end="\n"):
    if not DEBUG_LOG_F:
        return
    msg = sep.join("" if a is None else str(a) for a in args)
    with (DEBUG_LOG_LOCK or threading.Lock()):
        for line in msg.splitlines() or [""]:
            DEBUG_LOG_F.write(f"[{_ts_kst()}] {line}{end}")
        DEBUG_LOG_F.flush()

def setup_ezviz_logging(log_dir="ezviz_log"):
    log_f, log_path = _open_run_log_file(log_dir)
    log_lock = threading.Lock()

    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = TeeStdIO(sys.__stdout__, log_f, prefix_ts=True, lock=log_lock)
    sys.stderr = TeeStdIO(sys.__stderr__, log_f, prefix_ts=True, lock=log_lock)

    print(f"\n[+] Ezviz log file: {log_path}")
    bind_debug_logger(log_f, log_lock)
    return log_f, log_path, log_lock, old_stdout, old_stderr

def teardown_ezviz_logging(log_f, old_stdout, old_stderr):
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    try:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
    except Exception:
        pass
    try:
        log_f.close()
    except Exception:
        pass

def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return None

def _clip(s: str, n: int = 2000) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + f"... <truncated {len(s)-n} chars>"

def _b64(b: bytes) -> str:
    if b is None:
        return ""
    return base64.b64encode(b).decode("ascii")

def _as_form_encoded(data):
    # If requests receives a dict via data=, it sends it as application/x-www-form-urlencoded by default.
    if isinstance(data, dict):
        return urllib.parse.urlencode(data, doseq=True)
    return data

def build_requests_session(ssl_context: ssl.SSLContext) -> requests.Session:
    s = requests.Session()
    s.mount("https://", SSLContextAdapter(ssl_context))
    return s

def iso_add_days(iso_date: str, delta_days: int) -> str:
    d = datetime.strptime(iso_date, "%Y-%m-%d").date()
    return (d + timedelta(days=delta_days)).isoformat()


def ezviz_request(req: requests.Session, method: str, url: str, *, headers=None, params=None,
                  data=None, json_body=None, timeout=20, verify=False, tag: str="",
                  log_raw: bool=True, **kwargs):
    """
    ✅ Route all HTTP requests through this function to:
    - Keep the existing print flow for console output
    - Write detailed request/response logs to file only via dlog (order preserved)
    - If log_raw=True, store request/response raw bytes as Base64 for "raw evidence preservation"
    - If stream=True, do not force-read the response body here (prevents download corruption)
    """
    rid = uuid.uuid4().hex[:12]

    # Whether this is a streaming request (downloads, etc.)
    stream = bool(kwargs.get("stream", False))

    dlog("")
    dlog("====== [EZVIZ][HTTP][REQ] ===============================")
    dlog(f"rid={rid} tag={tag} {method} {url}")
    if headers: dlog("[REQ] headers:", json.dumps(headers, ensure_ascii=False))

    if params:
        dlog("[REQ] params :", json.dumps(params, ensure_ascii=False))

    # ---- Log request body in a human-readable form ----
    if json_body is not None:
        try:
            dlog("[REQ] json   :", json.dumps(json_body, ensure_ascii=False))
        except Exception:
            dlog("[REQ] json   :", str(json_body))

    if data is not None:
        try:
            dlog("[REQ] data(dict/str):", str(data))
            fe = _as_form_encoded(data)
            if fe is not None:
                dlog("[REQ] data(form-encoded):", fe if isinstance(fe, str) else str(fe))
        except Exception:
            dlog("[REQ] data   :", str(data))

    # ---- Send the actual request ----
    t0 = time.time()
    resp = req.request(
        method=method,
        url=url,
        headers=headers,
        params=params,
        data=data,
        json=json_body,
        timeout=timeout,
        verify=verify,
        **kwargs
    )
    dt = time.time() - t0

    dlog("------ [EZVIZ][HTTP][RESP] -------------------------------")
    dlog(f"rid={rid} status={resp.status_code} elapsed={dt:.3f}s")
    dlog("[RESP] headers:", json.dumps(dict(resp.headers), ensure_ascii=False))

    if not stream:
        try:
            raw = resp.content  # bytes
        except Exception:
            raw = b""

        try:
            txt = resp.text
        except Exception:
            txt = "<no text>"

        dlog("[RESP] text:", txt)

        j = _safe_json(resp)
        if j is not None:
            try:
                dlog("[RESP] json:", json.dumps(j, ensure_ascii=False, indent=2))
            except Exception:
                pass

        if log_raw:
            dlog(f"[RESP] raw_len={len(raw)} raw_b64:", _b64(raw))

    else:
        dlog("[RESP] stream=True (body not consumed here)")

    dlog("==========================================================")
    return resp

def local_timestr_to_compact_no_shift(timestr: str) -> str:
    """
    "YYYY-MM-DD HH:MM:SS" -> "YYYYMMDDT%H%M%SZ"
    (NO timezone conversion; only formatting)
    """
    if not timestr:
        return ""
    try:
        dt = datetime.strptime(timestr, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y%m%dT%H%M%S")
    except Exception:
        return timestr



# ==========================
# ✅ TLS KeyLog (for Wireshark) - auto-create a file (timestamped) and save it in the working directory
# ==========================

def make_ssl_context_for_keylog(keylog_path: str) -> ssl.SSLContext:
    # (Optional safety) Also set the environment variable for easier ops/debugging
    os.environ["SSLKEYLOGFILE"] = keylog_path

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # ✅ NSS Key Log output for Wireshark TLS decryption
    ctx.keylog_filename = keylog_path
    return ctx


class SSLContextAdapter(HTTPAdapter):
    def __init__(self, ssl_context: ssl.SSLContext, **kwargs):
        self._ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["ssl_context"] = self._ssl_context
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs
        )

REQ = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------
SIGNATURE = b"\x9e\xba\xac\xe9"
HEADER_SIZE = 0x20

@dataclass
class CloudVideoInfo:
    storageVersion: int
    seqId: int
    startTime: str
    stopTime: str
    devSerial: str
    channelNo: int
    ownerId: str
    fileType: int
    keyChecksum: str
    streamUrl: str
    totalDays: int
    deviceTz: str = "UTC+00:00"
    # ✅ Preserve original local times for TLS request
    startTimeLocal: str = ""
    stopTimeLocal: str = ""



@dataclass
class CloudFileInfo:
    user_name: str
    dev_id: str
    cloud_space_file_id: str
    file_id: str
    file_size: int
    file_storage_time: str
    video_start_time: str
    video_stop_time: str
    file_url: str
    cover_pic_url: str
    deviceTz: str = "UTC+00:00"


PUBKEY_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyl9htE6mJ581mXdhGXZjJ/"
    "aXjO9us3px3vMTgLZXpYtYzZUhNKvFqSM4toUvA8LOL5k8LCdcJABir8N/NTQWQBm"
    "jbOFVMhUuQQhS4HdH/X0GzlOpEhe0zc402deh9Zv1SXSAFDNKr1B00RXrOZzIBymn"
    "xaZ923l0d74R+k5FuWFAwWZh1XKvTjuOW0LYk+wD+fmt7BU3SgbG3PayMtp6m+iq8"
    "ByLJOpBXRMZoiJZVa72c3zYWz751PlDNH19lgCcVeAtvv7S6LuFXWGxLEISdRO0Rz"
    "WOo9kNGY9ldLfbaj6eHyZsSREq08bkD7/eto1p8PaIklrVVet/l0XnFNssfwIDAQAB"
)

# ==========================
# ✅ Featurecode extraction utilities
# ==========================

def _b64url_decode(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))

def extract_featurecode_from_session(sessionId: str) -> str:
    """
    If sessionId is in JWT format, try to extract featurecode from its payload.
    - Prefer the payload field 's' (matches the user's example)
    - If not present, also try alternative keys such as featureCode / featurecode, etc.
    Returns an empty string ("") on failure.
    """
    try:
        parts = sessionId.split(".")
        if len(parts) < 2:
            return ""
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="ignore"))
        for k in ("s", "featureCode", "featurecode", "feature_code"):
            v = payload.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""
    except Exception:
        return ""

def get_featurecode(sessionId: str) -> str:
    # 1) Try extracting it from the sessionId
    fc = extract_featurecode_from_session(sessionId)
    if fc:
        return fc
    # 2) Fallback to the featurecode used in the legacy login flow
    return "e1e54703fccd03232b66a16b36817ccc"

# ==========================
# ✅ Binary parser
# ==========================

def read_u32be(b, offset):
    return struct.unpack_from(">I", b, offset)[0]

def find_json_block(buf, start):
    begin = buf.find(b"{", start)
    if begin == -1:
        return None, None
    end_candidates = [buf.find(b"}\n", begin), buf.find(b"}", begin)]
    end_candidates = [p for p in end_candidates if p != -1]
    if not end_candidates:
        return None, None
    end = min(end_candidates) + 1
    return begin, end

def parse_block(buf, offset):
    header = buf[offset : offset + HEADER_SIZE]
    if len(header) < HEADER_SIZE or header[:4] != SIGNATURE:
        print(f"[!] Invalid header at 0x{offset:X}")
        return None

    meta_hint = read_u32be(header, 0x18)
    if meta_hint == 0 or meta_hint > len(buf):
        print(f"[!] Skipping invalid header at 0x{offset:X} (meta_hint={meta_hint})")
        return None

    meta_start, meta_end = find_json_block(buf, offset + HEADER_SIZE)
    if meta_start is None or meta_end is None:
        print(f"[!] No JSON found near 0x{offset:X}")
        return None

    if buf[meta_end - 1:meta_end] != b"\n" and meta_end < len(buf) and buf[meta_end:meta_end + 1] == b"\n":
        meta_end += 1

    meta_json_raw = buf[meta_start:meta_end]
    try:
        meta = json.loads(meta_json_raw.decode(errors="ignore"))
    except Exception as e:
        print(f"[!] JSON parse error at 0x{offset:X}: {e}")
        meta = {}

    data_len = int(meta.get("Length", 0))
    data_start = meta_end
    data_end = data_start + data_len
    data_bytes = buf[data_start:data_end] if data_len > 0 else b""

    md5_start = data_end
    md5_end = md5_start + 32
    if md5_end > len(buf):
        print(f"[!] Incomplete MD5 at 0x{offset:X}")
        return None

    md5_str = buf[md5_start:md5_end].decode(errors="ignore").strip()
    md5_calc = hashlib.md5(meta_json_raw + data_bytes).hexdigest()

    return {
        "offset": offset,
        "meta_hint": meta_hint,
        "meta_len": len(meta_json_raw),
        "meta": meta,
        "data_len": data_len,
        "md5_expected": md5_str,
        "md5_computed": md5_calc,
        "match": md5_str == md5_calc,
        "data": data_bytes,
    }

def parse_file_regex(path):
    with open(path, "rb") as f:
        buf = f.read()

    header_pattern = re.compile(re.escape(SIGNATURE) + b".{28}", re.DOTALL)
    header_offsets = [m.start() for m in header_pattern.finditer(buf)]

    if not header_offsets:
        print("[!] No headers found.")
        return []

    blocks = []
    all_data = bytearray()

    for off in header_offsets:
        block = parse_block(buf, off)
        if block:
            blocks.append(block)
            if block["data_len"] > 0:
                all_data.extend(block["data"])

    if all_data:
        combined_path = os.path.join(path + "_parsed")
        with open(combined_path, "wb") as cf:
            cf.write(all_data)
        print(f"[+] Parsed combined data saved: {combined_path}")

    return blocks

# ==========================
# ✅ Login
# ==========================

def get_encrypt_pwd(pwd_plain: str, pubkey_b64: str) -> str:
    if not pwd_plain:
        return ""
    if not pubkey_b64:
        print("[WARN] No public key provided → returning plain password")
        return pwd_plain
    try:
        md5_pwd = hashlib.md5(pwd_plain.encode("utf-8")).hexdigest()
        ts = int(time.time())
        plain = f"{md5_pwd},{ts}"
        plain_bytes = plain.encode("utf-8")

        s = pubkey_b64.strip()
        try:
            key = RSA.import_key(base64.b64decode(s))
        except Exception:
            pem = f"-----BEGIN PUBLIC KEY-----\n{chr(10).join(textwrap.wrap(s,64))}\n-----END PUBLIC KEY-----"
            key = RSA.import_key(pem.encode())

        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(plain_bytes)
        rsa_b64 = base64.b64encode(encrypted).decode().replace("\n", "")
        print(f"[DEBUG] md5={md5_pwd}, ts={ts}, encrypted_len={len(encrypted)}")
        return rsa_b64
    except Exception as e:
        print("[ERROR] RSA encryption failed:", e)
        return pwd_plain

def ezviz_login(account: str, password_plain: str, pubkey_b64: str):
    enc_password = get_encrypt_pwd(password_plain, pubkey_b64)

    url = "https://apiisgp.ezvizlife.com/v3/users/login/v6"
    headers = {
        "featurecode": "e1e54703fccd03232b66a16b36817ccc",  # Required for login
        "clienttype": "3",  # Required for login: iOS=1, Android=3
    }
    body = {"account": account, "password": enc_password}

    print("[*] Sending Ezviz login request...")
    resp = ezviz_request(REQ,"POST", url, headers=headers, data=body, verify=False, tag="LOGIN", log_raw=True)

    if resp.status_code != 200:
        print(f"[!] Login failed: HTTP {resp.status_code}")
        print(resp.text)
        return None

    try:
        data = resp.json()
        user = data.get("loginUser", {})
        sess = data.get("loginSession", {})

        sessionId = sess.get("sessionId")
        print("\n[+] Login successful")
        print(f"  userId    : {user.get('userId')}")
        print(f"  username  : {user.get('username')}")
        print(f"  userCode  : {user.get('userCode')}")
        print(f"  sessionId : {sessionId}")
        return sessionId
    except Exception as e:
        print("[!] Failed to parse response:", e)
        print(resp.text)
        return None

# ==========================
# ✅ (NEW) Registered device list API
# ==========================

def get_terminals(sessionId: str):
    url = f"https://apiisgp.ezvizlife.com/v3/terminals"
    featurecode = get_featurecode(sessionId)

    headers = {
        "sessionid": sessionId,      # Required
    }

    print("\n[*] Requesting terminals list...")
    resp = ezviz_request(REQ,"GET", url, headers=headers, verify=False)
    print(f"[+] Response status code: {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        print("[!] JSON parsing failed — printing raw response:")
        print(resp.text[:1000])
        return None

    meta = data.get("meta", {}) or {}
    if meta.get("code") != 200:
        print(f"[!] Request failed: code={meta.get('code')}, message={meta.get('message')}")
        return None

    terminals = data.get("terminals", []) or []
    if not terminals:
        print("[!] terminals is empty")
        return []

    print("\n[🧩 Registered Terminals List]")
    print("No. | userId | sign | type | signType | name | ip | addTime | lastModifytime | loginTime") #time =UTC
    print("-" * 160)

    for i, t in enumerate(terminals, 1):
        userId = (t.get("userId") or "")
        sign = (t.get("sign") or "")
        typ = (t.get("type") or "")
        signType = (t.get("signType") or "")
        name = t.get("name")
        name = "" if name is None else str(name)
        ip = (t.get("ip") or "")
        addTime = (t.get("addTime") or "")
        lastModifytime = (t.get("lastModifytime") or "")
        loginTime = (t.get("loginTime") or "")

        print(f"{i:>3} | {userId} | {sign} | {typ} | {signType} | {name} | {ip} | {addTime} | {lastModifytime} | {loginTime}")

    return terminals

# ==========================
# ✅ (NEW) User login logs API
# ==========================

def get_user_login_logs(sessionId: str, offset=0, scrollId=1, limit=20, only_user_login=True, max_pages=1000):
    """
    Collect user_operate logs until hasNext=false.
    - Start with scrollId=1
    - For the next page, reuse page.scrollId from the response (server updates it)
    - Dedup key: logs[*].header.id
    - If only_user_login=True, return/print only entries where type == 'user_login'
    """

    headers = {
        "sessionid": sessionId,       # Required
    }

    def _fetch_one(off, sid):
        url = (
            "https://apiisgp.ezvizlife.com/v3/common/logs/group/v1/user_operate"
            f"?offset={off}&scrollId={sid}&limit={limit}"
        )
        print(f"\n[*] Fetching User Operate Logs... offset={off}, scrollId={sid}, limit={limit}")
        resp = ezviz_request(REQ,"GET", url, headers=headers, verify=False)
        print(f"[+] Response status code: {resp.status_code}")

        try:
            data = resp.json()
        except Exception:
            print("[!] JSON parsing failed — printing raw response:")
            print(resp.text[:1000])
            return None

        meta = data.get("meta", {}) or {}
        if meta.get("code") != 200:
            print(f"[!] Request failed: code={meta.get('code')}, message={meta.get('message')}")
            return None

        page = data.get("page", {}) or {}
        logs = data.get("logs", []) or []
        return {"page": page, "logs": logs}

    # ---- Collect all pages + deduplicate ----
    seen_ids = set()
    out = []
    cur_offset = offset
    cur_scroll = scrollId
    pages = 0
    last_page = {"hasNext": False, "scrollId": -1, "offset": 0}

    while True:
        pages += 1
        if pages > max_pages:
            print(f"[!] Stopping because pages exceeded max_pages={max_pages} (infinite-loop guard)")
            break

        res = _fetch_one(cur_offset, cur_scroll)
        if res is None:
            break

        page = res.get("page", {}) or {}
        logs = res.get("logs", []) or []
        last_page = page

        for item in logs:
            if only_user_login and item.get("type") != "user_login":
                continue

            header = item.get("header", {}) or {}
            hid = header.get("id")

            # If header.id is missing, generate a defensive dedup key
            if not hid:
                content = item.get("content", {}) or {}
                hid = f"NOID|{item.get('opTimestamp')}|{item.get('type')}|{item.get('opTime')}|{content.get('ip')}"

            if hid in seen_ids:
                continue
            seen_ids.add(hid)

            content = item.get("content", {}) or {}
            out.append({
                "id": hid,
                "opTime": item.get("opTime") or "",
                "opTimestamp": item.get("opTimestamp"),
                "loginAccount": content.get("loginAccount") or "",
                "featureCode": content.get("featureCode") or "",
                "clientName": content.get("clientName") or "",
                "loginType": content.get("loginType"),
                "ip": content.get("ip") or "",
                "loginTypeName": content.get("loginTypeName") or "",
            })

        has_next = bool(page.get("hasNext"))
        if not has_next:
            break

        # ✅ Next page parameters: reuse page.scrollId / page.offset returned by the server
        # (The server updates scrollId on each response, so this is the safest approach)
        next_scroll = page.get("scrollId", -1)
        next_offset = page.get("offset", 0)

        # Defensive check: stop if values are invalid
        if not isinstance(next_scroll, int) or next_scroll < 0:
            print(f"[!] Invalid next scrollId: {next_scroll} → stopping")
            break

        cur_scroll = next_scroll
        cur_offset = next_offset

    # ---- Output ----
    print("\n[📜 Collected User Login Logs (user_login) - Full Result]")
    print("No. | opTime | loginAccount | featureCode | clientName | loginType | ip | loginTypeName | log_id")
    print("-" * 190)
    for i, r in enumerate(out, 1):
        print(f"{i:>3} | {r['opTime']} | {r['loginAccount']} | {r['featureCode']} | "
              f"{r['clientName']} | {r['loginType']} | {r['ip']} | {r['loginTypeName']} | {r['id']}")

    return {"page": last_page, "logs": out}


# ==========================
# ✅ Device/Cloud API
# ==========================

def get_user_devices_pagelist(sessionId):
    url = (
        "https://apiisgp.ezvizlife.com/v3/userdevices/v1/resources/pagelist"
        "?groupId=-1&limit=30&offset=0&"
        "filter=CLOUD%2CTIME_PLAN%2CCONNECTION%2CSWITCH%2CSTATUS%2CWIFI%2C"
        "NODISTURB%2CKMS%2CP2P%2CTIME_PLAN%2CCHANNEL%2CVTM%2CDETECTOR%2CFEATURE%2C"
        "CUSTOM_TAG%2CUPGRADE%2CVIDEO_QUALITY%2CQOS%2CPRODUCTS_INFO%2CSIM_CARD%2C"
        "MULTI_UPGRADE_EXT%2CFEATURE_INFO%2CTTS%2CSHADOW_STATUS%2CIPC_NVR"
    )
    headers = {
        "sessionid": sessionId,  # Required
    }

    print("\n[*] Requesting User Device Resource List...")
    resp = ezviz_request(REQ,"GET", url, headers=headers, verify=False)
    print(f"[+] Response status code: {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        print("[!] JSON parsing failed — printing raw response:")
        print(resp.text)
        return []

    device_infos = data.get("deviceInfos", [])
    conn = data.get("CONNECTION", {})
    wifi = data.get("WIFI", {})
    status = data.get("STATUS", {})

    if not device_infos:
        print("[!] No deviceInfos field found.")
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return []

    serials = []
    print("\n📋 EZVIZ Device List\n" + "=" * 60)
    for idx, dev in enumerate(device_infos, start=1):
        serial = dev.get("deviceSerial", "N/A")

        name = dev.get("name", "")
        device_type = dev.get("deviceType", "")
        created = dev.get("userDeviceCreateTime", "")
        offline = dev.get("offlineTime", "")
        user_name = dev.get("userName", "")
        mac = dev.get("mac", "")
        channelNo = dev.get("channelNumber","")

        conn_info = conn.get(serial, {})
        local_ip = conn_info.get("localIp", "")
        wan_ip = conn_info.get("wanIp", "")

        wifi_info = wifi.get(serial, {})
        net_type = wifi_info.get("netType", "")
        ssid = wifi_info.get("ssid", "")

        status_info = status.get(serial, {})
        is_encrypt = status_info.get("isEncrypt", "")
        encrypt_pwd = status_info.get("encryptPwd", "")

        print(f"\n[{idx}] 📡 {name}")
        print(f" ├─ Serial       : {serial}")
        print(f" ├─ Type         : {device_type}")
        print(f" ├─ channelNo    : {channelNo}")
        print(f" ├─ Created      : {created}")
        print(f" ├─ OfflineTime  : {offline}")
        print(f" ├─ User         : {user_name}")
        print(f" ├─ MAC          : {mac}")
        print(f" ├─ Local IP     : {local_ip}")
        print(f" ├─ WAN IP       : {wan_ip}")
        print(f" ├─ Net Type     : {net_type}")
        print(f" ├─ SSID         : {ssid}")
        print(f" ├─ Encrypted    : {is_encrypt}")
        print(f" └─ Encrypt Pwd  : {encrypt_pwd}")
        tz_str = "UTC+00:00"
        opt = (status_info.get("optionals") or {})
        if isinstance(opt, dict):
            tz_str = opt.get("timeZone") or "UTC+00:00"
        DEVICE_TZ_MAP[serial] = tz_str

        serials.append((serial, channelNo, tz_str))

    print("=" * 60)
    return serials 

def get_camera_ticket_info(sessionId, device_serial, channelNo):
    url = f"https://apiisgp.ezvizlife.com/v3/cameras/ticketInfo?deviceSerial={device_serial}&channelNo={channelNo}&supportMultiChannelSharedService=0"
    headers = {
        "sessionid": sessionId,
    }

    print(f"\n[*] Requesting Camera Ticket Info... ({device_serial})")
    resp = ezviz_request(REQ,"GET", url, headers=headers, verify=False)
    print(f"[+] Response status code: {resp.status_code}")

    try:
        data = resp.json()
        ticket = data.get("ticketInfo", {}).get("ticket")
        if ticket:
            print(f"[🎫] Ticket: {ticket}")
            return ticket
        print("[!] Could not find the 'ticket' field.")
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return None
    except Exception:
        print(resp.text)
        return None

def get_video_days(sessionId, device_serial, channelNo):
    url = (
        f"https://apiisgp.ezvizlife.com/v3/clouds/videoDays"
        f"?deviceSerial={device_serial}&channelNo={channelNo}&supportMultiChannelSharedService=0"
    )
    headers = {"sessionid": sessionId}
    resp = ezviz_request(REQ,"GET", url, headers=headers, verify=False)
    print(f"[+] videoDays response: HTTP {resp.status_code}")

    try:
        data = resp.json()
        meta = data.get("meta", {})
        if meta.get("code") != 200:
            print(f"[!] Request failed: {meta.get('message')}")
            return None
        video_days = data.get("videoDays", [])
        return video_days if video_days else None
    except Exception as e:
        print(f"[!] JSON parsing failed: {e}")
        print(resp.text)
        return None

def get_cloud_videos_incr_per_day(sessionId, device_serial, channelNo, search_date, device_tz_str="UTC+00:00"):
    url = (
        f"https://apiisgp.ezvizlife.com/v3/clouds/videosIncrPerDay"
        f"?deviceSerial={device_serial}&channelNo={channelNo}&videoType=-1"
        f"&searchDate={search_date}&fileDetailCount=-1&delListHash=1"
        f"&supportMultiChannelSharedService=0"
    )
    headers = {
        "sessionid": sessionId,
    }

    def _pick_str(d: dict, key: str) -> str:
        if not isinstance(d, dict):
            return ""
        v = d.get(key, "")
        if v is None:
            return ""
        if not isinstance(v, str):
            v = str(v)
        return v.strip()

    def _pick_int(d: dict, key: str, default=None):
        if not isinstance(d, dict):
            return default
        v = d.get(key, default)
        try:
            if v is None:
                return default
            return int(v)
        except Exception:
            return default

    def _first_nonempty_str(items, key: str) -> str:
        for it in items:
            v = _pick_str(it, key)
            if v:
                return v
        return ""

    def _first_valid_int(items, key: str):
        for it in items:
            v = _pick_int(it, key, None)
            if v is None:
                continue
            if key == "channelNo":
                if v >= 1:
                    return v
            else:
                return v
        return None

    print(f"\n[*] Requesting VideosIncrPerDay... ({search_date})")
    resp = ezviz_request(REQ,"GET", url, headers=headers, verify=False)
    print(f"[+] Response status code: {resp.status_code}")

    try:
        data = resp.json()
        meta = data.get("meta", {})
        if meta.get("code") != 200:
            print(f"[!] Request failed: code={meta.get('code')}, message={meta.get('message')}")
            return None

        videos = data.get("videos", {}).get("videos", [])
        if not videos:
            print("[!] videos is empty")

        day_stream_url = _first_nonempty_str(videos, "streamUrl")
        day_dev_serial = _first_nonempty_str(videos, "devSerial")
        day_channel_no = _first_valid_int(videos, "channelNo")

        results = []

        dev_tz_str = device_tz_str or DEVICE_TZ_MAP.get(device_serial, "UTC+00:00")

        for v in videos:
            start_time_local = v.get("startTime", "")  # localtime
            stop_time_local = v.get("stopTime", "")

            if SHOW_UTC:
                start_time = local_str_to_utc_str(start_time_local, dev_tz_str)
                stop_time = local_str_to_utc_str(stop_time_local, dev_tz_str)
            else:
                start_time = start_time_local
                stop_time = stop_time_local

            results.append(CloudVideoInfo(
                storageVersion=v.get("storageVersion"),
                seqId=v.get("seqId"),
                startTime=start_time,  # display
                stopTime=stop_time,  # display
                devSerial=day_dev_serial,
                channelNo=day_channel_no,
                ownerId=v.get("ownerId"),
                fileType=v.get("fileType"),
                keyChecksum=v.get("keyChecksum"),
                streamUrl=day_stream_url,
                totalDays=v.get("totalDays"),
                deviceTz=dev_tz_str,
                # ✅ Keep original local times for TLS
                startTimeLocal=start_time_local,
                stopTimeLocal=stop_time_local,
            ))

        return results   # ✅ Must stay inside the try block

    except Exception as e:
        print(f"[!] Failed to parse videosIncrPerDay response: {e}")
        print(resp.text[:1000])
        return None

def get_cloud_file_list(sessionId, device_serial, device_tz_str="UTC+00:00"):
    day_time = datetime.now().strftime("%Y-%m-%d %%20%H:%M:%S").replace("%%20", "%20")
    url = (
        f"https://apiisgp.ezvizlife.com/v3/clouds/cloudspace/page/file/list"
        f"?offset=1&limit=-1&order=1&dayTime={day_time}"
        f"&deviceSerial={device_serial}&channelNo=1"
    )
    headers = {
        "sessionid": sessionId,
    }

    print(f"\n[*] Requesting Cloud File List... ({day_time.replace('%20', ' ')})")
    resp = ezviz_request(REQ,"GET", url, headers=headers, verify=False)
    print(f"[+] Response status code: {resp.status_code}")

    try:
        data = resp.json()
        meta = data.get("meta", {})
        if meta.get("code") != 200:
            print(f"[!] Request failed: code={meta.get('code')}, message={meta.get('message')}")
            return None

        dev_tz_str = device_tz_str or DEVICE_TZ_MAP.get(device_serial, "UTC+00:00")

        files = data.get("files", [])
        out = []
        for f in files:
            st_local = f.get("videoStartTimeStr", "") or ""
            et_local = f.get("videoStopTimeStr", "") or ""
            fs_local = f.get("fileStorageTimeStr", "") or ""

            if SHOW_UTC:
                st = local_str_to_utc_str(st_local, dev_tz_str)
                et = local_str_to_utc_str(et_local, dev_tz_str)
                fs = local_str_to_utc_str(fs_local, dev_tz_str)
            else:
                st, et, fs = st_local, et_local, fs_local

            out.append(CloudFileInfo(
                user_name=f.get("userName", ""),
                dev_id=f.get("devId", ""),
                cloud_space_file_id=f.get("cloudSpaceFileId", ""),
                file_id=f.get("fileId", ""),
                file_size=f.get("fileSize", 0),
                file_storage_time=fs,
                video_start_time=st,
                video_stop_time=et,
                file_url=f.get("fileUrl", ""),
                cover_pic_url=f.get("coverPicUrl", ""),
                deviceTz=dev_tz_str,
            ))
        return out

    except Exception as e:
        print(f"[!] Failed to parse response: {e}")
        print(resp.text)
        return None

# ==========================
# ✅ TLS playback request/download
# ==========================

def hexdump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)

def send_tls_playback_request_from_info(info, ticket):
    global SSLCTX
    if SSLCTX is None:
        raise RuntimeError("SSLCTX is not initialized. Call run_ezviz(case_info) first.")

    def get_value(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        if hasattr(obj, key):
            return getattr(obj, key)
        return default

    stream_url = get_value(info, "streamUrl", "")
    if not stream_url:
        raise ValueError("The 'streamUrl' field is missing.")

    if ":" in stream_url:
        host, port = stream_url.split(":")
        port = int(port)
    else:
        host = stream_url
        port = 32723

    device_serial = get_value(info, "devSerial", "")
    channel_no = get_value(info, "channelNo", 1)
    storage_version = get_value(info, "storageVersion", 2)
    dev_tz_str = get_value(info, "deviceTz", "UTC+00:00")
    dev_tz = parse_utc_offset_to_tz(dev_tz_str)

    # ✅ Prefer preserved local times for TLS request
    start_time_local = get_value(info, "startTimeLocal", "") or ""
    stop_time_local = get_value(info, "stopTimeLocal", "") or ""

    # fallback (in case local fields are missing)
    start_time_fallback = get_value(info, "startTime", "") or ""
    stop_time_fallback = get_value(info, "stopTime", "") or ""

    start_time_src = start_time_local if start_time_local else start_time_fallback
    stop_time_src = stop_time_local if stop_time_local else stop_time_fallback

    # ✅ TLS: use "local time" format WITHOUT shifting
    start_time = local_timestr_to_compact_no_shift(start_time_src)
    stop_time = local_timestr_to_compact_no_shift(stop_time_src)

    start_time_raw = get_value(info, "startTime", "") or ""
    stop_time_raw = get_value(info, "stopTime", "") or ""

    json_data = {
        "BusType": 0, # Seems non-critical (exact value may not matter)
        "ChannelNo": channel_no,
        "ClientType": 0, # Seems non-critical (exact value may not matter)
        "ClientVersion": "6.10.1.0800", # Seems non-critical (exact value may not matter)
        "DevSerial": device_serial,
        "InterlaceFlag": 1, # Seems non-critical (exact value may not matter)
        "PlayType": 1, # Must be correct (cannot be fetched; must be 1)
        "StorageVersion": storage_version,
        "Ticket": ticket,
        "VideoList": [{"seqId": "", "StartTime": start_time, "StopTime": stop_time}]
    }


    json_str = json.dumps(json_data, separators=(",", ":")) + "\n"
    json_bytes = json_str.encode("utf-8")

    md5_hex_str = hashlib.md5(json_bytes).hexdigest()
    payload = json_bytes + md5_hex_str.encode("ascii")

    header = bytearray(0x20)
    header[0x00:0x04] = b'\x9e\xba\xac\xe9'
    header[0x04:0x08] = (1).to_bytes(4, 'little')  # Required
    header[0x08:0x0c] = b'\x00\x00\x00\x00'
    header[0x0c:0x10] = b'\x00\x00\x00\x00'
    header[0x10:0x14] = b'\x00\x00\x50\x31'        # Required
    header[0x14:0x18] = b'\x00\x00\x00\x00'
    header[0x18:0x1c] = len(json_bytes).to_bytes(4, 'big')
    header[0x1c:0x20] = b'\x00\x00\x00\x00'

    request_data = header + payload

    print(f"\n[*] Sending request to TLS server ({host}:{port})...")
    print(f"[*] JSON length: {len(json_bytes)}, MD5: {md5_hex_str}")
    print(hexdump(request_data))

    response = b""
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with SSLCTX.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(request_data)
                tls_sock.settimeout(5)

                while True:
                    try:
                        chunk = tls_sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break
    except Exception as e:
        print(f"[!] Socket communication error: {e}")
        return None

    print(f"[+] Receive complete ({len(response)} bytes)")
    if response:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Extract date from start_time_raw (original "YYYY-MM-DD HH:MM:SS")
        # or start_time ("YYYYMMDDT...") to determine the folder name
        date_folder = _extract_date_folder(start_time_src, start_time)

        out_dir = ensure_date_dir(date_folder)

        filename = os.path.join(out_dir, f"{device_serial}_{start_time}_{ts}.bin")
        with open(filename, "wb") as f:
            f.write(response)

        print(f"[💾] Saved: {filename}")
        parse_file_regex(filename)  # filename_parsed is also created in the same folder
        return filename

    else:
        print("[!] No server response (0 bytes).")
        return None

BASE_DOWNLOAD_DIR = None

def _kst_now_date_str() -> str:
    tz_kst = timezone(timedelta(hours=9))
    return datetime.now(tz_kst).strftime("%Y-%m-%d")

def _extract_date_folder(*candidates: str) -> str:
    """
    Search candidate strings for a date in YYYY-MM-DD format and return it.
    If not found, return today's date (KST) as the folder name.
    """
    for s in candidates:
        if not s:
            continue
        m = re.search(r"\d{4}-\d{2}-\d{2}", str(s))
        if m:
            return m.group(0)
    return _kst_now_date_str()

def ensure_date_dir(date_str: str) -> str:
    """
    Create ezviz_download/YYYY-MM-DD/ and return the path.
    """
    out_dir = os.path.join(BASE_DOWNLOAD_DIR, date_str)
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def safe_filename(name: str) -> str:
    name = name.strip().replace(":", "-").replace("/", "_").replace("\\", "_")
    name = re.sub(r"[^0-9A-Za-z가-힣._\- ]+", "_", name)
    return name[:180] if len(name) > 180 else name

def download_file_url(file_url: str, filename: str = None, timeout: int = 30):
    if not file_url:
        print("[!] file_url is empty.")
        return None

    # If filename is not provided, use the basename from the URL as the default filename
    if not filename:
        base = urllib.parse.urlparse(file_url).path.split("/")[-1] or "cloud_file.bin"
        filename = base

    # ✅ Key point: keep the directory path, but sanitize only the basename
    dirpart = os.path.dirname(filename)
    basepart = os.path.basename(filename)
    basepart = safe_filename(basepart)

    if dirpart:
        os.makedirs(dirpart, exist_ok=True)  # ✅ Create the directory if it doesn't exist
        filename = os.path.join(dirpart, basepart)
    else:
        filename = basepart

    try:
        with ezviz_request(
                REQ,
                "GET",
                file_url,
                stream=True,
                verify=False,
                timeout=timeout,
                allow_redirects=True
        ) as r:
            print(f"[+] GET {r.status_code}")
            if r.status_code != 200:
                print("[!] Download failed response:")
                print(r.text[:500])
                return None

            total = int(r.headers.get("Content-Length", "0") or "0")
            got = 0
            t0 = time.time()

            with open(filename, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 128):
                    if not chunk:
                        continue
                    f.write(chunk)
                    got += len(chunk)

                    if total > 0:
                        pct = (got / total) * 100
                        speed = got / max(time.time() - t0, 1e-6)
                        sys.stdout.write(
                            f"\r[*] {pct:6.2f}%  {got}/{total} bytes  {speed/1024/1024:6.2f} MB/s"
                        )
                        sys.stdout.flush()
                    else:
                        sys.stdout.write(f"\r[*] {got} bytes")
                        sys.stdout.flush()

            sys.stdout.write("\n")
            return filename

    except Exception as e:
        print(f"[!] Download error: {e}")
        return None


def parse_utc_offset_to_tz(tz_str: str):
    try:
        if not tz_str:
            return timezone.utc

        s = tz_str.strip().upper()
        s = s.replace("UTC", "").strip()  # "UTC+09:00" -> "+09:00"
        m = re.match(r"^([+-])(\d{1,2})(?::?(\d{2}))?$", s)
        if not m:
            return timezone.utc

        sign = 1 if m.group(1) == "+" else -1
        hh = int(m.group(2))
        mm = int(m.group(3) or "0")
        return timezone(sign * timedelta(hours=hh, minutes=mm))
    except Exception:
        return timezone.utc


def local_str_to_utc_str(dt_str: str, dev_tz_str: str) -> str:
    """
    "YYYY-MM-DD HH:MM:SS"  -> UTC "YYYY-MM-DD HH:MM:SS"
    """
    try:
        if not dt_str:
            return dt_str
        dev_tz = parse_utc_offset_to_tz(dev_tz_str)
        naive = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        local_dt = naive.replace(tzinfo=dev_tz)
        utc_dt = local_dt.astimezone(timezone.utc)
        return utc_dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return dt_str


def local_timestr_to_utc_str(timestr: str, local_tz: timezone, fmt_in: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    'YYYY-MM-DD HH:MM:SS'  -> UTC 'YYYY-MM-DD HH:MM:SS'
    """
    if not timestr:
        return ""
    try:
        dt_local = datetime.strptime(timestr, fmt_in).replace(tzinfo=local_tz)
        dt_utc = dt_local.astimezone(timezone.utc)
        return dt_utc.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return timestr


def local_timestr_to_utc_compact(timestr: str, local_tz: timezone) -> str:
    if not timestr:
        return ""
    try:
        dt_local = datetime.strptime(timestr, "%Y-%m-%d %H:%M:%S").replace(tzinfo=local_tz)
        dt_utc = dt_local.astimezone(timezone.utc)
        return dt_utc.strftime("%Y%m%dT%H%M%SZ")
    except Exception:
        return timestr

def utc_timestr_to_utc_compact(timestr: str) -> str:
    """
    Treat input as UTC time string "YYYY-MM-DD HH:MM:SS"
    -> return "YYYYMMDDT%H%M%SZ" without shifting.
    """
    if not timestr:
        return ""
    try:
        dt_utc = datetime.strptime(timestr, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return dt_utc.strftime("%Y%m%dT%H%M%SZ")
    except Exception:
        return timestr


# ==========================
# ✅ Menu utilities
# ==========================

def read_cmd(prompt: str):
    s = input(prompt).strip()
    if s.lower() == "q":
        raise SystemExit
    return s

def pick_index(prompt: str, n: int):
    s = read_cmd(prompt + " (number / b back / q quit): ")
    if s.lower() == "b":
        return None
    try:
        idx = int(s) - 1
        if 0 <= idx < n:
            return idx
    except ValueError:
        pass
    print("[!] Invalid input")
    return -1

# ==========================
# ✅ Program loop
# ==========================

def device_menu(sessionId: str, device_serial: list):
    cached_ticket = None
    dev_serial = device_serial[0]
    channel_no = device_serial[1]
    dev_tz_str = device_serial[2] if len(device_serial) > 2 else "UTC+00:00"
    dev_tz = parse_utc_offset_to_tz(dev_tz_str)

    while True:
        print("\n" + "=" * 70)
        print(f"[DEVICE] {device_serial[0]}")
        print(" 1. Select date → list/download videos")
        print(" 2. Get Cloud File List")
        print(" b. Back")
        print(" q. Quit")
        print("=" * 70)

        cmd = read_cmd("Select: ").lower()
        if cmd == "b":
            return

        if cmd == "1":
            days = get_video_days(sessionId, dev_serial, channel_no)
            if not days:
                print("[!] No available video days")
                continue

            print("\n[🎬 Select Date]")
            for i, d in enumerate(days, 1):
                print(f" {i}. {d.get('day')}")
            sel = read_cmd("Enter date index to fetch, or 'all' (b back / q quit): ").lower()
            if sel == "b":
                continue

            selected_days = []
            if sel == "all":
                selected_days = days
            else:
                try:
                    idx = int(sel) - 1
                    if 0 <= idx < len(days):
                        selected_days = [days[idx]]
                    else:
                        print("[!] Invalid index")
                        continue
                except ValueError:
                    print("[!] Input error")
                    continue

            all_videos = []
            for day in selected_days:
                day_str = day.get("day")
                if not day_str:
                    continue

                query_days = [day_str]

                if SHOW_UTC and SELECT_BY_UTC_DAY and UTC_QUERY_ADJACENT_DAYS:
                    query_days = list(dict.fromkeys([
                        iso_add_days(day_str, -1),
                        day_str,
                        iso_add_days(day_str, +1),
                    ]))

                for qd in query_days:
                    vids = get_cloud_videos_incr_per_day(
                        sessionId, dev_serial, channel_no, qd,
                        device_tz_str=dev_tz_str
                    )
                    if vids:
                        all_videos.extend(vids)

                if SHOW_UTC and SELECT_BY_UTC_DAY:
                    all_videos = [x for x in all_videos if (x.startTime or "")[:10] == day_str]

            all_videos.sort(key=lambda x: (x.startTime or "", x.seqId or 0))

            if not all_videos:
                print("[!] No videos found for the selected day(s)")
                continue

            print("\n[🎞️ CloudVideoInfo List]")
            print("No. | StartTime | StopTime | SeqId | OwnerId | KeyChecksum")
            print("-" * 90)
            for i, info in enumerate(all_videos, 1):
                print(f"{i:>3} | {info.startTime} | {info.stopTime} | {info.seqId} | "
                      f"{info.ownerId} | {info.keyChecksum}")

            while True:
                vid_idx = pick_index("Select a video to download", len(all_videos))
                if vid_idx is None:
                    break
                if vid_idx == -1:
                    continue

                if not cached_ticket:
                    cached_ticket = get_camera_ticket_info(sessionId, device_serial[0], device_serial[1])
                    if not cached_ticket:
                        print("[!] Failed to obtain ticket")
                        continue

                send_tls_playback_request_from_info(all_videos[vid_idx], cached_ticket)


        elif cmd == "2":
            flist = get_cloud_file_list(sessionId, device_serial[0], device_tz_str=dev_tz_str)
            if flist is None:
                print("[!] Cloud File List request failed")
                continue
            if not flist:
                print("[!] No cloud files found")
                continue

            target_day = read_cmd("Filter by day (YYYY-MM-DD) or Enter for all (b back / q quit): ").lower()
            if target_day == "b":
                continue
            if target_day.strip():
                if SHOW_UTC and SELECT_BY_UTC_DAY:
                    flist = [x for x in flist if (x.video_start_time or "")[:10] == target_day]
                else:
                    flist = [x for x in flist if (x.video_start_time or "")[:10] == target_day]

            flist.sort(key=lambda x: (x.video_start_time or "", x.file_id or ""))

            if not flist:
                print("[!] No cloud files after filtering")
                continue

            print("\n[🗂️ CloudFileInfo List]")
            print("No. | StartTime | StopTime | fileStorageTime | fileSize | userName")
            print("-" * 110)
            for i, f in enumerate(flist, 1):
                print(f"{i:>3} | {f.video_start_time} | {f.video_stop_time} | "
                      f"{f.file_storage_time} | {f.file_size} | {f.user_name}")

            while True:
                idx = pick_index("Select a CloudFile to download", len(flist))
                if idx is None:
                    break
                if idx == -1:
                    continue

                cf = flist[idx]
                print("\n[Selected CloudFile]")
                print(f"  Start : {cf.video_start_time}")
                print(f"  Stop  : {cf.video_stop_time}")
                print(f"  Size  : {cf.file_size}")
                print(f"  URL   : {cf.file_url}")

                base_name = f"{device_serial}_{cf.video_start_time}_{cf.video_stop_time}_{cf.file_id}.mp4"
                base_name = safe_filename(base_name)

                date_folder = _extract_date_folder(cf.video_start_time, cf.file_storage_time)
                out_dir = ensure_date_dir(date_folder)
                out_path = os.path.join(out_dir, base_name)
                download_file_url(cf.file_url, filename=out_path)
                print(f"[💾] Saved: {out_path}")

        else:
            print("[!] Invalid selection")

def main(log_dir="ezviz_log"):
    log_f = None
    old_stdout = old_stderr = None
    log_path = None

    try:
        # ✅ Create ezviz_log/<timestamp>.log on each run and apply tee logging
        log_f, log_path, _log_lock, old_stdout, old_stderr = setup_ezviz_logging(log_dir)

        sessionId = input("▶ Enter an existing sessionId (press Enter if none): ").strip()
        if not sessionId:
            account = input("📧 Ezviz account (email or phone number): ").strip()
            password_plain = input("🔑 Enter password: ").strip()
            sessionId = ezviz_login(account, password_plain, PUBKEY_B64)

        if not sessionId:
            print("[!] Failed to obtain sessionId. Exiting.")
            return

        while True:
            print("\n" + "=" * 70)
            print("[MAIN]")
            print(" 1. Select device")
            print(" 2. List registered terminals")
            print(" 3. Fetch user login logs (user_operate)")
            print(" q. Quit")
            print("=" * 70)

            cmd = read_cmd("Select: ").lower()

            if cmd == "1":
                serial_list = get_user_devices_pagelist(sessionId)
                if not serial_list:
                    print("[!] No devices found")
                    continue

                print("\n[📱 Connected Devices]")
                for i, s in enumerate(serial_list, 1):
                    print(f" {i}. {s[0]}")

                idx = pick_index("Select device", len(serial_list))
                if idx is None:
                    continue
                if idx == -1:
                    continue

                device_serial = serial_list[idx]
                device_menu(sessionId, device_serial)

            elif cmd == "2":
                get_terminals(sessionId)

            elif cmd == "3":
                res = get_user_login_logs(sessionId, offset=0, scrollId=1, limit=20)
                if isinstance(res, dict) and res.get("page") is not None:
                    print("\n[i] page:", json.dumps(res.get("page", {}), ensure_ascii=False))
            elif cmd == "q":
                raise SystemExit
            else:
                print("[!] Invalid selection")

    except SystemExit:
        print("\n[+] Exiting")
    except Exception as e:
        print("[!] Exception:", e)
        if log_path:
            print(f"[!] For details, check the log file: {log_path}")
    finally:
        if log_f and old_stdout and old_stderr:
            teardown_ezviz_logging(log_f, old_stdout, old_stderr)

def run_ezviz(case_info):
    ezviz_root = os.path.join(case_info.case_root, "ezviz")
    log_dir = os.path.join(ezviz_root, "ezviz_log")
    dl_dir = os.path.join(ezviz_root, "ezviz_download")
    keylog_dir = os.path.join(ezviz_root, "tls_keylog")
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(dl_dir, exist_ok=True)
    os.makedirs(keylog_dir, exist_ok=True)

    keylog_path = os.path.join(
        keylog_dir,
        f"sslkeylog_{datetime.now(timezone(timedelta(hours=9))).strftime('%Y%m%d_%H%M%S')}.log"
    )

    global SSLCTX
    SSLCTX = make_ssl_context_for_keylog(keylog_path)

    global REQ
    REQ = build_requests_session(SSLCTX)

    global BASE_DOWNLOAD_DIR
    BASE_DOWNLOAD_DIR = dl_dir

    print("[*] EZVIZ Case Root :", ezviz_root)
    print("[*] Log Dir         :", log_dir)
    print("[*] Download Dir    :", dl_dir)
    print("[*] TLS Keylog      :", keylog_path)

    main(log_dir=log_dir)



if __name__ == "__main__":
    main()

