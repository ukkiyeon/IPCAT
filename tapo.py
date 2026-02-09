import re
import json
import time
import uuid
import base64
import hmac
import hashlib
import binascii
import urllib3
import requests
from urllib.parse import urljoin
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from collections import defaultdict, Counter
import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo  # Python 3.9+


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEBUG_MAX_BODY = 20480          # Max bytes for debug output (text)
DEBUG_MAX_BINARY_PREVIEW = 512  # Binary preview size (HEX)

# ---------- Logging ----------
class TeeStdIO:
    """
    Record stdout/stderr to both the console and a file at the same time.
    - The console (terminal) prints the original output as-is (no timestamp/prefix).
    - The log file records each line with a timestamp prefix.
    - A shared lock is used to preserve output order and prevent interleaving.
    """
    def __init__(self, stream, file_obj, prefix_ts=True, lock=None):
        self.stream = stream
        self.file_obj = file_obj
        self.prefix_ts = prefix_ts
        self._lock = lock or threading.Lock()
        self._buf = ""  # for timestamped file logging

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
                file_line = f"[{self._ts()}] {line}\n"
                self.file_obj.write(file_line)
                self.file_obj.flush()

    def flush(self):
        with self._lock:
            if self.prefix_ts and self._buf:
                file_line = f"[{self._ts()}] {self._buf}"
                self._buf = ""
                self.file_obj.write(file_line)
                self.file_obj.flush()

            self.stream.flush()
            self.file_obj.flush()

# ---------- HTTP Client with Debug ----------
class HttpClient:
    def __init__(self, verify=False, debug=0, timeout=30, log_fp=None, log_lock=None):
        self.sess = requests.Session()
        self.verify = verify
        self.debug = debug
        self.timeout = timeout
        self.log_fp = log_fp
        self.log_lock = log_lock

    def _ts(self):
        tz_kst = timezone(timedelta(hours=9))
        return datetime.now(tz_kst).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _dlog(self, msg: str = ""):
        """Debug logs go to file only, with timestamp and lock"""
        if not self.debug or not self.log_fp:
            return
        lock = self.log_lock
        if lock:
            with lock:
                self.log_fp.write(f"[{self._ts()}] {msg}\n")
                self.log_fp.flush()
        else:
            self.log_fp.write(f"[{self._ts()}] {msg}\n")
            self.log_fp.flush()

    def _looks_binary(self, b: bytes) -> bool:
        if not b:
            return False
        nontext = sum(ch < 9 or (13 < ch < 32) for ch in b[:1024])
        return (b"\x00" in b[:1024]) or (nontext > len(b[:1024]) * 0.2)

    def _safe_print_body(self, content: bytes, headers: dict):
        if content is None:
            self._dlog("      (no body)")
            return
        ct = headers.get("Content-Type", "") if headers else ""
        is_text_hint = any(hint in ct for hint in ("json", "text", "xml", "javascript", "html", "m3u8"))
        preview = content[:DEBUG_MAX_BODY]

        if is_text_hint and not self._looks_binary(preview):
            try:
                text = preview.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    text = preview.decode("latin-1")
                except Exception:
                    text = ""
            if "json" in ct:
                try:
                    j = json.loads(text)
                    text = json.dumps(j, ensure_ascii=False, indent=2)
                except Exception:
                    pass
            self._dlog(text)
            if len(content) > DEBUG_MAX_BODY:
                self._dlog(f"\n      ... ({len(content)} bytes total, truncated at {DEBUG_MAX_BODY})")
        else:
            self._dlog(f"      (binary {len(content)} bytes)")
            hex_prev = binascii.hexlify(content[:DEBUG_MAX_BINARY_PREVIEW]).decode()
            self._dlog(f"      hex preview (first {min(len(content), DEBUG_MAX_BINARY_PREVIEW)} bytes):")
            for i in range(0, len(hex_prev), 32):
                self._dlog("      " + hex_prev[i:i+32])
            if len(content) > DEBUG_MAX_BINARY_PREVIEW:
                self._dlog("      ... (truncated preview)")

    def request(self, method, url, params=None, headers=None, data=None, json_body=None,
                stream=False, timeout=None):
        # ---- REQUEST LOG ----
        if self.debug:
            self._dlog(f">>> REQUEST {method.upper()} {url}")
            if params:
                self._dlog(f"    params: {params}")
            if headers:
                self._dlog("    headers:")
                for k, v in headers.items():
                    self._dlog(f"      {k}: {v}")
            if json_body is not None:
                body_bytes = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
                self._dlog("    body (json):")
                self._safe_print_body(body_bytes, {"Content-Type": "application/json"})
            elif data is not None:
                if isinstance(data, (bytes, bytearray)):
                    b = bytes(data)
                else:
                    b = str(data).encode("utf-8", errors="ignore")
                self._dlog("    body (raw):")
                self._safe_print_body(b, {"Content-Type": headers.get("Content-Type", "") if headers else ""})

        try:
            resp = self.sess.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                data=None if json_body is not None else data,
                json=json_body,
                stream=stream,
                timeout=timeout or self.timeout,
                verify=self.verify
            )
        except Exception as e:
            # Also log "request failed (no response)" cases
            if self.debug:
                self._dlog(f"!!! REQUEST ERROR ({type(e).__name__}): {e}")
            raise

        # ---- RESPONSE LOG ----
        if self.debug:
            self._dlog(f"<<< RESPONSE {resp.status_code} {resp.reason}")
            self._dlog("    headers:")
            for k, v in resp.headers.items():
                self._dlog(f"      {k}: {v}")

            if stream:
                self._dlog("    (stream=True; body not auto-read)")
            else:
                content = resp.content or b""
                self._dlog("    body:")
                self._safe_print_body(content, resp.headers)

        return resp

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)



def open_run_log_file(case_root: str, log_subdir="tapo_log"):
    """Create a log file under <case_root>/<log_subdir>/YYYYMMDD_HHMMSS.log"""
    log_dir = os.path.join(case_root, log_subdir)
    os.makedirs(log_dir, exist_ok=True)

    tz_kst = timezone(timedelta(hours=9))
    ts = datetime.now(tz_kst).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(log_dir, f"{ts}.log")
    f = open(path, "a", encoding="utf-8", buffering=1)
    return f, path


# ---------- AES CBC Decryption ----------
def decrypt_aes_cbc(data: bytes, key: bytes, iv: bytes, strip_pkcs7: bool = True) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    dec = decryptor.update(data) + decryptor.finalize()
    if strip_pkcs7 and dec:
        pad_len = dec[-1]
        if 1 <= pad_len <= 16 and dec[-pad_len:] == bytes([pad_len]) * pad_len:
            return dec[:-pad_len]
    return dec

# ---------- M3U8 Parser ----------
def parse_attribute_list(s):
    out = {}
    regex = re.compile(r'([A-Z0-9-]+)=("(?:[^"]*)"|[^,]*)')
    for m in regex.finditer(s):
        k = m.group(1)
        v = m.group(2)
        out[k] = v
    return out

def parse_m3u8_text(text, base_url=None):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    key = None
    segments = []
    i = 0
    while i < len(lines):
        l = lines[i]
        if l.startswith('#EXT-X-KEY'):
            attrs = parse_attribute_list(l[len('#EXT-X-KEY:'):])
            key = {
                'method': attrs.get('METHOD'),
                'uri': attrs.get('URI').strip('"') if attrs.get('URI') else None,
                'iv': attrs.get('IV')
            }
            if key['uri'] and base_url:
                key['uri'] = urljoin(base_url, key['uri'])
        elif l.startswith('#EXTINF'):
            duration = float(l.split(':', 1)[1].rstrip(','))
            br = None
            j = i + 1
            if j < len(lines) and lines[j].startswith('#EXT-X-BYTERANGE'):
                br_attr = lines[j].split(':', 1)[1]
                if '@' in br_attr:
                    length_s, offset_s = br_attr.split('@', 1)
                    br = (int(length_s), int(offset_s))
                else:
                    br = (int(br_attr), None)
                j += 1
            if j < len(lines) and not lines[j].startswith('#'):
                uri = lines[j]
                if base_url:
                    uri = urljoin(base_url, uri)
                segments.append({'duration': duration, 'byterange': br, 'uri': uri})
                i = j
        i += 1
    return {'key': key, 'segments': segments}

def parse_event_local_to_utc(event_local_str: str, region_tz: str):
    """
    event_local_str: e.g. "2026-02-09 13:05:22" (timezone info 없음)
    region_tz: e.g. "Asia/Seoul" (IANA TZ)
    return: (utc_dt, utc_str)
    """
    if not event_local_str:
        return None, "N/A"

    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]

    dt_naive = None
    for f in fmts:
        try:
            dt_naive = datetime.strptime(event_local_str, f)
            break
        except Exception:
            pass

    if dt_naive is None:
        return None, event_local_str

    try:
        tz = ZoneInfo(region_tz) if region_tz else timezone.utc
    except Exception:
        tz = timezone.utc

    dt_local = dt_naive.replace(tzinfo=tz)
    dt_utc = dt_local.astimezone(timezone.utc)      # UTC
    utc_str = dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    return dt_utc, utc_str

def _parse_epoch_to_utc_dt(v):
    """
    v: epoch seconds or milliseconds (int/str)
    return: datetime(UTC) or None
    """
    if v is None:
        return None
    try:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return None
            v = int(float(v))
        elif isinstance(v, float):
            v = int(v)
        elif not isinstance(v, int):
            return None

        if v >= 10**12:
            return datetime.fromtimestamp(v / 1000.0, tz=timezone.utc)
        else:
            return datetime.fromtimestamp(v, tz=timezone.utc)
    except Exception:
        return None


def _parse_event_local_to_utc_dt(event_local_str: str, region_tz: str):
    """
    fallback: eventLocalTime + device region tz UTC
    """
    if not event_local_str:
        return None

    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]

    dt_naive = None
    for f in fmts:
        try:
            dt_naive = datetime.strptime(event_local_str, f)
            break
        except Exception:
            pass
    if dt_naive is None:
        return None

    try:
        tz = ZoneInfo(region_tz) if region_tz else timezone.utc
    except Exception:
        tz = timezone.utc

    dt_local = dt_naive.replace(tzinfo=tz)
    return dt_local.astimezone(timezone.utc)


def get_event_utc_dt(ev: dict, region_tz: str):
    if not isinstance(ev, dict):
        return None

    event_obj = ev.get("event") if isinstance(ev.get("event"), dict) else {}
    data_obj = event_obj.get("data") if isinstance(event_obj.get("data"), dict) else {}

    candidates = [
        ev.get("timestamp"),
        ev.get("time"),
        ev.get("eventTime"),
        event_obj.get("timestamp"),
        event_obj.get("time"),
        event_obj.get("eventTime"),
        event_obj.get("eventTimeMs"),
        event_obj.get("eventTimeStamp"),
        event_obj.get("utcTime"),
        data_obj.get("timestamp"),
        data_obj.get("time"),
        data_obj.get("eventTime"),
    ]

    for c in candidates:
        dt = _parse_epoch_to_utc_dt(c)
        if dt:
            return dt

    for k in ("startTime", "endTime", "startTimestamp", "endTimestamp"):
        dt = _parse_epoch_to_utc_dt(ev.get(k))
        if dt:
            return dt
        dt = _parse_epoch_to_utc_dt(event_obj.get(k))
        if dt:
            return dt
        dt = _parse_epoch_to_utc_dt(data_obj.get(k))
        if dt:
            return dt

    ev_local = event_obj.get("eventLocalTime")
    return _parse_event_local_to_utc_dt(ev_local, region_tz)


def fmt_utc(dt_utc: datetime) -> str:
    if not dt_utc:
        return "N/A"
    return dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

def utc_range_to_local_dates(start_utc: datetime, end_utc: datetime, region_tz: str):
    """
    Convert UTC datetime range [start_utc, end_utc) into a set of local dates (region_tz)
    that might contain events in that UTC range when queried via 'byDate' API.

    Returns: (local_start_date, local_end_date_exclusive)
    """
    try:
        tz = ZoneInfo(region_tz) if region_tz else timezone.utc
    except Exception:
        tz = timezone.utc

    s_local = start_utc.astimezone(tz)
    e_local = end_utc.astimezone(tz)

    # We query by whole local-day buckets. To ensure coverage, include the local day that contains end_utc
    # because events very close to end boundary could appear in that local day's listing.
    local_start_date = s_local.date()
    local_end_date_excl = (e_local.date() + timedelta(days=1))  # +1 day to be safe at boundary
    return local_start_date, local_end_date_excl


def in_utc_range(dt_utc: datetime, start_utc: datetime, end_utc: datetime) -> bool:
    return dt_utc is not None and (start_utc <= dt_utc < end_utc)


# ---------- Key Fetch ----------
def fetch_key_bytes(client: HttpClient, key_uri, headers=None):
    print(f"[+] Fetching key from: {key_uri}")
    resp = client.get(key_uri, headers=headers, timeout=20)
    resp.raise_for_status()
    data = resp.content
    if len(data) == 16:
        return data

    text = resp.text.strip()

    # HEX
    hex_candidate = re.sub(r'[^0-9a-fA-F]', '', text)
    if len(hex_candidate) >= 32:
        try:
            return binascii.unhexlify(hex_candidate[:32])
        except Exception:
            pass

    # BASE64
    try:
        kb = base64.b64decode(text)
        if len(kb) == 16:
            return kb
    except Exception:
        pass

    # Search inside JSON
    try:
        j = resp.json()
        for cand in ("key", "data", "secret", "k"):
            if cand in j:
                val = j[cand]
                if isinstance(val, str):
                    v = val.strip()
                    if re.fullmatch(r"[0-9a-fA-F]{32}", v):
                        return binascii.unhexlify(v)
                    try:
                        b = base64.b64decode(v)
                        if len(b) == 16:
                            return b
                    except Exception:
                        pass
    except Exception:
        pass

    raise ValueError("Unable to parse key response into 16-byte AES key.")

# ---------- Segment Download ----------
def download_range(client: HttpClient, url, start, length, headers=None):
    end = start + length - 1
    rh = dict(headers or {})
    rh['Range'] = f'bytes={start}-{end}'
    r = client.get(url, headers=rh, stream=True, timeout=30)
    r.raise_for_status()
    # Even in debug mode, the actual bytes are assembled only here
    return b''.join(r.iter_content(16384))

# ---------- IV Handling ----------
def iv_from_str(iv_str, seq_num=None):
    if not iv_str:
        if seq_num is None:
            return None
        return seq_num.to_bytes(16, "big")
    s = iv_str.strip()
    if s.startswith("0x"):
        hexpart = s[2:].rjust(32, "0")
        return binascii.unhexlify(hexpart[:32])
    if s.isdigit():
        return int(s).to_bytes(16, "big")
    if re.fullmatch(r"[0-9a-fA-F]{1,32}", s):
        return binascii.unhexlify(s.rjust(32, "0"))
    return None

def get_signature(str1: str, str2: str, str3: str, str4: str, secret: str) -> str:
    data = f"{str1}\n{str2}\n{str3}\n{str4}"
    mac = hmac.new(secret.encode("utf-8"), data.encode("utf-8"), hashlib.sha1)
    return mac.hexdigest()

def login(client: HttpClient, user_id: str, password: str, term_id: str):
    url = (
        "https://n-wap.i.tplinkcloud.com/api/v2/account/login"
    )
    body = {
        "appType": "TP-Link_Tapo_Android",
        "appVersion": "3.13.818",
        "cloudPassword": password,
        "cloudUserName": user_id,
        "platform": "Android 11",
        "refreshTokenNeeded": False,
        "supportBindAccount": False,
        "terminalMeta": "1",
        "terminalName": "Google Pixel 2 XL",
        "terminalUUID": term_id,
    }
    body_str = json.dumps(body, separators=(",", ":"))
    md5_bytes = hashlib.md5(body_str.encode("utf-8")).digest()
    content_md5 = base64.b64encode(md5_bytes).decode()
    timestamp = "9999999999"
    nonce = str(uuid.uuid4())
    access_key = "4d11b6b9d5ea4d19a829adbb9714b057"
    secret = "6ed7d97f3e73467f8a5bab90b577ba4c"
    signature = get_signature(content_md5, timestamp, nonce, "/api/v2/account/login", secret)
    headers = {
        "accept-encoding": "gzip",
        "connection": "Keep-Alive",
        "content-length": str(len(body_str.encode("utf-8"))),
        "content-md5": content_md5,
        "content-type": "application/json; charset=UTF-8",
        "host": "n-wap.i.tplinkcloud.com",
        "user-agent": "okhttp/3.14.9",
        "x-authorization": f"Timestamp={timestamp}, Nonce={nonce}, AccessKey={access_key}, Signature={signature}",
    }
    resp = client.post(url, headers=headers, data=body_str)
    return resp.status_code, resp.text

# ----- 1) Fetch device basic info -----
# Simplified to keep only required headers
def get_device_info(client: HttpClient, account_id: str, token: str, term_id: str):
    url = f"https://aps1-app-tapo-care.i.tplinkcloud.com/v2/device/packages/byAccount"
    headers = {
        "authorization": f"ut|{token}",
        "x-app-name": "TP-Link_Tapo_Android"
    }
    resp = client.get(url, headers=headers)
    return resp.status_code, resp.text

# ----- 2) Fetch device detailed info -----
# Simplified to keep only required headers
def get_device_details(client: HttpClient, token: str, term_id: str):
    url = "https://aps1-app-server.iot.i.tplinkcloud.com/v2/things"
    headers = {
        "app-cid": f"app:TP-Link_Tapo_Android:{term_id}",
        "authorization": f"ut|{token}"
    }
    resp = client.get(url, headers=headers)
    return resp.status_code, resp.text

# ----- 4) Cloud video list & download API -----
# Simplified to keep only required headers
def get_cloud_videos(
    client: HttpClient,
    device_id: str,
    token: str,
    term_id: str,
    days: int = 30,
    debug: int = 0,
    region_tz: str = "UTC"
):
    """
    ✅ Apply the same logic as date-range mode (menu 5) to menu 4:
      - Interpret the last `days` as a UTC date window
      - UTC window: [start_utc, end_utc] where end_utc = tomorrow 00:00 UTC
      - Convert the UTC window into local-date buckets (region_tz) for wide byDate queries
      - Convert each event to UTC datetime using get_event_utc_dt
      - Strictly filter events by the UTC window
      - Group results by UTC date
      - Remove duplicate events by ID
    """
    # ✅ Set end_utc to tomorrow 00:00 UTC (includes today, last `days` days)
    today_utc = datetime.now(timezone.utc).date()
    end_utc = datetime(today_utc.year, today_utc.month, today_utc.day, 0, 0, 0, tzinfo=timezone.utc) + timedelta(days=1)
    start_utc = end_utc - timedelta(days=days)

    # ✅ Calculate local-date buckets covering the UTC window
    local_s, local_e_excl = utc_range_to_local_dates(start_utc, end_utc, region_tz)

    url = "https://aps1-app-tapo-care.i.tplinkcloud.com/v2/activities/listActivitiesByDate"
    headers = {
        "authorization": f"ut|{token}",
        "x-app-name": "TP-Link_Tapo_Android",
        "x-app-version": "3.13.818",
    }

    date_events = defaultdict(list)
    seen_ids = set()

    total_days = (local_e_excl - local_s).days
    for i in range(total_days):
        d = local_s + timedelta(days=i)

        body = {
            "deviceId": device_id,
            "startTime": f"{d} 00:00:00",
            "endTime": f"{(d + timedelta(days=1))} 00:00:00",
            "source": "1",
            "page": 0,
            "pageSize": 10,
        }

        resp = client.post(url, headers=headers, json_body=body)
        if resp.status_code != 200:
            time.sleep(1)
            continue

        data = resp.json()
        total = data.get("total", 0)

        # (Keep legacy behavior) expand pageSize to match total count
        if total > body["pageSize"]:
            body["pageSize"] = total
            resp2 = client.post(url, headers=headers, json_body=body)
            if resp2.status_code == 200:
                data = resp2.json()

        for ev in (data.get("listing", []) or []):
            ev_id = ev.get("id")
            if ev_id and ev_id in seen_ids:
                continue
            if ev_id:
                seen_ids.add(ev_id)

            dt_utc = get_event_utc_dt(ev, region_tz)
            if not dt_utc:
                continue

            if not in_utc_range(dt_utc, start_utc, end_utc):
                continue

            day_key = dt_utc.strftime("%Y-%m-%d")
            date_events[day_key].append(ev)

        time.sleep(1)

    if debug:
        print("\n[DEBUG] === Duplicate Event ID Check (last N days, strict UTC window) ===")
        for day, events in date_events.items():
            ids = [ev.get("id") for ev in events if ev.get("id")]
            c = Counter(ids)
            dup = [i for i, cnt in c.items() if cnt > 1]
            if dup:
                print(f" - {day}: Found {len(dup)} duplicate IDs")
                for d in dup:
                    print(f"    {d}")
            else:
                print(f" - {day}: No duplicates")

    summary = [(day, len(v), v) for day, v in date_events.items()]
    summary.sort(reverse=True)
    return summary




def get_cloud_videos_by_range(
    client: HttpClient,
    device_id: str,
    token: str,
    term_id: str,
    start_date: str,   # "YYYY-MM-DD" (interpreted as UTC date start)
    end_date: str,     # "YYYY-MM-DD" (interpreted as UTC date end, exclusive)
    debug: int = 0,
    region_tz: str = "UTC",
):

    try:
        s_date = datetime.strptime(start_date, "%Y-%m-%d").date()
        e_date = datetime.strptime(end_date, "%Y-%m-%d").date()
    except Exception:
        print("[-] Invalid date format. Please use YYYY-MM-DD.")
        return []

    if e_date <= s_date:
        print("[-] end_date must be greater than start_date. (end is exclusive)")
        return []

    start_utc = datetime(s_date.year, s_date.month, s_date.day, 0, 0, 0, tzinfo=timezone.utc)
    end_utc   = datetime(e_date.year, e_date.month, e_date.day, 0, 0, 0, tzinfo=timezone.utc)

    local_s, local_e_excl = utc_range_to_local_dates(start_utc, end_utc, region_tz)

    url = "https://aps1-app-tapo-care.i.tplinkcloud.com/v2/activities/listActivitiesByDate"
    headers = {
        "app-cid": f"app:TP-Link_Tapo_Android:{term_id}",
        "authorization": f"ut|{token}",
        "x-app-name": "TP-Link_Tapo_Android",
        "x-app-version": "3.13.818",
    }

    date_events = defaultdict(list)
    seen_ids = set()

    total_days = (local_e_excl - local_s).days
    for i in range(total_days):
        d = local_s + timedelta(days=i)

        body = {
            "deviceId": device_id,
            "startTime": f"{d} 00:00:00",
            "endTime": f"{(d + timedelta(days=1))} 00:00:00",
            "eventTypeFilters": [],
            "page": 0,
            "pageSize": 10,
            "source": "1",
        }

        resp = client.post(url, headers=headers, json_body=body)
        if resp.status_code != 200:
            time.sleep(1)
            continue

        data = resp.json()
        total = data.get("total", 0)

        if total > body["pageSize"]:
            body["pageSize"] = total
            resp2 = client.post(url, headers=headers, json_body=body)
            if resp2.status_code == 200:
                data = resp2.json()

        for ev in (data.get("listing", []) or []):
            ev_id = ev.get("id")
            if ev_id and ev_id in seen_ids:
                continue
            if ev_id:
                seen_ids.add(ev_id)

            dt_utc = get_event_utc_dt(ev, region_tz)
            if not dt_utc:
                continue

            if not in_utc_range(dt_utc, start_utc, end_utc):
                continue

            day_key = dt_utc.strftime("%Y-%m-%d")  # ✅ UTC day grouping
            date_events[day_key].append(ev)

        time.sleep(1)

    if debug:
        print("\n[DEBUG] === Duplicate Event ID Check (range, strict UTC window) ===")
        for day, events in date_events.items():
            ids = [ev.get("id") for ev in events if ev.get("id")]
            c = Counter(ids)
            dup = [i for i, cnt in c.items() if cnt > 1]
            if dup:
                print(f" - {day}: Found {len(dup)} duplicate IDs")
                for d in dup:
                    print(f"    {d}")
            else:
                print(f" - {day}: No duplicates")

    summary = [(day, len(v), v) for day, v in date_events.items()]
    summary.sort(reverse=True)
    return summary


def get_app_notifications(client: HttpClient, device_token: str, term_id: str):
    """Retrieve TP-Link Tapo app notifications."""

    msg_token =""

    if not msg_token:
        print("\n[?] msgToken was not provided.")
        print("\n[!] msgToken in shared_prefs/com.google.android.gms.appid.xml")
        msg_token = input("▶ Please enter the Tapo app msgToken value: ").strip()
        if not msg_token:
            print("[!] msgToken is missing. Exiting.")
            return

    url = f"https://n-aps1-wap.i.tplinkcloud.com/api/v2/common/getAppNotificationByPage?token={device_token}"

    index_time = int(time.time() * 1000)
    body = {
        "appType": "TP-Link_Tapo_Android",
        "contentVersion": 3,
        "deviceToken": msg_token,
        "direction": "asc",
        "index": 0,
        "indexTime": index_time,
        "limit": 50,
        "locale": "en_US",
        "mobileType": "ANDROID",
        "msgTypes": [
            "UNKNOWN_NOTIFICATION_MSG", "tapoShareLaunch", "tapoNewFirmware",
            "Motion", "Audio", "BabyCry", "tapoFfsNewDeviceFound", "smartTapoDeviceActivity",
            "PersonDetected", "PersonEnhanced", "tapoCameraSDNeedInitialization",
            "tapoCameraSDInsufficientStorage", "tapoCameraAreaIntrusionDetection",
            "tapoCameraLinecrossingDetection", "tapoCameraCameraTampering", "tapoGlassBreakingDetected",
            "tapoSmokeAlarmDetected", "tapoMeowDetected", "tapoBarkDetected",
            "TAPO_CARE_TRIAL_EXPIRING_IN_3_DAYS", "TAPO_CARE_TRIAL_EXPIRED",
            "TAPO_CARE_SUBSCRIPTION_EXPIRING_IN_3_DAYS", "TAPO_CARE_SUBSCRIPTION_EXPIRED",
            "TAPO_CARE_SUBSCRIPTION_PAYMENT_FAILED", "tapoHubTriggered", "tapoContactSensorTriggered",
            "tapoMotionSensorTriggered", "tapoSmartButtonTriggered", "tapoSmartSwitchTriggered",
            "tapoThermostatRadiatorValve", "tapoDeviceLowBattery", "tapoSensorFrequentlyTriggered",
            "brandPromotion", "marketPromotion", "announcement", "userResearch", "tapoDeviceOverheat",
            "tapoDeviceOverheatRelieve", "videosummaryGenerated", "videosummaryGeneratedV2",
            "videosummaryCanCreateFromClips", "tapoCareWeeklyReport", "tapoCareWeeklyReportNewFeature",
            "BatteryEmpty", "BatteryFullyCharged", "PowerSavingModeEnabled", "CameraLowBattery",
            "PetDetected", "VehicleDetected", "deliverPackageDetected", "pickUpPackageDetected",
            "antiTheft", "ringEvent", "missRingEvent", "tapoSensorWaterLeakDetected",
            "tapoSensorWaterLeakSolved", "tapoSensorTempTooWarm", "tapoSensorTempTooCool",
            "tapoSensorTooHumid", "tapoSensorTooDry", "lensMaskChargingEnabled",
            "tapoDevicePowerProtection", "currentProtectionEvent", "connectedApplianceFullyCharged",
            "Tapo.RelayOperatingAbnormal", "Tapo.DeviceBatteryEmpty", "tpSimpleSetup", "other",
            "robotBatteryExceptionEvent", "robotCleanRelativeEvent", "Tapo.SelfCleanRobotCleanCompleteEvent",
            "Tapo.SelfCleanRobotSelfMopCleanCompleteEvent", "Tapo.SelfCleanRobotSelfWaterShortageEvent",
            "Tapo.SelfCleanRobotWaterTankFullEvent", "Tapo.SelfCleanRobotMopClothDryingEvent",
            "robotLocateFailEvent", "robotIssueDetected", "abnormalBatteryPowerConsumption",
            "deviceOffline", "switchedToHardwirePowering", "switchedToBatteryPowering",
            "exitAlwaysOnMode", "tapoBabyLeave", "tapoBabyOffFence", "tapoMotionNearFence",
            "tapoBabyAwake", "tapoBabyAsleep", "tapoBabyFaceCoverd", "tapoBabyMove", "tapoCaptureNotice",
            "tapoWeeklySleepAnalysis", "tapoCaregiverDetected", "tapoCameraSDvideoInsufficientStorage",
            "Tapo.CameraSDCaptureInsufficientStorage", "Tapo.CameraSDCaptureNearlyFullStorage",
            "tapoCameraCloudCaptureInsufficientStorage", "Tapo.CloudStorageForMomentsNearlyFull",
            "tapoSubscriptionExpiration", "Tapo.CloudStorageForMomentsCleared",
            "Tapo.MonthlyGrowthRecordVideo", "Tapo.BirthdayGrowthRecordVideo",
            "Tapo.AnnualGrowthRecordVideo", "Tapo.NetworkSwitchTo4G", "Tapo.NetworkSwitchToWifi",
            "kasaCareFreeTrialEnded", "kasaCareSubscriptionExpired", "kasaCarePaymentFailed",
            "kasaCareSubscriptionCancellationFailed", "iotDeviceActivity", "iotDeviceManualRecording",
            "iotDeviceTampered", "iotDeviceTransactionTimeout", "iotDoorBellRing", "iotDeviceTempOverheat",
            "iotDeviceVideoSummary", "iotDeviceAbnormal", "iotDeviceLoadAbnormal", "messageActionPush",
            "lteTrafficExceedUsrSetLimit", "lteTrafficExceedTotalAmount", "tapoDeviceJam",
            "tapoDeviceUnlock", "tapoDeviceLock", "tapoDeviceWrongTry", "tapoDeviceDoorbellRang",
            "tapoDeviceMotorMalfunction", "tapoLockLowBattery", "newMessageFromTechnicalSupport",
            "familiarFaceDetected", "unfamiliarFaceDetected", "hardDiskNotInitialized",
            "hardDiskInsufficientStorage", "faceDetectWeeklyReport", "faceDetectMonthlyReport",
            "Tapo.EventsSummaryWeeklyReport", "Tapo.EventsSummaryMonthlyReport", "Tapo.LockLowDryBattery",
            "Tapo.SensorLowBattery", "Tapo.PanoramicVideo", "Tapo.CamSDCardEncryptionDisabled",
            "Tapo.CamSDCardAutomaticDecryptionFailed", "Tapo.DeviceSharingCanceled",
            "Tapo.CamBatteryLowStopAOV", "Tapo.CamBatterySufficientResumeAOV", "Tapo.LoiteringDetected",
            "Tapo.NvrDiskException", "Tapo.NvrDiskInsufficientStorage", "Tapo.NvrDiskNeedInitialization",
            "Tapo.NvrVideoLoss", "Tapo.LockDryExtremeLowBattery", "Tapo.LockLowMainBattery",
            "Tapo.LockLowBackupBattery", "Tapo.LockMainBatteryDepleted",
            "Tapo.LockBackupBatteryExtremeLowBattery", "Tapo.LockDoorSensorMalfunction",
            "Tapo.LockLeftOpenAlarm", "Tapo.DeviceFrequentOperations", "Tapo.LockDoorSensorOffset"
        ],
        "terminalUUID": term_id
    }


    body_str = json.dumps(body, separators=(",", ":"))
    md5_bytes = hashlib.md5(body_str.encode("utf-8")).digest()
    content_md5 = base64.b64encode(md5_bytes).decode()
    timestamp = "9999999999"
    nonce = str(uuid.uuid4())
    access_key = "4d11b6b9d5ea4d19a829adbb9714b057"
    secret = "6ed7d97f3e73467f8a5bab90b577ba4c"
    signature = get_signature(content_md5, timestamp, nonce, "/api/v2/common/getAppNotificationByPage", secret)
    headers = {
        "accept-encoding": "gzip",
        "connection": "Keep-Alive",
        "content-length": str(len(body_str.encode("utf-8"))),
        "content-md5": content_md5,
        "content-type": "application/json; charset=UTF-8",
        "user-agent": "okhttp/3.14.9",
        "x-authorization": f"Timestamp={timestamp}, Nonce={nonce}, AccessKey={access_key}, Signature={signature}",
    }
    resp = client.post(url, headers=headers, data=body_str)
    return resp.status_code, resp.text


# ----- 4), 5) View event list -----
def show_event_details(events, region_tz: str = "UTC"):
    print("\n=== Event List ===")
    for idx, ev in enumerate(events, 1):
        ev_id = ev.get("id", "N/A")
        event_data = ev.get("event", {}) if isinstance(ev.get("event"), dict) else {}
        ev_type = event_data.get("name", "N/A")

        dt_utc = get_event_utc_dt(ev, region_tz)
        ev_time_utc = fmt_utc(dt_utc)

        data_field = event_data.get("data", {}) if isinstance(event_data.get("data"), dict) else {}

        vlist = data_field.get("videoList") or []
        v0 = vlist[0] if vlist else {}

        duration = v0.get("duration")
        vsize = v0.get("size")

        parts = []
        if duration is not None:
            parts.append(f"duration={duration}s")
        if vsize is not None:
            parts.append(f"videoSize={vsize}B")
        extra = " | " + ", ".join(parts) if parts else ""

        print(f"[{idx}] Time(UTC): {ev_time_utc} | Type: {ev_type} | ID: {ev_id}{extra}")


# ----- 4), 5) Select multiple user events -----
def parse_index_selection(sel: str, n: int):
    """
    User input examples:
      "1,3,5" / "1-4" / "1,3-6" / "all" / "" (empty)
    Returns: a sorted list of 0-based indexes (deduplicated)
    """
    sel = (sel or "").strip().lower()
    if not sel:
        return []
    if sel in ("all", "*"):
        return list(range(n))

    out = set()
    tokens = [t.strip() for t in sel.split(",") if t.strip()]
    for t in tokens:
        if "-" in t:
            a, b = t.split("-", 1)
            if a.strip().isdigit() and b.strip().isdigit():
                start = int(a.strip())
                end = int(b.strip())
                if start > end:
                    start, end = end, start
                for k in range(start, end + 1):
                    if 1 <= k <= n:
                        out.add(k - 1)
        else:
            if t.isdigit():
                k = int(t)
                if 1 <= k <= n:
                    out.add(k - 1)
    return sorted(out)


def decrypt_snapshot(client: HttpClient, url: str, key_b64: str, iv_b64: str, out_dir: str = "."):
    filename = os.path.basename(url.split("?")[0])
    enc_path = os.path.join(out_dir, filename)
    dec_path = os.path.join(out_dir, filename.rsplit(".", 1)[0] + "_decrypt.jpeg")

    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)

    print(f"[+] Downloading encrypted JPEG from:\n    {url}")
    resp = client.get(url, timeout=30)
    resp.raise_for_status()
    enc_data = resp.content
    with open(enc_path, "wb") as f:
        f.write(enc_data)
    print(f"[+] Saved encrypted file: {enc_path}")

    print("[+] Decrypting...")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    dec_data = decryptor.update(enc_data) + decryptor.finalize()
    with open(dec_path, "wb") as f:
        f.write(dec_data)
    print(f"[+] Saved decrypted file: {dec_path}")

# ----- Output: 1) Get basic device info -----
def _print_device_basic_info(dev: dict):
    print("\n--- Basic Device Info (deviceList) ---")
    for k in sorted(dev.keys()):
        print(f"  {k:<22}: {dev.get(k)}")

# ----- Output: 2) Get detailed device info -----
def _print_device_detail_info(detail: dict):
    # Details from get_device_details() -> things
    print("\n--- Detailed Device Info (things) ---")
    keys = [
        "thingName", "model", "deviceName", "category", "deviceType",
        "hwVer", "fwVer", "mac", "ssid", "region", "status",
        "appServerUrl", "cloudGatewayUrl", "cloudGatewayUrlV2",
        "familyId", "roomId", "oemId", "hwId", "fwId", "mqttRegion",
        "localAccessToken", "thingModelId", "avatarUrl"
    ]
    for k in keys:
        if k in detail:
            print(f"{k:<22}: {detail.get(k)}")

    # nickname base64 decode
    nick_b64 = detail.get("nickname")
    if nick_b64:
        try:
            nick = base64.b64decode(nick_b64).decode("utf-8", errors="replace")
            print(f"{'nickname(decoded)':<22}: {nick}")
        except Exception:
            pass


# ----- 4) Cloud video query + download flow -----
def _cloud_download_flow(client: HttpClient, device_id: str, token: str, term_id: str, days: int, debug: int, case_root: str, region_tz: str = "UTC"):
    """
    Refactored existing logic into a function:
    summary -> select day -> select event(s) -> decrypt snapshot -> download/decrypt m3u8
    """
    summary = get_cloud_videos(
        client=client,
        device_id=device_id,
        token=token,
        term_id=term_id,
        days=days,
        debug=debug,
        region_tz=region_tz
    )

    if not summary:
        print(f"No videos/events found in the last {days} days.")
        return

    while True:
        print("\n=== Video Summary (UTC+0) ===")
        for idx, (day, total, _) in enumerate(summary, 1):
            print(f"{idx}. {day} - {total} events")

        day_choice = input("\nSelect a day index to view (b=back): ").strip().lower()
        if day_choice == "b":
            return
        if not day_choice.isdigit() or not (1 <= int(day_choice) <= len(summary)):
            print("Invalid input. Please select again.")
            continue

        _, _, events = summary[int(day_choice) - 1]
        show_event_details(events, region_tz=region_tz)

        # Multi-select events supported (e.g., 1,3,5 / 1-4 / 1,3-6 / all)
        ev_sel = input("\nEnter event index(es) to decrypt/download (e.g., 1,3,5 / 1-4 / all / b=back, Enter=skip): ").strip().lower()
        if ev_sel == "b":
            continue

        sel_idxs = parse_index_selection(ev_sel, len(events))
        if not sel_idxs:
            # Enter(skip) or invalid input -> continue loop
            continue

        # Process selected events in order
        for sel_i in sel_idxs:
            ev = events[sel_i]
            data_field = ev.get("event", {}).get("data", {}) if isinstance(ev.get("event", {}), dict) else {}

            print(f"\n--- [{sel_i + 1}] Starting event processing ---")

            # --- Pre-build snapshot list (actual save happens after ev_dir is created) ---
            snap_list = []
            if data_field.get("snapshot"):
                snap_list.append(data_field["snapshot"])
            if data_field.get("snapshotList"):
                snap_list.extend(data_field["snapshotList"])

            # --- Video download/decryption list ---
            video_urls = []
            for v in data_field.get("videoList", []):
                if v.get("streamUrl"):
                    video_urls.append(v["streamUrl"])
                for ex in v.get("extraResolutionInfos", []):
                    if ex.get("streamUrl"):
                        video_urls.append(ex["streamUrl"])

            if not video_urls:
                print("No video URL found.")
                continue

            print("\n=== Event Video List ===")
            for i, vurl in enumerate(video_urls, 1):
                print(f"{i}. {vurl}")

            chosen_url = video_urls[0]
            print("\n[+] Downloading video #1")
            m3u8_url = chosen_url
            joiner = '&' if '?' in m3u8_url else '?'
            m3u8_url = f"{m3u8_url}{joiner}token={token}&retryTimes=0"

            print(f"[+] Fetching playlist: {m3u8_url}")
            r = client.get(m3u8_url, timeout=30)
            r.raise_for_status()

            parsed = parse_m3u8_text(r.text, base_url=m3u8_url)
            keyinfo = parsed["key"]
            segments = parsed["segments"]

            if not segments:
                print("[-] No segments found.")
                continue

            key_bytes = None
            if keyinfo and keyinfo["method"] and keyinfo["method"].upper() != "NONE":
                try:
                    key_bytes = fetch_key_bytes(client, keyinfo["uri"])
                    print("[+] Key:", binascii.hexlify(key_bytes).decode())
                except Exception as e:
                    print("[-] Key fetch failed:", e)
                    key_bytes = None
            else:
                print("[*] No encryption detected.")

            # Create per-event folder (prevent overwrites)
            ev_prefix = ev.get("id", f"ev_{sel_i + 1}")
            ev_time = (ev.get("event", {}).get("eventLocalTime") or "").replace(":", "").replace(" ", "_")
            base_dl = os.path.join(case_root, "tapo_download")
            ev_dir = os.path.join(base_dl, f"{ev_prefix}_{ev_time}" if ev_time else ev_prefix)
            os.makedirs(ev_dir, exist_ok=True)

            # --- Snapshot decrypt (save into event folder) ---
            if snap_list:
                s0 = snap_list[0]
                if s0.get("url") and s0.get("decryptionInfo"):
                    key = s0["decryptionInfo"].get("key")
                    iv = s0["decryptionInfo"].get("iv")
                    if key and iv:
                        decrypt_snapshot(client, s0["url"], key, iv, out_dir=ev_dir)

            # --- Merge download/decrypt video ---
            chosen_url = video_urls[0]
            merged_ts_path = os.path.join(ev_dir, "video_merged_decrypted.ts")

            fetch_and_decrypt_m3u8_merge_ts(
                client=client,
                m3u8_url=chosen_url,  # Use original URL (do not append token here)
                token=token,
                out_path_ts=merged_ts_path,
                save_segments=True,
                seg_prefix=f"{ev_prefix}_v1"
            )

            print(f"--- [{sel_i + 1}] Event processing complete ---")


# ----- 5) Cloud video query & download (date range) -----
def _cloud_download_flow_range(
    client: HttpClient,
    device_id: str,
    token: str,
    term_id: str,
    start_date: str,
    end_date: str,
    debug: int,
    case_root: str,
    region_tz: str = "UTC"
):
    summary = get_cloud_videos_by_range(
        client=client,
        device_id=device_id,
        token=token,
        term_id=term_id,
        start_date=start_date,
        end_date=end_date,
        debug=debug,
        region_tz=region_tz
    )

    if not summary:
        print(f"No videos/events found in the range {start_date} ~ {end_date}.")
        return

    while True:
        print("\n=== Video Summary (UTC+0) ===")
        for idx, (day, total, _) in enumerate(summary, 1):
            print(f"{idx}. {day} - {total} events")

        day_choice = input("\nSelect a day index to view (b=back): ").strip().lower()
        if day_choice == "b":
            return
        if not day_choice.isdigit() or not (1 <= int(day_choice) <= len(summary)):
            print("Invalid input. Please select again.")
            continue

        _, _, events = summary[int(day_choice) - 1]
        show_event_details(events, region_tz=region_tz)

        ev_sel = input("\nEnter event index(es) to decrypt/download (e.g., 1,3,5 / 1-4 / all / b=back, Enter=skip): ").strip().lower()
        if ev_sel == "b":
            continue

        sel_idxs = parse_index_selection(ev_sel, len(events))
        if not sel_idxs:
            continue

        for sel_i in sel_idxs:
            ev = events[sel_i]
            event_obj = ev.get("event", {}) if isinstance(ev.get("event", {}), dict) else {}
            data_field = event_obj.get("data", {}) if isinstance(event_obj.get("data", {}), dict) else {}

            ev_id = ev.get("id", f"ev_{sel_i + 1}")
            ev_time = (event_obj.get("eventLocalTime") or "").replace(":", "").replace(" ", "_")
            ev_type = event_obj.get("name")

            print(f"\n--- [{sel_i + 1}] Starting event processing ---")

            # Create per-event folder (downloads/<eventId>_<time>/)
            base_dl = os.path.join(case_root, "tapo_download")
            ev_dir = os.path.join(base_dl, f"{ev_id}_{ev_time}" if ev_time else ev_id)
            os.makedirs(ev_dir, exist_ok=True)

            # --- Snapshot decrypt (save into event folder) ---
            snap_list = []
            if data_field.get("snapshot"):
                snap_list.append(data_field["snapshot"])
            if data_field.get("snapshotList"):
                snap_list.extend(data_field["snapshotList"])

            if snap_list:
                s0 = snap_list[0]
                try:
                    if s0.get("url") and s0.get("decryptionInfo"):
                        key = s0["decryptionInfo"].get("key")
                        iv = s0["decryptionInfo"].get("iv")
                        if key and iv:
                            decrypt_snapshot(client, s0["url"], key, iv, out_dir=ev_dir)
                except Exception as ex:
                    print("[-] Snapshot decrypt failed:", ex)
            else:
                print("No snapshot available.")

            # --- Collect video URLs ---
            video_urls = []
            for v in (data_field.get("videoList", []) or []):
                if v.get("streamUrl"):
                    video_urls.append(v["streamUrl"])
                for ex in (v.get("extraResolutionInfos", []) or []):
                    if ex.get("streamUrl"):
                        video_urls.append(ex["streamUrl"])

            if not video_urls:
                print("No video URL found.")
                print(f"--- [{sel_i + 1}] Event processing completed (no video) ---")
                continue

            # (Display only; selection is fixed to #1)
            print("\n=== Video List ===")
            for i, vurl in enumerate(video_urls, 1):
                print(f"{i}. {vurl}")

            chosen_url = video_urls[0]
            print("\n[+] Video selection: fixed to #1")

            # ✅ Merged TS output path
            merged_ts_path = os.path.join(ev_dir, "video_merged_decrypted.ts")

            # ✅ Run merge download (playlist/segments handled inside)
            try:
                fetch_and_decrypt_m3u8_merge_ts(
                    client=client,
                    m3u8_url=chosen_url,
                    token=token,
                    out_path_ts=merged_ts_path,
                    save_segments=True,
                    seg_prefix=f"{ev_id}_v1"
                )
            except Exception as ex:
                print("[-] Video fetch/decrypt/merge failed:", ex)

            print(f"--- [{sel_i + 1}] Event processing complete ---")


def fetch_and_decrypt_m3u8_merge_ts(
    client: HttpClient,
    m3u8_url: str,
    token: str,
    out_path_ts: str,
    save_segments: bool = True,
    seg_prefix: str = "seg"
):
    """
    Given m3u8_url:
      - Download segments
      - Decrypt AES-128 CBC if required
      - Merge and save everything into out_path_ts
      - Optionally save per-segment encrypted/decrypted files

    out_path_ts example: "./downloads/<event_id>/video_merged_decrypted.ts"
    """
    os.makedirs(os.path.dirname(out_path_ts) or ".", exist_ok=True)

    joiner = '&' if '?' in m3u8_url else '?'
    m3u8_url = f"{m3u8_url}{joiner}token={token}&retryTimes=0"

    print(f"[+] Fetching playlist: {m3u8_url}")
    r = client.get(m3u8_url, timeout=30)
    r.raise_for_status()

    parsed = parse_m3u8_text(r.text, base_url=m3u8_url)
    keyinfo = parsed["key"]
    segments = parsed["segments"]
    if not segments:
        print("[-] No segments found.")
        return

    key_bytes = None
    if keyinfo and keyinfo.get("method") and keyinfo["method"].upper() != "NONE":
        try:
            key_bytes = fetch_key_bytes(client, keyinfo["uri"])
            print("[+] Key:", binascii.hexlify(key_bytes).decode())
        except Exception as e:
            print("[-] Key fetch failed:", e)
            key_bytes = None
    else:
        print("[*] No encryption detected.")

    out_dir = os.path.dirname(out_path_ts) or "."
    merged_tmp = out_path_ts + ".part"

    with open(merged_tmp, "wb") as merged_out:
        for seg_idx, seg in enumerate(segments):
            seg_url = seg["uri"]
            filename = os.path.basename(seg_url.split("?")[0]) or "segment.ts"

            raw_name = os.path.join(out_dir, f"{seg_prefix}_{seg_idx:04d}_{filename}_encrypted.ts")
            dec_name = os.path.join(out_dir, f"{seg_prefix}_{seg_idx:04d}_{filename}_decrypted.ts")

            # 1) download
            if seg.get("byterange"):
                length, offset = seg["byterange"]
                if offset is None:
                    print("[-] Byterange without explicit offset is not supported.")
                    continue
                print(f"[+] Downloading {seg_url} range={offset}-{offset + length - 1}")
                data = download_range(client, seg_url, offset, length)
            else:
                print(f"[+] Downloading full segment: {seg_url}")
                rr = client.get(seg_url, timeout=30)
                rr.raise_for_status()
                data = rr.content

            # 2) optional save encrypted segment
            if save_segments:
                with open(raw_name, "wb") as f:
                    f.write(data)

            # 3) decrypt (if key exists)
            if key_bytes:
                ivv = iv_from_str(keyinfo.get("iv"), seq_num=seg_idx)
                if ivv is None:
                    ivv = seg_idx.to_bytes(16, "big")
                data = decrypt_aes_cbc(data, key_bytes, ivv)

            # 4) optional save decrypted segment
            if save_segments:
                with open(dec_name, "wb") as f:
                    f.write(data)

            # 5) ✅ merge append
            merged_out.write(data)

    os.replace(merged_tmp, out_path_ts)
    print(f"[+] Merged TS saved: {out_path_ts}")


def device_submenu(client: HttpClient, account_id: str, token: str, term_id: str,
                      device_id: str, device_basic: dict, device_detail: dict, debug: int, case_root: str, device_region: str = "UTC"):
    while True:
        print("\n=== Tapo Device Menu ===")
        print(f"Device ID: {device_id}")
        print("1) View basic device info")
        print("2) View detailed device info")
        print("3) View device notifications")
        print("4) View & download cloud videos")
        print("5) View & download cloud videos (date range)")
        print("b) Back to device list")

        sel = input("Select: ").strip().lower()
        if sel == "b":
            return

        if sel == "1":
            _print_device_basic_info(device_basic)
            input("\nPress Enter to return...")
        elif sel == "2":
            _print_device_detail_info(device_detail)
            input("\nPress Enter to return...")
        elif sel == "3":
            # This function prompts for msgToken internally
            get_app_notifications(client, token, term_id)
            input("\nPress Enter to return...")
        elif sel == "4":
            # Default: 7
            _cloud_download_flow(client, device_id, token, term_id, days=30, debug=debug,
                                 case_root=case_root, region_tz=device_region)
        elif sel == "5":
            print("[*] Date range is interpreted as UTC dates. (end date is exclusive)")

            s = input("▶ Start date (YYYY-MM-DD): ").strip()
            e = input("▶ End date (YYYY-MM-DD, end is exclusive): ").strip()

            _cloud_download_flow_range(
                client=client,
                device_id=device_id,
                token=token,
                term_id=term_id,
                start_date=s,
                end_date=e,
                debug=debug,
                case_root=case_root,
                region_tz=device_region
            )

        else:
            print("Invalid input. Please try again.")


def run_tapo(case_info):
    log_f, log_path = open_run_log_file(case_info.case_root, "tapo_log")

    # ✅ Shared lock for preserving output ordering across console + file
    log_lock = threading.Lock()

    orig_stdout = sys.stdout
    orig_stderr = sys.stderr

    # ✅ Apply stdout/stderr tee logging (all prints also saved to file)
    sys.stdout = TeeStdIO(sys.__stdout__, log_f, prefix_ts=True, lock=log_lock)
    sys.stderr = TeeStdIO(sys.__stderr__, log_f, prefix_ts=True, lock=log_lock)

    try:
        print(f"\n[+] Tapo log file: {log_path}")
        print("=== TP-Link Tapo ===")

        debug = 1
        user_id = input("▶ Cloud User ID(email) (Enter=use token mode): ").strip()

        # ✅ HttpClient shares the same lock
        client = HttpClient(verify=False, debug=debug, timeout=30, log_fp=log_f, log_lock=log_lock)

        # -------------------------------------------------------
        # Login or token mode
        # -------------------------------------------------------

        print("Enter the previously authenticated terminaluuid for the account you want to use.")
        print("On Android, you can check term_uuid_pref.xml (terminal UUID pref file).")
        term_id = input("▶ terminaluuid (Enter=auto-generate): ").strip()


        if not term_id:
            term_id = uuid.uuid4().hex.upper()[:30]

        if not user_id:
            token = input("▶ Existing access token: ").strip()
            account_id = input("▶ accountId: ").strip()
            if not token or not account_id:
                print("[!] Missing token/accountId. Exiting.")
                return
            print("\n[+] Existing token provided. Skipping login process.")
        else:
            password = input("▶ Cloud Password: ").strip()
            if not password:
                print("[!] Password is missing. Exiting.")
                return

            status, response = login(client, user_id, password, term_id)
            if status != 200:
                print("Login failed")
                return

            data = json.loads(response)
            if data.get("error_code") != 0:
                print("Login failed:", data)
                return

            result = data.get("result", {})

            # ✅ Prevent crash if MFA is enabled and token is not issued
            if "token" not in result:
                print("\n[!] MFA (2-step verification) is enabled, so no token was issued.")
                print(f"    - errorMsg: {result.get('errorMsg')}")
                print(f"    - MFAProcessId: {result.get('MFAProcessId')}")
                print(f"    - supportedMFATypes: {result.get('supportedMFATypes')}")
                return

            token = result["token"]
            account_id = result["accountId"]

            print("\n=== Login successful ===")
            print(f"Token: {token}")
            print(f"Account ID : {account_id}")

        # -------------------------------------------------------
        # (Optional) App Notification
        # -------------------------------------------------------
        use_noti = input("\n▶ Do you want to fetch App Notifications? (y/n): ").strip().lower()
        if use_noti == "y":
            _, ret = get_app_notifications(client, token, term_id)
            text = ret.strip()
            print(text)

        # -------------------------------------------------------
        # Device/event loop
        # -------------------------------------------------------
        while True:
            d_status, d_response = get_device_info(client, account_id, token, term_id)
            d_json = json.loads(d_response) if d_status == 200 else {}
            device_list = d_json.get("deviceList", [])
            if not device_list:
                print("No devices found.")
                return

            s_status, s_response = get_device_details(client, token, term_id)
            s_json = json.loads(s_response) if s_status == 200 else {}
            detail_list = s_json.get("data", [])
            detail_map = {d["thingName"]: d for d in detail_list if "thingName" in d}

            print("\n=== Device List ===")
            for idx, dev in enumerate(device_list, 1):
                dev_id = dev.get("deviceId")
                print(f"\n[{idx}] Device")
                print(f"  Device ID : {dev_id}")
                print(f"  Trial     : {dev.get('trial', {}).get('status')}")
                print(f"  Timestamp : {dev.get('timestamp')}")

                detail = detail_map.get(dev_id)
                if detail:
                    nickname_encoded = detail.get("nickname", "")
                    nickname_decoded = None
                    try:
                        nickname_decoded = base64.b64decode(nickname_encoded).decode("utf-8")
                    except Exception:
                        pass

                    print(f"  Model     : {detail.get('model')}")
                    print(f"  Nickname  : {nickname_decoded if nickname_decoded else nickname_encoded}")
                    print(f"  Category  : {detail.get('category')}")
                    print(f"  DeviceType: {detail.get('deviceType')}")
                    print(f"  HW Ver    : {detail.get('hwVer')}")
                    print(f"  FW Ver    : {detail.get('fwVer')}")
                    print(f"  MAC       : {detail.get('mac')}")
                    print(f"  SSID      : {detail.get('ssid')}")
                    print(f"  Region    : {detail.get('region')}")

            choice = input("\nSelect a device index to view (b=back): ").strip()
            if choice.lower() == "b":
                print("Exiting Tapo menu and returning to the previous menu.")
                return
            if not choice.isdigit() or not (1 <= int(choice) <= len(device_list)):
                print("Invalid input. Please select again.")
                continue

            idx = int(choice) - 1
            device_basic = device_list[idx]
            device_id = device_basic.get("deviceId")

            # detail_map is already available; fetch device detail from it
            device_detail = detail_map.get(device_id, {})
            device_region = device_detail.get("region") or "UTC"

            device_submenu(
                client=client,
                account_id=account_id,
                token=token,
                term_id=term_id,
                device_id=device_id,
                device_basic=device_basic,
                device_detail=device_detail,
                debug=debug,
                case_root=case_info.case_root,
                device_region=device_region,
            )



    except Exception:
        import traceback
        # If you want exceptions logged into the file as well:
        traceback.print_exc()
        print("[!] Exception occurred. For details, check the log file:", log_path)
    finally:
        sys.stdout = orig_stdout
        sys.stderr = orig_stderr
        try:
            log_f.close()
        except Exception:
            pass

if __name__ == "__main__":
    run_tapo()
