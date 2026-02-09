#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import gzip
import json
import base64
import hashlib
import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from http.cookies import SimpleCookie
from Cryptodome.Cipher import ARC4
from Cryptodome.Cipher import AES
import binascii
import subprocess
import shutil
import sys
import threading
from datetime import datetime, timezone, timedelta
import webbrowser
from xiaomi_2fa import run_xiaomi_2fa

# ================= Basic Configuration =================
URL1 = "https://account.xiaomi.com/pass/serviceLogin?_json=true&sid=xiaomiio&_locale=en_US"
URL2 = "https://account.xiaomi.com/pass/serviceLoginAuth2"

HEADERS_BASE = {
    "Accept-Encoding": "gzip",
    "Connection": "Keep-Alive",
    "Content-Type": "application/x-www-form-urlencoded",
}

# ===== Logging (xiaomi_log) =====
class TeeStdIO:
    """
    Record stdout/stderr to both the console and a file at the same time.
    - The console (terminal) shows the original output as-is.
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
        # KST(UTC+9)
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


def open_run_log_file(log_dir="xiaomi_log"):
    # Create a log filename based on KST (UTC+9) and open the log file
    os.makedirs(log_dir, exist_ok=True)
    tz_kst = timezone(timedelta(hours=9))
    ts = datetime.now(tz_kst).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(log_dir, f"{ts}.log")
    f = open(path, "a", encoding="utf-8", buffering=1)
    return f, path

def log_http_exchange(tag: str, method: str, url: str,
                      headers: dict = None,
                      cookies: dict = None,
                      data=None,
                      params=None,
                      resp: requests.Response = None,
                      note: str = None):
    """
    Write a full HTTP request/response exchange into debug log (file-only).
    No masking. Use with care.
    """
    try:
        dlog("")
        dlog(f"====== [XIAOMI][{tag}][REQ] ===========================")
        if note:
            dlog("note:", note)
        dlog("method:", method)
        dlog("url:", url)
        if headers is not None:
            dlog("headers:", json.dumps(headers, ensure_ascii=False) if isinstance(headers, dict) else str(headers))
        if cookies is not None:
            dlog("cookies:", json.dumps(cookies, ensure_ascii=False) if isinstance(cookies, dict) else str(cookies))

        if params is not None:
            dlog("params:", json.dumps(params, ensure_ascii=False) if isinstance(params, dict) else str(params))
        if data is not None:
            # data can be dict or str (form)
            dlog("data:", json.dumps(data, ensure_ascii=False) if isinstance(data, dict) else str(data))

        if resp is not None:
            dlog(f"------ [XIAOMI][{tag}][RESP] ---------------------------")
            dlog("status_code:", resp.status_code)
            dlog("resp.headers:", dict(resp.headers))
            txt = resp.text if isinstance(resp.text, str) else ""
            dlog("resp.text (head):", txt[:8000] + ("... <truncated>" if len(txt) > 8000 else ""))
    except Exception:
        pass



# ===== Debug-only logger (file only; no console) =====
DEBUG_LOG_F = None
DEBUG_LOG_LOCK = None

def _ts_kst():
    tz_kst = timezone(timedelta(hours=9))
    return datetime.now(tz_kst).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def bind_debug_logger(log_f, log_lock):
    global DEBUG_LOG_F, DEBUG_LOG_LOCK
    DEBUG_LOG_F = log_f
    DEBUG_LOG_LOCK = log_lock

def dlog(*args, sep=" ", end="\n"):
    global DEBUG_LOG_F, DEBUG_LOG_LOCK
    if not DEBUG_LOG_F:
        return
    msg = sep.join("" if a is None else str(a) for a in args)
    with (DEBUG_LOG_LOCK or threading.Lock()):
        for line in msg.splitlines() or [""]:
            DEBUG_LOG_F.write(f"[{_ts_kst()}] {line}{end}")
        DEBUG_LOG_F.flush()


def setup_xiaomi_logging(log_dir="xiaomi_log"):
    # Apply tee to stdout/stderr so output is written to both the console and a file
    log_f, log_path = open_run_log_file(log_dir)
    log_lock = threading.Lock()

    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = TeeStdIO(sys.__stdout__, log_f, prefix_ts=True, lock=log_lock)
    sys.stderr = TeeStdIO(sys.__stderr__, log_f, prefix_ts=True, lock=log_lock)

    print(f"\n[+] Xiaomi log file: {log_path}")
    bind_debug_logger(log_f, log_lock)
    return log_f, log_path, log_lock, old_stdout, old_stderr


def teardown_xiaomi_logging(log_f, old_stdout, old_stderr):
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



# ================= Utility Functions =================
def decrypt_aes128_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(data)
    # Remove PKCS7 padding
    pad_len = dec[-1]
    if 1 <= pad_len <= 16:
        dec = dec[:-pad_len]
    return dec


def generate_nonce() -> str:
    millis = round(time.time() * 1000)
    nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder="big")
    return base64.b64encode(nonce_bytes).decode()


def signed_nonce_sec(nonce: str, ssecurity: str) -> str:
    hash_object = hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(nonce))
    return base64.b64encode(hash_object.digest()).decode("utf-8")


def encrypt_rc4(password: str, payload: str) -> str:
    r = ARC4.new(base64.b64decode(password))
    r.encrypt(bytes(1024))
    return base64.b64encode(r.encrypt(payload.encode())).decode()


def decrypt_rc4(password: str, payload: str) -> bytes:
    r = ARC4.new(base64.b64decode(password))
    r.encrypt(bytes(1024))
    return r.encrypt(base64.b64decode(payload))


def generate_enc_signature(url_key, method, signed_nonce, params):
    signature_params = [str(method).upper(), url_key]
    for k, v in params.items():
        signature_params.append(f"{k}={v}")
    signature_params.append(signed_nonce)
    signature_string = "&".join(signature_params)
    return base64.b64encode(hashlib.sha1(signature_string.encode('utf-8')).digest()).decode()


def generate_enc_params(url_key, method, signed_nonce, nonce, params, ssecurity):
    params['rc4_hash__'] = generate_enc_signature(url_key, method, signed_nonce, params)
    for k, v in list(params.items()):
        params[k] = encrypt_rc4(signed_nonce, v)
    params.update({
        'signature': generate_enc_signature(url_key, method, signed_nonce, params),
        'ssecurity': ssecurity,
        '_nonce': nonce,
    })
    return params


def run_ffmpeg_merge(ffmpeg_path: str, concat_list_path: str, out_mp4: str) -> bool:
    cmd = [
        ffmpeg_path, "-y",
        "-f", "concat",
        "-safe", "0",
        "-i", concat_list_path,
        "-c", "copy",
        out_mp4
    ]
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        stderr = (p.stderr or b"").decode("utf-8", errors="replace")
        print(stderr[-2000:])
        return False
    return True

def make_output_dir_by_event_time(base_dir: str, event_utc_dt: datetime) -> str:
    if event_utc_dt.tzinfo is None:
        event_utc_dt = event_utc_dt.replace(tzinfo=timezone.utc)
    else:
        event_utc_dt = event_utc_dt.astimezone(timezone.utc)

    display_name = event_utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    safe_name = display_name.replace(":", "-")

    out_dir = os.path.join(base_dir, safe_name)
    os.makedirs(out_dir, exist_ok=True)

    print(f"[FolderName] {display_name}")
    return out_dir

def extract_device_id_from_set_cookie(resp):
    set_cookie = resp.headers.get("Set-Cookie", "")
    if not set_cookie:
        return None

    cookie = SimpleCookie()
    cookie.load(set_cookie)

    if "deviceId" in cookie:
        return cookie["deviceId"].value
    return None

# ================= Step-by-Step Requests =================
def first_request(cookies):
    #print("\n=== [Step 1] serviceLogin ===")

    r = requests.get(URL1, headers=HEADERS_BASE, cookies=cookies, timeout=15)
    log_http_exchange(
        tag="LOGIN_STEP1",
        method="GET",
        url=URL1,
        headers=HEADERS_BASE,
        cookies=cookies,
        resp=r
    )

    body = r.text or ""
    if body.startswith("&&&START&&&"):
        body = body[len("&&&START&&&"):]

    data = json.loads(body)
    cookies.update(r.cookies.get_dict())
    return data, cookies


def _extract_login_error(data: dict) -> str:
    """
    Extract a human-readable error message from a Xiaomi login response JSON.

    Xiaomi login responses are not consistent across failure cases,
    so this function attempts multiple commonly used fields to infer
    the most meaningful error message for the user.
    """
    if not isinstance(data, dict):
        return "Unknown response (not a dict)"

    for k in ["description", "desc", "message", "msg", "notificationUrl"]:
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            # notificationUrl indicates a 2FA trigger, not an error message itself
            if k == "notificationUrl":
                continue
            return v.strip()

    # Fallback to numeric or symbolic error indicators
    for k in ["code", "resultCode", "errorCode", "errno"]:
        if k in data:
            return f"{k}={data.get(k)}"

    try:
        return json.dumps(data, ensure_ascii=False)[:400]
    except Exception:
        return str(data)[:400]


def second_request(first_data, cookies, user_id, password, max_attempts: int = 5, sleep_sec: float = 1.0):
    #print("\n=== [Step 2] serviceLoginAuth2 ===")

    payload = {
        "_json": "true",
        "_locale": "en_US",
        "user": user_id,
        "hash": hashlib.md5(password.encode()).hexdigest().upper(),
        "qs": first_data.get("qs", ""),
        "callback": first_data.get("callback", ""),
        "_sign": first_data.get("_sign", ""),
        "sid": first_data.get("sid", ""),
    }

    last_err = None

    for attempt in range(1, max_attempts + 1):
        note = f"attempt {attempt}/{max_attempts}"

        try:
            r2 = requests.post(URL2, headers=HEADERS_BASE, cookies=cookies, data=payload, timeout=15)
        except requests.exceptions.Timeout as e:
            last_err = f"Timeout while calling serviceLoginAuth2 ({note}): {e}"
            print(f"[!] {last_err}")
            log_http_exchange(
                tag="LOGIN_STEP2",
                method="POST",
                url=URL2,
                headers=HEADERS_BASE,
                cookies=cookies,
                data=payload,
                resp=None,
                note=last_err
            )
            time.sleep(sleep_sec)
            continue
        except requests.exceptions.RequestException as e:
            last_err = f"Request error in serviceLoginAuth2 ({note}): {e}"
            print(f"[!] {last_err}")
            log_http_exchange(
                tag="LOGIN_STEP2",
                method="POST",
                url=URL2,
                headers=HEADERS_BASE,
                cookies=cookies,
                data=payload,
                resp=None,
                note=last_err
            )
            time.sleep(sleep_sec)
            continue

        # ✅ Always log the request+response (success or fail)
        log_http_exchange(
            tag="LOGIN_STEP2",
            method="POST",
            url=URL2,
            headers=HEADERS_BASE,
            cookies=cookies,
            data=payload,
            resp=r2,
            note=note
        )

        body = r2.text or ""
        if body.startswith("&&&START&&&"):
            body = body[len("&&&START&&&"):]

        try:
            data = json.loads(body)
        except Exception:
            last_err = f"Non-JSON response from Xiaomi (status={r2.status_code}): {body[:400]}"
            print(f"[!] {last_err}")
            dlog("[LOGIN_STEP2][NON_JSON_BODY]", body[:8000])
            time.sleep(sleep_sec)
            continue

        cookies.update(r2.cookies.get_dict())

        # ✅ success
        location = data.get("location")
        if isinstance(location, str) and location.strip():
            dlog("[LOGIN_STEP2][SUCCESS] location:", location)
            return (
                location,
                cookies,
                data.get("ssecurity"),
                data.get("cUserId") or data.get("userId"),
                None,
            )

        # ✅ 2FA
        if isinstance(data.get("notificationUrl"), str) and data.get("notificationUrl").strip():
            dlog("[LOGIN_STEP2][2FA] notificationUrl:", data.get("notificationUrl"))
            return None, cookies, None, None, "2FA required (notificationUrl returned)"

        # ❌ fail
        err = _extract_login_error(data)
        last_err = f"Login step2 failed ({note}): {err}"
        print(f"[!] {last_err}")
        dlog("[LOGIN_STEP2][FAIL_JSON]", json.dumps(data, ensure_ascii=False)[:8000])

        time.sleep(sleep_sec)

    return None, cookies, None, None, (last_err or "Login step2 failed (unknown)")


def third_request(location_url, cookies):
    #print("\n=== [Step 3] location URL Request ===")

    req_cookies = {"deviceId": cookies.get("deviceId", "")}
    r3 = requests.get(location_url, headers=HEADERS_BASE, cookies=req_cookies, allow_redirects=True, timeout=15)

    log_http_exchange(
        tag="LOGIN_STEP3",
        method="GET",
        url=location_url,
        headers=HEADERS_BASE,
        cookies=req_cookies,
        resp=r3
    )

    service_token = None
    set_cookie_header = r3.headers.get("Set-Cookie")
    if set_cookie_header:
        cookie_obj = SimpleCookie()
        cookie_obj.load(set_cookie_header)
        for name, morsel in cookie_obj.items():
            if name.lower() == "servicetoken":
                service_token = morsel.value
    return service_token


# ================= Service API Caller =================
def call_service_api(method, url, url_key, params, signed_nonce, nonce, ssecurity, cUserId, serviceToken, device_id):
    enc_params = generate_enc_params(url_key, method, signed_nonce, nonce, params, ssecurity)

    headers_api = {
        "accept-encoding": "identity",
        "miot-accept-encoding": "GZIP",
        "miot-encrypt-algorithm": "ENCRYPT-RC4",
        "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
    }
    if method.upper() == "POST":
        headers_api["content-type"] = "application/x-www-form-urlencoded"

    cookies_str = (
        f"cUserId={cUserId}; serviceToken={serviceToken}; yetAnotherServiceToken={serviceToken}; "
        f"PassportDeviceId={device_id}; locale=en_US"
    )
    headers_api["Cookie"] = cookies_str

    print(f"\n[API Request] {url_key}")

    # Debug log
    try:
        dlog("")
        dlog("====== [XIAOMI][API REQ] =============================")
        dlog("method:", method, "url_key:", url_key)
        dlog("url:", url)
        dlog("cUserId:", cUserId)
        dlog("device_id:", device_id)
        dlog("nonce:", nonce)
        dlog("signed_nonce:", signed_nonce)
        dlog("ssecurity:", ssecurity)
        dlog("serviceToken:", serviceToken)
        dlog("Cookie(header):", cookies_str)

        # params
        try:
            pj = json.dumps(params, ensure_ascii=False)
        except Exception:
            pj = str(params)
        dlog("params:", pj if len(pj) <= 2000 else pj[:2000] + f"... <truncated {len(pj)-2000} chars>")

        # enc_params
        try:
            epj = json.dumps(enc_params, ensure_ascii=False)
        except Exception:
            epj = str(enc_params)
        dlog("enc_params:", epj if len(epj) <= 2000 else epj[:2000] + f"... <truncated {len(epj)-2000} chars>")

    except Exception:
        pass

    # Send request
    resp = (
        requests.post(url, headers=headers_api, data=enc_params, timeout=20)
        if method.upper() == "POST"
        else requests.get(url, headers=headers_api, params=enc_params, timeout=20)
    )
    print(f"Status: {resp.status_code}")

    # Response Log
    try:
        dlog("------ [XIAOMI][API RESP] ---------------------------")
        dlog("status_code:", resp.status_code)
        dlog("headers:", dict(resp.headers))
        txt = resp.text if isinstance(resp.text, str) else ""
        dlog("resp.text (head):", txt[:4000] + ("... <truncated>" if len(txt) > 4000 else ""))
    except Exception:
        pass

    # /common/app/m3u8 is NOT encrypted → return as-is
    if url_key == "/common/app/m3u8":
        print("[!] Non-encrypted API: handling as plain response.")
        return resp.text

    # Decryption Logic
    try:
        decrypted = decrypt_rc4(signed_nonce, resp.text)
        if isinstance(decrypted, bytes) and decrypted.startswith(b"\x1f\x8b"):
            decrypted = gzip.decompress(decrypted)

        # Logging
        try:
            dlog("[XIAOMI][DECRYPT] success. type:", type(decrypted), "len:", len(decrypted) if isinstance(decrypted, (bytes, bytearray)) else "-")
            if isinstance(decrypted, (bytes, bytearray)):
                try:
                    dlog("decrypted(head utf8):", decrypted[:4000].decode("utf-8", errors="replace"))
                except Exception:
                    dlog("decrypted(head hex):", decrypted[:2000].hex())
        except Exception:
            pass

        return decrypted

    except Exception as e:
        print(f"[Decryption failed] {e}")
        print(resp.text)
        try:
            dlog("[XIAOMI][DECRYPT][ERROR]", str(e))
        except Exception:
            pass
        return None



# ================= Main =================
# =========================================================
# Xiaomi Step Functions + Runner
# =========================================================

def step_login_interactive(max_relogin: int = 3):
    """
    Steps 1–3: Perform the login flow, then return ctx.
    If login fails, show error and re-prompt up to max_relogin.
    """
    for relogin_round in range(1, max_relogin + 1):
        print("\n=== Xiaomi API Interactive Login ===")
        if relogin_round > 1:
            print(f"[INFO] Re-login attempt {relogin_round}/{max_relogin}")

        user_id = input("Enter user ID: ").strip()
        password = input("Enter user password: ").strip()
        if not user_id or not password:
            print("[!] Both ID and Password are required.")
            continue

        print("Please ready for device_uuid, refer to /shared_prefs/deviceId.xml(android), /Library/Preferences/com.xiaomi.mihome.plist(iOS)")

        device_uuid = input("Enter device_uuid (press Enter to auto-generate for Android): ").strip()
        device_type = input("Android(1) or iOS(2): ").strip()

        if not device_uuid or device_type not in ("1", "2"):
            device_uuid = str(uuid.uuid4())
            print(f"[+] Generated device_uuid: {device_uuid}")
            device_id = f"android_{device_uuid}"
        else:
            if device_type == "1":
                device_id = f"android_{device_uuid}"
            else:
                device_id = device_uuid

        print(f"final device id: {device_id}")

        cookies = {"userId": user_id, "deviceId": device_id}

        # Step 1
        try:
            first_data, cookies = first_request(cookies)
        except requests.exceptions.RequestException as e:
            print(f"[!] Step1 request failed: {e}")
            continue
        except Exception as e:
            print(f"[!] Step1 parsing failed: {e}")
            continue

        # Step 2
        location, cookies, ssecurity, cUserId, err_msg = second_request(first_data, cookies, user_id, password)

        service_token = None

        if location:
            # Step 3
            try:
                service_token = third_request(location, cookies)
            except requests.exceptions.RequestException as e:
                print(f"[!] Step3 request failed: {e}")
                continue
            except Exception as e:
                print(f"[!] Step3 parsing failed: {e}")
                continue
        else:
            # 2FA or failure
            if err_msg and "2FA required" in err_msg:
                print("[!] Login flow did not return a location URL. Need 2FA")
                try:
                    ssecurity, userId, cUserId, service_token, cookies = run_xiaomi_2fa(device_id, user_id, password)
                except Exception as e:
                    print(f"[!] 2FA flow failed: {e}")
                    continue
            else:
                print(f"[!] Login failed in Step2: {err_msg or '(no error message)'}")
                continue

        if not (ssecurity and service_token and cUserId):
            print("[!] Login failed: missing tokens (ssecurity/service_token/cUserId).")
            continue

        nonce = generate_nonce()
        signed_nonce = signed_nonce_sec(nonce, ssecurity)
        region = input("Region (default=US): ").strip().upper() or "US"

        ctx = {
            "user_id": user_id,
            "device_id": device_id,
            "cookies": cookies,
            "ssecurity": ssecurity,
            "cUserId": cUserId,
            "service_token": service_token.value if hasattr(service_token, "value") else str(service_token),
            "nonce": nonce,
            "signed_nonce": signed_nonce,
            "region": region,
            "selected_device": None,
        }
        return ctx

    print("[!] Login aborted: exceeded max re-login attempts.")
    return None


def step_home_profiles(ctx):
    #print("\n===== [Step 1/7] home/profiles =====")
    params = {"data": json.dumps({"uids": [ctx["cUserId"]]})}
    _ = call_service_api(
        "POST",
        "https://sg.api.io.mi.com/app/home/profiles",
        "/home/profiles",
        params,
        ctx["signed_nonce"],
        ctx["nonce"],
        ctx["ssecurity"],
        ctx["cUserId"],
        ctx["service_token"],
        ctx["device_id"],
    )

def step_device_list_page(ctx):
    """
    Fetch the device list only and do not print the output.
    Returns: devices (list[dict])
    """
    #print("\n===== [Step 2/7] v2/home/device_list_page =====")
    params = {
        "data": json.dumps({
            "getVirtualModel": True,
            "getHuamiDevices": 1,
            "get_third_device": True
        })
    }

    resp_data = call_service_api(
        "POST",
        "https://sg.core.api.io.mi.com/app/v2/home/device_list_page",
        "/v2/home/device_list_page",
        params,
        ctx["signed_nonce"],
        ctx["nonce"],
        ctx["ssecurity"],
        ctx["cUserId"],
        ctx["service_token"],
        ctx["device_id"],
    )

    if not resp_data:
        print("[!] device_list_page failed.")
        return []

    try:
        data = json.loads(resp_data.decode(errors="ignore"))
        devices = data.get("result", {}).get("list", []) or []
        return devices
    except Exception as e:
        print(f"[!] Failed to parse device list: {e}")
        return []


def select_device_by_index(devices, ctx):
    """
    Only numeric selection is allowed.
    Save the selected device dict to ctx["selected_device"] and return (did, model).
    """
    if not devices:
        print("[!] No devices.")
        return None, None

    print("\n=== [Select Device] ===")
    for i, d in enumerate(devices, 1):
        name = d.get("name", "-")
        did = d.get("did", "-")
        model = d.get("model", "-")
        ip = d.get("localip", "-")
        print(f"[{i}] {name} | DID={did} | model={model} | ip={ip}")

    sel = input(f"Select device index (1~{len(devices)}): ").strip()
    if not sel.isdigit():
        print("[!] Invalid index.")
        return None, None

    idx = int(sel)
    if not (1 <= idx <= len(devices)):
        print("[!] Out of range.")
        return None, None

    dev = devices[idx - 1]
    ctx["selected_device"] = dev

    did = str(dev.get("did") or "")
    model = dev.get("model")

    print("\n[SELECTED]")
    print(f" - index : {idx}")
    print(f" - DID   : {did}")
    print(f" - model : {model}")

    return did, model

def print_selected_device_summary(ctx):
    """
    Pretty-print the selected device information from device_list_page.
    """
    dev = ctx.get("selected_device") or {}
    print("\n=== [Device Info Summary] ===")
    print(f"Name     : {dev.get('name', '-')}")
    print(f"DID      : {dev.get('did', '-')}")
    print(f"Model    : {dev.get('model', '-')}")
    print(f"IP       : {dev.get('localip', '-')}")
    print(f"MAC      : {dev.get('mac', '-')}")
    print(f"SSID     : {dev.get('ssid', '-')}")
    print(f"BSSID    : {dev.get('bssid', '-')}")
    print(f"RSSI     : {dev.get('rssi', '-')}")
    print(f"UID      : {dev.get('uid', '-')}")
    print(f"Token    : {dev.get('token', '-')}")
    print(f"Location : {dev.get('longitude', '-')}, {dev.get('latitude', '-')}")

def step_device_info_summary(ctx, did):
    """
    Print detailed information for the selected device (ctx['selected_device']) from device_list_page
    (in the old Device List Summary style).
    """
    dev = ctx.get("selected_device") or {}
    if not dev:
        print("[!] selected_device not found in ctx.")
        return

    # In case of a DID mismatch
    if str(dev.get("did")) != str(did):
        print("[!] Warning: selected_device DID != current DID")

    name = dev.get("name", "-")
    did_val = dev.get("did", "-")
    uid = dev.get("uid", "-")
    token = dev.get("token", "-")
    model = dev.get("model", "-")
    ip = dev.get("localip", "-")
    mac = dev.get("mac", "-")
    ssid = dev.get("ssid", "-")
    bssid = dev.get("bssid") or "(none)"
    rssi = dev.get("rssi", "-")
    longitude = dev.get("longitude", "0.00000000")
    latitude = dev.get("latitude", "0.00000000")

    # last_online from device_list_page (may be missing)
    last_online = dev.get("last_online")
    if last_online:
        last_online_utc = datetime.fromtimestamp(last_online, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    else:
        last_online_utc = "(none)"

    print("\n=== [Device Info Summary] ===")
    print(f"\n[Device] {name}")
    print(f"  • DID: {did_val}")
    print(f"  • UID: {uid}")
    print(f"  • TOKEN: {token}")
    print(f"  • MODEL: {model}")
    print(f"  • IP: {ip}")
    print(f"  • MAC: {mac}")
    print(f"  • SSID: {ssid}")
    print(f"  • BSSID: {bssid}")
    print(f"  • RSSI: {rssi}")
    print(f"  • LOCATION: {longitude}, {latitude}")
    print(f"  • LAST ONLINE (UTC): {last_online_utc}")



def step_vip_status(ctx, did):
    print("\n===== [VIP] vip/status =====")
    params = {"data": json.dumps({"did": did, "region": ctx.get("region", "US")})}
    vip_resp = call_service_api(
        "GET",
        "https://sg.app.business.smartcamera.api.io.mi.com/miot/camera/app/v1/vip/status",
        "/miot/camera/app/v1/vip/status",
        params,
        ctx["signed_nonce"],
        ctx["nonce"],
        ctx["ssecurity"],
        ctx["cUserId"],
        ctx["service_token"],
        ctx["device_id"],
    )

    if not vip_resp:
        print("[!] vip/status failed.")
        return None

    try:
        decoded = vip_resp.decode(errors="ignore")
        data = json.loads(decoded)
        vip_info = data.get("data", {})

        print("\n=== [VIP Status Info] ===")
        print(f"VIP Status: {vip_info.get('vipStatusEnum')}")
        print(f"VIP Version: {vip_info.get('vipVersion')}")
        print(f"Package Type: {vip_info.get('pacakgeType')}")
        print(f"VIP Active: {vip_info.get('vip')}")
        print(f"Auto Renewal: {vip_info.get('renewStatus')}")
        print(f"Renewable (isRenew): {vip_info.get('isRenew')}")
        print(f"VIP Bind Status: {vip_info.get('vipBindStatus')}")
        print(f"Rolling Save Interval (ms): {vip_info.get('rollingSaveInterval')}")
        print(f"Status Code: {vip_info.get('status')}")

        for label, key in [
            ("Free Home Surveillance Expire", "freeHomeSurExpireTime"),
            ("Start Time", "startTime"),
            ("End Time", "endTime"),
        ]:
            ts = vip_info.get(key)
            if ts:
                utc_time = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
                print(f"{label}: {utc_time}")
            else:
                print(f"{label}: (none)")

        print(f"\nServer response code: {data.get('code')} / message: {data.get('description')}")
        return vip_info
    except Exception as e:
        print(f"[!] Failed to parse VIP status: {e}")
        return None


def step_get_last_online(ctx, did):
    #print("\n===== [Step 4/7] get_last_online =====")
    params = {"data": json.dumps({"dids": [did]})}

    resp_last_online = call_service_api(
        method="POST",
        url="https://sg.api.io.mi.com/app/appgateway/miot/appdeviceinfo_service/AppDeviceInfoService/get_last_online",
        url_key="/appgateway/miot/appdeviceinfo_service/AppDeviceInfoService/get_last_online",
        params=params,
        signed_nonce=ctx["signed_nonce"],
        nonce=ctx["nonce"],
        ssecurity=ctx["ssecurity"],
        cUserId=ctx["cUserId"],
        serviceToken=ctx["service_token"],
        device_id=ctx["device_id"]
    )

    if not resp_last_online:
        print("[!] get_last_online failed.")
        return None

    try:
        obj = json.loads(resp_last_online.decode(errors="ignore"))
        info_list = obj.get("result", {}).get("info", [])
        if not info_list:
            print("[!] 'result.info' is empty.")
            return obj

        last_utc = None

        print("\n=== [Device Last Online Time] ===")
        for it in info_list:
            did_val = it.get("did")
            ts_raw = it.get("last_online")  # string
            if not ts_raw:
                continue
            try:
                ts = int(ts_raw)
            except ValueError:
                ts = int(float(ts_raw))
            if ts > 10**12:
                ts //= 1000
            last_utc = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")

            print(f"DID: {did_val}")
            print(f"LAST ONLINE (UTC): {last_utc}")
        return last_utc


    except Exception as e:
        print(f"[!] Failed to parse result: {e}\nOriginal (partial): {resp_last_online[:200]} ...")
        return None


def step_message_typelist(ctx):
    #print("\n===== [Step 5/7] message typelist =====")

    ts = int(time.time() * 1000)
    params = {
        "data": json.dumps({
            "timestamp": ts,
            "limit": 200
        })
    }

    resp_msg = call_service_api(
        method="POST",
        url="https://sg.api.io.mi.com/app/v2/message/v2/typelist",
        url_key="/v2/message/v2/typelist",
        params=params,
        signed_nonce=ctx["signed_nonce"],
        nonce=ctx["nonce"],
        ssecurity=ctx["ssecurity"],
        cUserId=ctx["cUserId"],
        serviceToken=ctx["service_token"],
        device_id=ctx["device_id"]
    )

    if not resp_msg:
        print("[!] No server response.")
        return None

    try:
        if isinstance(resp_msg, bytes) and resp_msg.startswith(b"\x1f\x8b"):
            resp_msg = gzip.decompress(resp_msg)
        decoded = resp_msg.decode(errors="ignore")
        data = json.loads(decoded)
    except Exception as e:
        print(f"[!] Response decoding failed: {e}")
        return None

    result = data.get("result", {})
    messages = result.get("messages", [])
    if not messages:
        print("[ℹ️] No messages.")
        return data

    print(f"\n=== [Message List] Total {len(messages)} ===")
    for idx, msg in enumerate(messages, 1):
        msg_id = msg.get("msg_id")
        uid = msg.get("uid")
        did = msg.get("did")
        title = msg.get("title")
        content = msg.get("content")

        file_id = None
        try:
            params_obj = msg.get("params", {})
            body = params_obj.get("body", {})
            extra = body.get("extra", {})
            if isinstance(extra, dict):
                file_id = extra.get("fileId")
            else:
                extra_json = json.loads(body.get("extraInfo", "{}"))
                file_id = extra_json.get("fileId")
        except Exception:
            pass

        home_extra = msg.get("params", {}).get("body", {}).get("homeRoomExtra", {})
        home_name = home_extra.get("homeName")
        room_name = home_extra.get("roomName")

        ts_raw = msg.get("time")
        utc_time = "(none)"
        if ts_raw:
            try:
                ts_int = int(ts_raw)
                utc_time = datetime.fromtimestamp(ts_int, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
            except Exception:
                pass

        print(f"""
[{idx}] Message
  • msg_id: {msg_id}
  • uid: {uid}
  • did: {did}
  • title: {title}
  • content: {content}
  • fileId: {file_id or '(none)'}
  • homeName: {home_name or '(none)'}
  • roomName: {room_name or '(none)'}
  • time (UTC): {utc_time}
""")

    return data


def step_eventlist_30days(ctx, did, model):
    #print("\n===== [Step 6/7] eventlist (last 30 days) =====")

    if not model:
        model = input("Enter model for eventlist (press Enter to skip eventlist): ").strip()
        if not model:
            print("[INFO] model not provided → skipping eventlist.")
            return None

    now_utc = datetime.now(timezone.utc)
    end_time = int(now_utc.timestamp() * 1000)

    thirty_days_ago_midnight = datetime.combine(
        (now_utc - timedelta(days=30)).date(),
        datetime.min.time(),
        tzinfo=timezone.utc
    )
    begin_time = int(thirty_days_ago_midnight.timestamp() * 1000)

    print(f"[Time Settings] beginTime={begin_time} ({thirty_days_ago_midnight}), endTime={end_time} ({now_utc})")

    page = 1
    total_events = []

    while True:
        print(f"\n--- [Event Page {page}] ---")

        params = {
            "data": json.dumps({
                "model": model,
                "eventType": "Default",
                "limit": 20,
                "beginTime": begin_time,
                "endTime": end_time,
                "sortType": "DESC",
                "needMerge": True,
                "doorBell": False,
                "region": ctx.get("region", "US"),
                "did": did
            })
        }

        resp_eventlist = call_service_api(
            method="GET",
            url="https://sg.app.business.smartcamera.api.io.mi.com/common/app/get/eventlist",
            url_key="/common/app/get/eventlist",
            params=params,
            signed_nonce=ctx["signed_nonce"],
            nonce=ctx["nonce"],
            ssecurity=ctx["ssecurity"],
            cUserId=ctx["cUserId"],
            serviceToken=ctx["service_token"],
            device_id=ctx["device_id"]
        )

        if not resp_eventlist:
            print("[!] No response. Stopping.")
            break

        try:
            decoded = resp_eventlist.decode(errors="ignore")
            data = json.loads(decoded)
            payload = data.get("data", {})
            events = payload.get("thirdPartPlayUnits", []) or []
            total_events.extend(events)

            print(f"=== [Event Summary: Page {page}] ===")
            print(f"Number of events: {len(events)}")

            for idx, e in enumerate(events[:5]):
                create_ts = e.get("createTime", 0)
                expire_ts = e.get("expireTime", 0)
                file_id = e.get("fileId")
                video_id = (e.get("videoStoreId", "") or "")[:50]
                img_id = (e.get("imgStoreId", "") or "")[:50]

                extra_info = e.get("extraInfo", "")
                try:
                    extra_json = json.loads(extra_info)
                    event_type = extra_json.get("eventType", "Unknown")
                except Exception:
                    event_type = "Unknown"

                create_utc = datetime.fromtimestamp(create_ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                expire_utc = datetime.fromtimestamp(expire_ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

                print(f"[{idx+1}] {create_utc} → {expire_utc} | {event_type} | fileId={file_id} | video={video_id}... | img={img_id}...")

            next_time = payload.get("nextTime", 0)
            is_continue = payload.get("isContinue", False)
            print(f"\n[Paging State] nextTime={next_time}, isContinue={is_continue}")

            if next_time == 0 or not is_continue:
                print("\n[Paging End] nextTime=0 or isContinue=False → last page.")
                break

            end_time = next_time
            page += 1
            time.sleep(1.2)

        except Exception as e:
            print(f"[!] Failed to parse event list: {e}")
            break

    if total_events:
        base_dir = ctx.get("download_root") or "xiaomi_download"
        os.makedirs(base_dir, exist_ok=True)

        fname = os.path.join(base_dir, f"eventlist_{did}_{int(time.time())}.json")
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(total_events, f, indent=2, ensure_ascii=False)

        print(f"\n📁 Saved all events ({len(total_events)}): {fname}")

    # ✅ Cache the latest event list (for selecting an item by number in m3u8)
    ctx["last_events"] = total_events
    ctx["last_events_meta"] = {"did": did, "model": model, "region": ctx.get("region", "US")}

    return total_events



def step_m3u8_and_ts(ctx, did, model):
    #print("\n===== [Step 7/7] m3u8 + TS segments =====")

    if not model:
        model = input("Enter model for m3u8 (press Enter to skip m3u8): ").strip()
        if not model:
            print("[INFO] model not provided → skipping m3u8.")
            return

    # ✅ Select an event by number
    cached = ctx.get("last_events") or []
    file_id = None

    # If there is no cache, automatically run eventlist once to populate it
    if not cached:
        print("[INFO] No cached event list found. Fetching eventlist first...")
        cached = step_eventlist_30days(ctx, did, model) or []
        cached = ctx.get("last_events") or cached

    # If still empty, fall back to manual input
    if not cached:
        file_id = input("\n▶ Enter fileId of the event to play (no events cached): ").strip()
        if not file_id:
            print("[!] fileId not provided. Stopping.")
            return
    else:
        max_show = len(cached)  # ✅ Show all events
        print("\n=== [Select Event for m3u8] ===")
        for i, e in enumerate(cached, 1):
            create_ts = e.get("createTime", 0)
            extra_info = e.get("extraInfo", "")
            try:
                event_type = json.loads(extra_info).get("eventType", "Unknown")
            except Exception:
                event_type = "Unknown"

            create_utc = datetime.fromtimestamp(create_ts / 1000, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC") if create_ts else "(none)"
            fid = e.get("fileId", "-")
            print(f"[{i:02d}] {create_utc} | {event_type:<12} | fileId={fid}")

        sel = input(f"Select event index (1..{max_show}) or 'r' to refresh eventlist: ").strip().lower()

        if sel == "r":
            _ = step_eventlist_30days(ctx, did, model)
            cached = ctx.get("last_events") or []
            if not cached:
                print("[!] No events after refresh.")
                return
            max_show = len(cached) # ✅ Show all
            print("\n=== [Select Event for m3u8] ===")
            for i, e in enumerate(cached, 1):
                create_ts = e.get("createTime", 0)
                extra_info = e.get("extraInfo", "")
                try:
                    event_type = json.loads(extra_info).get("eventType", "Unknown")
                except Exception:
                    event_type = "Unknown"

                create_utc = datetime.fromtimestamp(create_ts / 1000, tz=timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC") if create_ts else "(none)"
                fid = e.get("fileId", "-")
                print(f"[{i:02d}] {create_utc} | {event_type:<12} | fileId={fid}")

            sel = input(f"Select event index (1..{max_show}): ").strip()

        if not sel.isdigit():
            print("[!] Invalid selection.")
            return

        idx = int(sel)
        if not (1 <= idx <= max_show):
            print("[!] Out of range.")
            return

        file_id = str(cached[idx - 1].get("fileId") or "").strip()
        if not file_id:
            print("[!] Selected event has no fileId.")
            return

        print(f"\n[SELECTED EVENT] index={idx} fileId={file_id}")

        # ✅ Create the output folder based on the selected event's createTime (UTC)
        event_utc_dt = None

        # If cached + idx are available, we can retrieve createTime
        # (idx is already an int from the event selection step)
        if cached and isinstance(idx, int) and 1 <= idx <= len(cached):
            create_ts = cached[idx - 1].get("createTime", 0)
            if create_ts:
                event_utc_dt = datetime.fromtimestamp(create_ts / 1000, tz=timezone.utc)

        # Fallback: if cache is missing or createTime is not available, use current UTC time
        if event_utc_dt is None:
            event_utc_dt = datetime.now(timezone.utc)

    # ✅ After file_id is finalized: create out_dir only once based on the selected event's createTime (UTC)
    event_utc_dt = None

    # If the selected event comes from cache, use its createTime
    if cached and isinstance(idx, int) and 1 <= idx <= len(cached):
        create_ts = cached[idx - 1].get("createTime", 0)
        if create_ts:
            event_utc_dt = datetime.fromtimestamp(create_ts / 1000, tz=timezone.utc)

    # Fallback: if fileId was entered manually (no cached event), use current UTC time
    if event_utc_dt is None:
        event_utc_dt = datetime.now(timezone.utc)

    base_dir = ctx.get("download_root") or "xiaomi_download"
    os.makedirs(base_dir, exist_ok=True)

    out_dir = make_output_dir_by_event_time(base_dir, event_utc_dt)

    print(f"\n📁 Output folder: {os.path.abspath(out_dir)}")

    params = {
        "data": json.dumps({
            "did": did,
            "fileId": file_id,
            "model": model,
            "isAlarm": False,
            "videoCodec": "H265"
        })
    }

    print("[*] Requesting m3u8 file from the server...")

    decrypted = call_service_api(
        method="GET",
        url="https://sg.app.business.smartcamera.api.io.mi.com/common/app/m3u8",
        url_key="/common/app/m3u8",
        params=params,
        signed_nonce=ctx["signed_nonce"],
        nonce=ctx["nonce"],
        ssecurity=ctx["ssecurity"],
        cUserId=ctx["cUserId"],
        serviceToken=ctx["service_token"],
        device_id=ctx["device_id"]
    )

    if not decrypted:
        print("[!] m3u8 request failed")
        return

    if isinstance(decrypted, bytes):
        try:
            decrypted_text = decrypted.decode("utf-8")
        except Exception:
            decrypted_text = decrypted.decode("latin1", errors="ignore")
    else:
        decrypted_text = str(decrypted)

    m3u8_path = os.path.join(out_dir, "video.m3u8")
    with open(m3u8_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(decrypted_text)

    print(f"\n✅ m3u8 file saved: {m3u8_path}")

    # Parse m3u8
    lines = decrypted_text.splitlines()
    key_uri = None
    iv_hex = None
    ts_urls = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith("#EXT-X-KEY:"):
            parts = line.split(",")
            for p in parts:
                if p.startswith("URI="):
                    key_uri = p.split("URI=")[-1].strip().strip('"')
                elif p.startswith("IV="):
                    iv_hex = p.split("IV=")[-1].strip()

            print("\n🔑 AES-128 encryption detected")
            print(f"  • Key URI: {key_uri}")
            print(f"  • IV: {iv_hex}")

            if key_uri:
                try:
                    key_resp = requests.get(key_uri, timeout=10)
                    key_data = key_resp.content
                    key_path = os.path.join(out_dir, "key.bin")
                    with open(key_path, "wb") as f:
                        f.write(key_data)
                    print(f"  ✅ Key downloaded: {key_path} ({len(key_data)} bytes)")
                except Exception as e:
                    print(f"  ⚠️ Key download failed: {e}")

        elif line.startswith("http"):
            ts_urls.append(line)

    if not ts_urls:
        print("⚠️ No segment URLs found.")
        return

    print(f"\n=== [Segment List] total={len(ts_urls)} ===")
    print("✅ Auto mode: downloading ALL segments and merging.")

    # ============================================
    # Download everything + (if possible) decrypt + merge with ffmpeg
    # ============================================
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ffmpeg_path = os.path.join(script_dir, "ffmpeg.exe")
    if not os.path.exists(ffmpeg_path):
        found = shutil.which("ffmpeg")
        if found:
            ffmpeg_path = found
    if not ffmpeg_path or not os.path.exists(ffmpeg_path):
        print("❌ Could not find the ffmpeg executable.")
        return

    # ✅ Prepare key/IV (key.bin is already saved, so just load it)
    key_data = None
    iv_data = None
    if key_uri and iv_hex:
        try:
            with open(os.path.join(out_dir, "key.bin"), "rb") as f:
                key_data = f.read()
            iv_data = binascii.unhexlify(iv_hex[2:] if iv_hex.startswith("0x") else iv_hex)
        except Exception as e:
            print(f"⚠️ Failed to prepare key/IV: {e}")

    # ✅ 1) Download all segments and (if possible) decrypt, then save as mp4
    dec_files = []
    print(f"\n📥 Downloading ALL segments... total={len(ts_urls)}")

    for i, url in enumerate(ts_urls, 1):
        try:
            r = requests.get(url, timeout=30)
            enc_path = os.path.join(out_dir, f"segment_{i:04d}.enc")
            with open(enc_path, "wb") as f:
                f.write(r.content)

            # If decryption is possible, save as decrypted mp4; otherwise keep the encrypted data as-is
            # (merging may fail or produce corrupted output)
            if key_data and iv_data:
                dec = decrypt_aes128_cbc(r.content, key_data, iv_data)
                dec_path = os.path.join(out_dir, f"segment_{i:04d}.mp4")
                with open(dec_path, "wb") as f:
                    f.write(dec)
                dec_files.append(dec_path)
            else:
                dec_files.append(enc_path)

            if i % 20 == 0 or i == len(ts_urls):
                print(f"✅ [{i}/{len(ts_urls)}] saved")

        except Exception as e:
            print(f"⚠️ [{i}] download failed: {e}")
            return

    if not dec_files:
        print("❌ No segments downloaded.")
        return

    # ✅ 2) concat list
    concat_path = os.path.join(out_dir, "concat.txt")
    with open(concat_path, "w", encoding="utf-8") as f:
        for pth in dec_files:
            abs_path = os.path.abspath(pth).replace("\\", "/")
            f.write(f"file '{abs_path}'\n")

    out_mp4 = os.path.join(out_dir, "merged.mp4")

    print("\n🧩 Merging via ffmpeg (concat demuxer)...")
    print(f"  • ffmpeg: {ffmpeg_path}")
    print(f"  • list  : {concat_path}")
    print(f"  • output: {out_mp4}")

    ok = run_ffmpeg_merge(ffmpeg_path, concat_path, out_mp4)
    if not ok:
        print("❌ ffmpeg merge failed.")
        return

    print(f"✅ Merge complete! Output: {os.path.abspath(out_mp4)}")
    return


# ----- Function Menu -----
def device_action_menu(ctx, did, model):
    """
    Selected-device feature menu.
    """
    while True:
        print("\n=== Xiaomi Device Menu ===")
        print("1) Get device info (device summary + last_online)")
        print("2) Get cloud info (VIP status)")
        print("3) Get messages (message typelist)")
        print("4) Get events (eventlist 30 days)")
        print("5) Download m3u8 + TS")
        print("b) Select a different device")
        print("q) Quit")

        sel = input("Select menu: ").strip().lower()

        if sel == "1":
            step_device_info_summary(ctx, did)  # Based on device_list_page (includes token/ssid, etc.)
            last_utc = step_get_last_online(ctx, did)  # Latest last_online fetched from the server
            if last_utc:
                print(f"  • LAST ONLINE (API, UTC): {last_utc}")


        elif sel == "2":
            step_vip_status(ctx, did)

        elif sel == "3":
            step_message_typelist(ctx)

        elif sel == "4":
            step_eventlist_30days(ctx, did, model)

        elif sel == "5":
            step_m3u8_and_ts(ctx, did, model)

        elif sel == "b":
            return "BACK"

        elif sel == "q" or sel == "":
            return "QUIT"

        else:
            print("[INFO] Invalid input.")


def run_xiaomi(case_info):
    """
    CaseInfo based
    """
    log_f = None
    old_stdout = old_stderr = None
    log_path = None

    # ✅ Case
    log_dir = os.path.join(case_info.case_root, "xiaomi_log")
    download_dir = os.path.join(case_info.case_root, "xiaomi_download")

    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(download_dir, exist_ok=True)

    try:
        # ✅ Create xiaomi_log/<timestamp>.log for each run and apply tee logging
        log_f, log_path, _lock, old_stdout, old_stderr = setup_xiaomi_logging(log_dir)

        ctx = step_login_interactive()
        if not ctx:
            return

        ctx["download_root"] = download_dir

        step_home_profiles(ctx)

        while True:
            devices = step_device_list_page(ctx)
            if not devices:
                print("[!] Device list is empty.")
                return

            did, model = select_device_by_index(devices, ctx)
            if not did:
                print("[!] Failed to select a device. Please try again.")
                continue

            r = device_action_menu(ctx, did, model)
            if r == "BACK":
                continue
            if r == "QUIT":
                print("[INFO] Exiting.")
                return

    except Exception:
        import traceback
        traceback.print_exc()
        if log_path:
            print(f"[!] An exception occurred. Please check the log file for details: {log_path}")
        else:
            print("[!] An exception occurred.")
    finally:
        if log_f and old_stdout and old_stderr:
            teardown_xiaomi_logging(log_f, old_stdout, old_stderr)



if __name__ == "__main__":
    run_xiaomi()
