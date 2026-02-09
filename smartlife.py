#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, json, time, uuid, hmac, base64, hashlib, argparse, requests, struct, binascii, threading, traceback
from typing import Any, Tuple, List, Union, Dict, Optional
from urllib.parse import urlsplit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo


# ===== S3 (optional) =====
try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except Exception:
    HAS_BOTO3 = False

# ===== Logging (smartlife_log) =====
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
        self._buf = ""  # Line buffer for timestamped file logging

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


def open_run_log_file(log_dir="smartlife_log"):
    # KST(UTC+9)
    os.makedirs(log_dir, exist_ok=True)
    tz_kst = timezone(timedelta(hours=9))
    ts = datetime.now(tz_kst).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(log_dir, f"{ts}.log")
    f = open(path, "a", encoding="utf-8", buffering=1)
    return f, path


def setup_smartlife_logging(log_dir="smartlife_log"):
    """
    Apply tee logging to stdout/stderr (console + file).
    Returns: (log_f, log_path, lock, old_stdout, old_stderr)
    """
    log_f, log_path = open_run_log_file(log_dir)
    log_lock = threading.Lock()

    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = TeeStdIO(sys.__stdout__, log_f, prefix_ts=True, lock=log_lock)
    sys.stderr = TeeStdIO(sys.__stderr__, log_f, prefix_ts=True, lock=log_lock)

    print(f"\n[+] SmartLife log file: {log_path}")
    bind_debug_logger(log_f, log_lock)   # ✅ Added
    return log_f, log_path, log_lock, old_stdout, old_stderr

# ===== Debug-only logger (file only; no console) =====
DEBUG_LOG_F = None
DEBUG_LOG_LOCK = None

def _ts_kst():
    tz_kst = timezone(timedelta(hours=9))
    return datetime.now(tz_kst).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def bind_debug_logger(log_f, log_lock):
    """Bind the log file/lock created in setup_smartlife_logging to the debug logger."""
    global DEBUG_LOG_F, DEBUG_LOG_LOCK
    DEBUG_LOG_F = log_f
    DEBUG_LOG_LOCK = log_lock

def dlog(*args, sep=" ", end="\n"):
    """
    ✅ Debug logging goes to file only (bypasses stdout/stderr tee).
    - Do NOT use print(): print() will also appear in the console.
    """
    global DEBUG_LOG_F, DEBUG_LOG_LOCK
    if not DEBUG_LOG_F:
        return
    msg = sep.join("" if a is None else str(a) for a in args)
    with (DEBUG_LOG_LOCK or threading.Lock()):
        for line in msg.splitlines() or [""]:
            DEBUG_LOG_F.write(f"[{_ts_kst()}] {line}{end}")
        DEBUG_LOG_F.flush()


def teardown_smartlife_logging(log_f, old_stdout, old_stderr):
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

# =========================================================
# Constants
# =========================================================
SMARTLIFE_ROOT = None
LOG_DIR = "smartlife_log"
DOWNLOAD_DIR = "smartlife_download"

API_URL = "https://a1-us.lifeaiot.com/api.json"
APP_VERSION = "6.9.0"; SDK_VERSION="6.9.0"; DEVICE_CORE_VERSION="6.9.0"; APP_RN_VERSION="5.97"
CHANNEL="oem"; DEVICE_ID="54df4439ca9318fed6ebeb9f7aae08c676b2122562cd"; CHKEY="ec9709a4"
OS_SYSTEM="11"; TTID="sdk_international@ekmnwp9f5pnh3trdtpgy"; ET="3"; ND="1"; PLATFORM="Pixel 2 XL"
CLIENT_ID="ekmnwp9f5pnh3trdtpgy"; OS_NAME="Android"; TIMEZONE_ID="Asia/Seoul"; LANG="en_US"
UA="Thing-UA=APP/Android/6.9.0/SDK/6.9.0"; CP="gzip"

# API versions
V_TOKEN="2.0"; V_LOGIN="3.0"; V_GROUP_SORT="2.1"; V_GROUP_LIST="2.2"
V_MSG_LIST="5.2"; V_MSG_LIST_FALLBACK="4.0"
V_HOME_LIST="1.0"; V_RTC_CONFIG="1.0"; V_IPC_SECRET="1.0"; V_USER_SERVED="1.0"
V_TIMELINE="2.0"; V_PREFIXS="1.0"; V_READ_AUTH="3.0"
V_DAY_COUNT="1.0"   # tuya.m.ipc.storage.info.day.count

# local files
ENCRYPT_KEYS_PATH="ipc_encrypt_keys.json"
TIMELINE_PREFIXES="ipc_timeline_prefixes.json"
MEDIA_FILES_PATH="ipc_media_files.json"
READ_AUTH_PATH="ipc_read_authority.json"

# HMAC key
SIGN_KEY = (
    "com.tuya.smartlife_0F:C3:61:99:9C:C0:C3:5B:A8:AC:A5:7D:AA:55:93:A2:"
    "0C:F5:57:27:70:2E:A8:5A:D7:B3:22:89:49:F8:88:FE_jfg5rs5kkmrj5mxahug"
    "vucrsvw43t48x_r3me7ghmxjevrvnpemwmhw3fxtacphyg"
)
G_CONST = SIGN_KEY

# FixedSecureRandom seed (for login)
SEED_SIGNED=[-86,-3,18,-10,89,-54,-26,52,-119,-76,121,-27,7,109,-34,-62,-16,108,-75,-113]
SEED_BYTES = bytes((b & 0xFF) for b in SEED_SIGNED)
N_DEC_FALLBACK=("132138344467957583121047335344070585673601170540441819201865512450207051928227131403091908356898775090481454730430076854025012241882872133751231833253288410104639079905942048748696583943310435842012801044588596374512031448558327466279030544128522132220377549690286711091978505065350117381355345162123380033693")
E_DEC=65537

# ===== Decrypt const =====
PIC_HEADER_SIZE = 0x40
VID_HEADER_SIZE = 0x18
VID_FIXED_IV_HEX = "00010203040506070f0e0d0c0b0a0908"

# =========================================================
# Utils
# =========================================================
def ensure_download_dir():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    return DOWNLOAD_DIR

def pretty(v: Any)->str:
    if isinstance(v,(dict,list)): return json.dumps(v, ensure_ascii=False, indent=2)
    if isinstance(v,bytes): return v.hex()
    return str(v)

def get_encrypto_key(str1:str,str2:str,G:str)->Tuple[str,List[int]]:
    msg=(G if (not str2 or str2.strip().lower()=="null") else f"{G}_{str2}").encode()
    digest_hex=hmac.new(str1.encode(), msg, hashlib.sha256).hexdigest()
    short16=digest_hex[:16]
    return short16,[ord(c) for c in short16]

def _to_bytes(obj:Union[dict,list,str,bytes])->bytes:
    if isinstance(obj,(dict,list)): return json.dumps(obj, ensure_ascii=False, separators=(",",":")).encode()
    if isinstance(obj,str): return obj.encode()
    if isinstance(obj,bytes): return obj
    raise TypeError(type(obj))

def encrypt_postdata_aesgcm_b64(key16:bytes, post_plain:Union[dict,list,str,bytes])->str:
    if len(key16)!=16: raise ValueError("AES-128 key must be 16 bytes")
    data=_to_bytes(post_plain)
    nonce=os.urandom(12)
    ct=AESGCM(key16).encrypt(nonce,data,None)
    return base64.b64encode(nonce+ct).decode()

def decrypt_aesgcm_b64(key16:bytes,b64:str)->Any:
    raw=base64.b64decode(b64); nonce,ct=raw[:12],raw[12:]
    plain=AESGCM(key16).decrypt(nonce,ct,None)
    try:
        s=plain.decode()
        try: return json.loads(s)
        except json.JSONDecodeError: return s
    except UnicodeDecodeError: return plain

def _swap_md5_2_1_4_3(md5hex:str)->str:
    hx=md5hex.lower(); return f"{hx[8:16]}{hx[0:8]}{hx[24:32]}{hx[16:24]}"

def unwrap_result(obj:Any)->Any:
    if isinstance(obj,dict) and "result" in obj: return obj["result"]
    return obj

def build_sign_message(body:Dict[str,Any], v_value:str, *, include_postdata:bool, post_b64:Optional[str]=None)->str:
    parts=[
        f"a={body['a']}", f"appVersion={body['appVersion']}", f"chKey={body['chKey']}",
        f"clientId={body['clientId']}", f"deviceId={body['deviceId']}", f"et={body['et']}",
        f"lang={body['lang']}", f"os={body['os']}",
    ]
    if include_postdata:
        if not post_b64: raise ValueError("include_postdata=True requires post_b64")
        md5_swapped=_swap_md5_2_1_4_3(hashlib.md5(post_b64.encode()).hexdigest())
        parts.append(f"postData={md5_swapped}")
    parts.append(f"requestId={body['requestId']}")
    if body.get("sid"): parts.append(f"sid={body['sid']}")
    parts.extend([f"time={body['time']}", f"ttid={body['ttid']}", f"v={v_value}"])
    return "||".join(parts)

def hmac_sha256_hex(key_str:str,msg_str:str)->str:
    return hmac.new(key_str.encode(), msg_str.encode(), hashlib.sha256).hexdigest()

def default_biz_data()->Dict[str,Any]:
    return {
        "brand":"google","customDomainSupport":"1",
        "miniappVersion":"{\"AIKit\":\"1.3.3\",\"AIStreamKit\":\"1.1.2\",\"BaseKit\":\"3.24.6\",\"BizKit\":\"4.20.4\",\"CategoryCommonBizKit\":\"6.4.1\",\"DeviceKit\":\"4.21.3\",\"HealthKit\":\"6.6.0\",\"HomeKit\":\"3.10.0\",\"IPCKit\":\"6.8.5\",\"LightKit\":\"1.0.10\",\"MapKit\":\"6.4.6\",\"MediaKit\":\"3.6.2\",\"MediaPlayerKit\":\"1.0.21\",\"MiniKit\":\"3.21.0\",\"P2PKit\":\"6.4.2\",\"PlayNetKit\":\"1.3.31\",\"SweeperKit\":\"2.0.0\",\"ThirdPartyDeviceKit\":\"1.0.0-rc.4\",\"WearKit\":\"1.2.7\",\"basicLib\":\"2.29.10\",\"container\":\"3.32.20\"}",
        "nd":"1","sdkInt":"30",
    }

def build_common_body(a:str, request_id:str, v_value:str, now_ts:Optional[int]=None, *, sid:Optional[str]=None, include_bizdata:bool=True, biz_dm:Optional[str]=None)->Dict[str,Any]:
    if now_ts is None: now_ts=int(time.time())
    body={
        "appVersion":APP_VERSION,"appRnVersion":APP_RN_VERSION,"channel":CHANNEL,
        "deviceId":DEVICE_ID,"chKey":CHKEY,"osSystem":OS_SYSTEM,"ttid":TTID,"et":ET,"nd":ND,
        "sdkVersion":SDK_VERSION,"platform":PLATFORM,"requestId":request_id,"lang":LANG,"a":a,
        "clientId":CLIENT_ID,"os":OS_NAME,"timeZoneId":TIMEZONE_ID,"cp":CP,"v":v_value,
        "deviceCoreVersion":DEVICE_CORE_VERSION,"time":str(now_ts),
    }
    if include_bizdata: body["bizData"]=json.dumps(default_biz_data(), ensure_ascii=False, separators=(",",":"))
    if biz_dm: body["bizDM"]=biz_dm
    if sid: body["sid"]=sid
    return body

def build_headers(request_id:str)->Dict[str,str]:
    return {
        "accept-encoding":"gzip","connection":"keep-alive","content-type":"application/x-www-form-urlencoded",
        "host":"a1-us.lifeaiot.com","user-agent":UA,"x-client-trace-id":request_id,
    }

def fixed_secure_random_bytes(nbytes:int)->bytes:
    out=bytearray()
    while len(out)<nbytes: out.extend(SEED_BYTES)
    return bytes(out[:nbytes])

def rsa_pkcs1_v15_encrypt_fixed(payload:bytes, n:int, e:int=65537)->bytes:
    k=(n.bit_length()+7)//8
    if len(payload)>k-11: raise ValueError("payload too long")
    ps_len=k-3-len(payload)
    ps=fixed_secure_random_bytes(ps_len)
    ps=bytes(b if b!=0 else 1 for b in ps)
    em=b"\x00\x02"+ps+b"\x00"+payload
    m=int.from_bytes(em,"big"); c=pow(m,e,n)
    return c.to_bytes(k,"big")

def encrypt_password_hex_fixed(password:str, public_key_dec:str)->str:
    md5_hex_ascii=hashlib.md5(password.encode("utf-8")).hexdigest().encode("ascii")
    ct=rsa_pkcs1_v15_encrypt_fixed(md5_hex_ascii, int(public_key_dec), 65537)
    return ct.hex()

# =========================================================
# Core API caller (prints postData ASCII in debug)
# =========================================================
def call_api(a:str, post_plain:Optional[Union[dict,list,str,bytes]], *, v_value:str, arg2:str="null",
             sid:Optional[str]=None, include_bizdata:bool=True, use_postdata:bool=True, biz_dm:Optional[str]=None,
             extra_fields:Optional[Dict[str,Any]]=None, debug:bool=False)->Dict[str,Any]:
    req_id=str(uuid.uuid4())
    _,ascii_list=get_encrypto_key(req_id,arg2,G_CONST)
    key16=bytes(ascii_list)

    post_b64=None; plain_bytes=None; plain_ascii=None
    if use_postdata:
        if post_plain is None: post_plain={}
        plain_bytes=_to_bytes(post_plain)
        plain_ascii=plain_bytes.decode("utf-8", errors="backslashreplace")
        post_b64=encrypt_postdata_aesgcm_b64(key16, post_plain)

    body=build_common_body(a=a, request_id=req_id, v_value=v_value, sid=sid, include_bizdata=include_bizdata, biz_dm=biz_dm)
    if extra_fields: body.update(extra_fields)
    sign_msg=build_sign_message(body, v_value, include_postdata=use_postdata, post_b64=post_b64)
    if use_postdata and post_b64 is not None: body["postData"]=post_b64
    body["sign"]=hmac_sha256_hex(SIGN_KEY, sign_msg)
    headers=build_headers(req_id)

    if debug:
        dbg=dict(body)
        if "postData" in dbg: dbg["postData"]=f"<b64 len={len(post_b64 or '')}>"

        dlog("")
        dlog("====== [DEBUG][REQ] ==================================")
        dlog(f"a={a}  v={v_value}  requestId={req_id}  arg2={arg2}  sid?={'yes' if sid else 'no'}")
        dlog("[DEBUG] signMessage:")
        dlog(sign_msg)

        if use_postdata:
            b64_md5=hashlib.md5((post_b64 or '').encode()).hexdigest()
            swapped=_swap_md5_2_1_4_3(b64_md5)
            dlog("[DEBUG] postData plaintext (ASCII):")
            if plain_ascii is None:
                dlog("  (none)")
            else:
                dlog(plain_ascii if len(plain_ascii)<=1024 else plain_ascii[:1024]+f"... <truncated {len(plain_ascii)-1024} chars>")
            dlog(f"[DEBUG] postData plain bytes={len(plain_bytes or b'')} md5={hashlib.md5((plain_bytes or b'')).hexdigest()}")
            dlog(f"[DEBUG] postData b64 md5={b64_md5}  swapped(for sign)={swapped}")

        dlog("[DEBUG] body:")
        dlog(pretty(dbg))


    resp=requests.post(API_URL, headers=headers, data=body, timeout=20)
    out={"status_code":resp.status_code,"requestId":req_id}

    try:
        j=resp.json(); out["json"]=j
        if debug:
            dlog(f"[DEBUG][RESP] status: {resp.status_code}")
            dlog("[DEBUG][RESP] json:")
            dlog(pretty(j))
    except Exception:
        out["text"]=resp.text
        if debug:
            dlog(f"[DEBUG][RESP] status: {resp.status_code}")
            dlog("[DEBUG][RESP] text:")
            dlog(resp.text[:800])
        return out

    if isinstance(j,dict) and isinstance(j.get("result"),str):
        try:
            dec=decrypt_aesgcm_b64(key16, j["result"])
            out["result_decrypted"]=dec
            if debug:
                dlog("[DEBUG][DECRYPT] result:")
                dlog(pretty(dec))
        except Exception as e:
            out["decrypt_error"]=str(e)
            if debug:
                dlog(f"[DEBUG][DECRYPT][ERROR] {e}")

    return out

# =========================================================
# Auth
# =========================================================
def api_get_token(email:str, country_code:str="1", *, debug:bool=False)->Dict[str,Any]:
    return call_api("smartlife.m.user.username.token.get",
                    {"countryCode":country_code,"isUid":False,"username":email},
                    v_value=V_TOKEN, arg2="null", use_postdata=True, debug=debug)

def api_login_email_password_fixed(email:str, password:str, token_block:Dict[str,Any], country_code:str="1", *, debug:bool=False)->Dict[str,Any]:
    dec=token_block.get("result_decrypted") or {}
    if isinstance(dec,dict) and "result" in dec: dec=dec["result"]
    public_key_dec=(dec.get("publicKey") or N_DEC_FALLBACK); token=dec.get("token")
    if not public_key_dec or not token: raise RuntimeError("token.get result does not contain publicKey/token")

    passwd_hex=encrypt_password_hex_fixed(password, public_key_dec)
    options_str="{\"group\": 1,\"mfaCode\": \"\"}"
    post_plain={"countryCode":country_code,"email":email,"ifencrypt":1,"options":options_str,"passwd":passwd_hex,"token":token}
    r=call_api("smartlife.m.user.email.password.login", post_plain, v_value=V_LOGIN, arg2="null", use_postdata=True, debug=debug)

    dec_login=r.get("result_decrypted") or r.get("json")
    if isinstance(dec_login,dict) and dec_login.get("success") is False:
        code=dec_login.get("errorCode"); msg=dec_login.get("errorMsg")
        print(f"\n[ERROR] Login failed: {code} - {msg}"); sys.exit(1)
    return r

def check_login_or_die(login_dec:Any)->None:
    if not isinstance(login_dec,dict):
        print("\n[ERROR] Failed to parse login response."); sys.exit(1)
    if login_dec.get("success") is False:
        print(f"\n[ERROR] Login failed: {login_dec.get('errorCode')} - {login_dec.get('errorMsg')}"); sys.exit(1)
    if "result" not in login_dec:
        print("\n[ERROR] Login response does not contain 'result'."); sys.exit(1)

# =========================================================
# Device & groups
# =========================================================
def api_home_space_list(ecode:str, sid:str, *, v:str=V_HOME_LIST, debug:bool=False)->Dict[str,Any]:
    return call_api("m.life.home.space.list", None, v_value=v, arg2=ecode, sid=sid, include_bizdata=True, use_postdata=False, debug=debug)

def api_group_device_sort_list(ecode:str, sid:str, gid:str, *, debug:bool=False)->Dict[str,Any]:
    return call_api("m.life.my.group.device.sort.list", {"gid":str(gid)}, v_value=V_GROUP_SORT, arg2=ecode, sid=sid, include_bizdata=False, use_postdata=True, debug=debug)

def api_group_device_list(ecode:str, sid:str, gid:str, *, debug:bool=False)->Dict[str,Any]:
    return call_api("m.life.my.group.device.list", {"gid":str(gid)}, v_value=V_GROUP_LIST, arg2=ecode, sid=sid, include_bizdata=False, use_postdata=True, debug=debug)

# =========================================================
# Device trio
# =========================================================
def api_rtc_config_get(ecode:str, sid:str, dev_id:str, *, v:str=V_RTC_CONFIG, debug:bool=False)->Dict[str,Any]:
    return call_api("smartlife.m.rtc.config.get", {"devId":dev_id}, v_value=v, arg2=ecode, sid=sid, include_bizdata=True, use_postdata=True, biz_dm="ipc", debug=debug)

def api_ipc_storage_secret_get(ecode:str, sid:str, dev_id:str, product_id:str, gid:str, *, v:str=V_IPC_SECRET, debug:bool=False)->Dict[str,Any]:
    extra={"pid":product_id,"gid":str(gid),"devId":dev_id}
    return call_api("tuya.m.ipc.storage.secret.get", {"devId":dev_id,"gwId":dev_id}, v_value=v, arg2=ecode, sid=sid, include_bizdata=True, use_postdata=True, extra_fields=extra, debug=debug)

def api_customer_user_instance_served_get(ecode:str, sid:str, dev_id:str, product_id:str, instance_id:str, *, v:str=V_USER_SERVED, debug:bool=False)->Dict[str,Any]:
    return call_api("smartlife.customer.user.instance.served.get", {"clientId":product_id,"devId":dev_id,"instanceId":instance_id}, v_value=v, arg2=ecode, sid=sid, include_bizdata=True, use_postdata=True, debug=debug)

# =========================================================
# Cloud storage APIs
# =========================================================
def api_day_count(ecode: str, sid: str, dev_id: str, gid: str, tz_offset: str, *, v: str = V_DAY_COUNT, debug: bool = False) -> Dict[str, Any]:
    extra = {"ct": "RN"}
    if gid:
        extra["gid"] = str(gid)
    return call_api(
        "tuya.m.ipc.storage.info.day.count",
        {"devId": dev_id, "gwId": dev_id, "timeZone": tz_offset},
        v_value=v, arg2=ecode, sid=sid, include_bizdata=True, use_postdata=True, extra_fields=extra, debug=debug
    )

def api_ipc_storage_timeline_get(ecode:str, sid:str, dev_id:str, time_gt:int, time_lt:int, *, v:str=V_TIMELINE, debug:bool=False)->Dict[str,Any]:
    print(f"[PROGRESS] Timeline: devId={dev_id}, timeGT={time_gt}, timeLT={time_lt}")
    return call_api("m.ipc.storage.timeline.get", {"devId":dev_id,"timeGT":str(time_gt),"timeLT":str(time_lt)}, v_value=v, arg2=ecode, sid=sid, include_bizdata=True, use_postdata=True, debug=debug)

def api_ipc_storage_prefixs_get(ecode:str, sid:str, dev_id:str, prefixes:List[int], *, v:str=V_PREFIXS, debug:bool=False)->Dict[str,Any]:
    print(f"[PROGRESS] Prefixs.get: prefixes={len(prefixes)} request in progress...")
    return call_api("smartlife.m.ipc.storage.prefixs.get", {"devId":dev_id,"prefixs":"["+",".join(str(p) for p in prefixes)+"]"}, v_value=v, arg2=ecode, sid=sid, include_bizdata=True, use_postdata=True, debug=debug)

def api_ipc_storage_read_authority_get(ecode:str, sid:str, dev_id:str, buckets:List[int], *, v:str=V_READ_AUTH, debug:bool=False)->Dict[str,Any]:
    print(f"[PROGRESS] ReadAuthority.get: buckets={buckets}")
    return call_api("m.ipc.storage.read.authority.get", {"buckets":"["+",".join(str(b) for b in buckets)+"]","devId":dev_id}, v_value=v, arg2=ecode, sid=sid, include_bizdata=True, use_postdata=True, debug=debug)

# =========================================================
# Message list (progress + 2s interval + offset+=15)
# =========================================================
def api_msg_list(ecode:str, sid:str, dev_id:str, msg_type:int, offset:int, limit:int=15, *, v:str=V_MSG_LIST, debug:bool=False)->Dict[str,Any]:
    print(f"[PROGRESS] msg.list v={v}: dev={dev_id} type={msg_type} offset={offset} limit={limit}")
    return call_api("smartlife.m.msg.list",
                    {"limit":int(limit),"msgSrcId":dev_id,"msgType":int(msg_type),"offset":int(offset)},
                    v_value=v, arg2=ecode, sid=sid, include_bizdata=True, use_postdata=True, debug=debug)

def _parse_msg_page(resp:Dict[str,Any])->Tuple[List[Dict[str,Any]], int, bool]:
    dec = resp.get("result_decrypted") or resp.get("json")
    res = unwrap_result(dec) if dec is not None else None
    if isinstance(res, dict) and ("datas" in res or "totalCount" in res):
        datas = res.get("datas") or []
        total = res.get("totalCount") or len(datas)
        return (datas, int(total), True)
    if isinstance(res, bool):
        return ([], 0, False)
    return ([], 0, False)

def _sequential_fetch(ecode:str, sid:str, dev_id:str, msg_type:int, *, v:str, limit:int=15, debug:bool=False)->Tuple[Optional[List[Dict[str,Any]]], Optional[int]]:
    items: List[Dict[str,Any]] = []
    total_seen: Optional[int] = None
    offset = 0
    page_idx = 0
    while True:
        if page_idx > 0:
            time.sleep(2)  # 2-second delay between pages
        r = api_msg_list(ecode, sid, dev_id, msg_type, offset, limit=limit, v=v, debug=debug)
        datas, total, ok = _parse_msg_page(r)
        if not ok:
            print("[PROGRESS] v", v, "Unrecognized page format → fallback required")
            return None, None
        if total_seen is None: total_seen = total
        print(f"[PROGRESS] Received: page={page_idx} +{len(datas)} (total {len(items)+len(datas)}/{total_seen})")
        if not datas:
            print("[PROGRESS] No more data → stopping")
            break
        items.extend(datas)
        offset += limit
        page_idx += 1
    return items, (total_seen if isinstance(total_seen,int) else len(items))

def fetch_all_messages(ecode:str, sid:str, dev_id:str, msg_type:int, *, limit:int=15, debug:bool=False)->Dict[str,Any]:
    items, total = _sequential_fetch(ecode, sid, dev_id, msg_type, v=V_MSG_LIST, limit=limit, debug=debug)
    if items is None:
        print("[PROGRESS] v=5.2 failed → starting fallback to v=4.0")
        items, total = _sequential_fetch(ecode, sid, dev_id, msg_type, v=V_MSG_LIST_FALLBACK, limit=limit, debug=debug)
    if items is None:
        return {"total": 0, "items": []}
    return {"total": (total if isinstance(total,int) else len(items)), "items": items}

# =========================================================
# File helpers
# =========================================================
def _load_json(path:str)->Dict[str,Any]:
    if not os.path.exists(path): return {}
    try:
        with open(path,"r",encoding="utf-8") as f: return json.load(f)
    except Exception: return {}

def _save_json(path:str, data:Dict[str,Any])->None:
    with open(path,"w",encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False,indent=2)

def get_encrypt_key(dev_id:str)->Optional[str]:
    data=_load_json(ENCRYPT_KEYS_PATH)
    return data.get(dev_id)

def save_encrypt_key(dev_id:str, key:str)->None:
    data=_load_json(ENCRYPT_KEYS_PATH); data[dev_id]=key; _save_json(ENCRYPT_KEYS_PATH,data)

def save_timeline_prefixes(dev_id:str, prefixes:List[int])->None:
    data=_load_json(TIMELINE_PREFIXES); data[dev_id]=prefixes; _save_json(TIMELINE_PREFIXES,data)

def save_media_file_list(dev_id:str, files:List[str])->None:
    data=_load_json(MEDIA_FILES_PATH); data[dev_id]=files; _save_json(MEDIA_FILES_PATH,data)

def save_read_authority(dev_id:str, auth_obj:Any)->None:
    data=_load_json(READ_AUTH_PATH); data[dev_id]=auth_obj; _save_json(READ_AUTH_PATH,data)

# =========================================================
# Presentation / helpers
# =========================================================
def extract_login_user_fields(login_dec:Dict[str,Any])->Dict[str,str]:
    r={}
    if isinstance(login_dec,dict):
        payload=login_dec.get("result",login_dec)
        if isinstance(payload,dict):
            r["ecode"]=payload.get("ecode") or ""
            r["email"]=payload.get("email") or payload.get("username") or ""
            r["sid"]=payload.get("sid") or ""
            r["uid"]=payload.get("uid") or ""
    return r

def extract_gid_from_home_list(home_dec:Any)->Optional[str]:
    data=unwrap_result(home_dec)
    if isinstance(data,list) and data:
        first=data[0]
        if isinstance(first,dict):
            gid=first.get("gid") or first.get("groupId")
            if gid is not None: return str(gid)
    return None

def print_user_info(user:Dict[str,str])->None:
    print("\n[USER INFO]")
    print(f' - "ecode": "{user.get("ecode","")}"')
    print(f' - "email": "{user.get("email","")}"')
    print(f' - "sid": "{user.get("sid","")}"')
    print(f' - "uid": "{user.get("uid","")}"')
    print(f' - "gid": {user.get("gid","")}')

def summarize_devices(dev_list:List[Dict[str,Any]])->None:
    print("\n[DEVICES] (Select by number / Enter=Quit)")
    for idx,d in enumerate(dev_list,1):
        print(f"{idx:>2}. devId={d.get('devId','')} | ip={d.get('ip','')} | localKey={d.get('localKey','')}")
        print(f"    name={d.get('name','')} | productId={d.get('productId','')} | uuid={d.get('uuid','')}")

def _fmt_ms(ms: Optional[int], tz: Optional[timezone] = None) -> str:
    if not isinstance(ms, (int, float)):
        return "-"
    try:
        dt = datetime.fromtimestamp(ms / 1000.0, tz=tz) if tz else datetime.fromtimestamp(ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ms)

def _fmt_s(sec: int, fmt: str = "%Y-%m-%d %H:%M:%S", tz: Optional[timezone] = None) -> str:
    try:
        dt = datetime.fromtimestamp(int(sec), tz=tz) if tz else datetime.fromtimestamp(int(sec))
        return dt.strftime(fmt)
    except Exception:
        return str(sec)

def _parse_any_datetime_to_utc_str(v: Any) -> str:
    """
    Convert various time fields to a UTC(+0) string.
    Supported:
      - epoch seconds (int/float, 10 digits-ish)
      - epoch milliseconds (int/float, 13 digits-ish)
      - ISO-8601-like strings (with 'Z' or timezone offset)
      - other date strings: returned as-is with a marker
    """
    try:
        # 1) numeric epoch
        if isinstance(v, (int, float)):
            # heuristic: ms if too large
            sec = float(v) / 1000.0 if v > 1e12 else float(v)
            dt = datetime.fromtimestamp(sec, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S")

        # 2) numeric string epoch
        if isinstance(v, str):
            s = v.strip()
            if s.isdigit():
                n = int(s)
                sec = n / 1000.0 if n > 1e12 else n
                dt = datetime.fromtimestamp(sec, tz=timezone.utc)
                return dt.strftime("%Y-%m-%d %H:%M:%S")

            # 3) ISO-ish
            # handle trailing Z
            iso = s.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(iso)
                # if naive, assume UTC (better than local for forensic consistency)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                dt = dt.astimezone(timezone.utc)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                # unknown format; return original with mark
                return f"{s} (raw)"
    except Exception:
        pass
    return "-"  # fallback


def _utc_day_to_utc_range(day_str: str) -> Tuple[int, int]:
    y, m, d = map(int, day_str.split("-"))
    start = datetime(y, m, d, 0, 0, 0, tzinfo=timezone.utc)
    end   = datetime(y, m, d, 23, 59, 59, tzinfo=timezone.utc)
    return int(start.timestamp()), int(end.timestamp())

def _tz_local_day_to_utc_range(day_str: str, tzid: str) -> Tuple[int, int]:
    y, m, d = map(int, day_str.split("-"))
    z = ZoneInfo(tzid)
    start_local = datetime(y, m, d, 0, 0, 0, tzinfo=z)
    end_local   = datetime(y, m, d, 23, 59, 59, tzinfo=z)
    start_utc = start_local.astimezone(timezone.utc)
    end_utc   = end_local.astimezone(timezone.utc)
    return int(start_utc.timestamp()), int(end_utc.timestamp())

def _utc_date_str_from_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")

def build_utc_days_from_upload_days(upload_days: List[str], tzid: str) -> List[str]:
    utc_days = set()
    for ds in upload_days:
        try:
            gt, lt = _tz_local_day_to_utc_range(ds, tzid)
        except Exception:
            continue
        start_d = datetime.fromtimestamp(gt, tz=timezone.utc).date()
        end_d   = datetime.fromtimestamp(lt, tz=timezone.utc).date()
        cur = start_d
        while cur <= end_d:
            utc_days.add(cur.strftime("%Y-%m-%d"))
            cur += timedelta(days=1)
    return sorted(utc_days)


def _interpret_served(served_dec:Any)->Dict[str,Any]:
    raw=served_dec if isinstance(served_dec,dict) else {}
    r=raw.get("result") if isinstance(raw.get("result"),dict) else None
    if raw.get("success") is False and raw.get("errorCode")=="SERVED_NOT_EXISTED":
        return {"exists":False,"status":"not_subscribed","serveType":None,"plan":None,"begin_ms":None,"end_ms":None,"raw":raw}
    if r is not None:
        return {"exists":True,"status":r.get("servedStatus"),"serveType":r.get("serveType"),"plan":r.get("commodityName"),
                "begin_ms":r.get("gmtServedBegin"),"end_ms":r.get("gmtServedEnd"),"raw":r}
    if isinstance(raw,dict) and ("servedStatus" in raw or "serveType" in raw):
        return {"exists":True,"status":raw.get("servedStatus"),"serveType":raw.get("serveType"),"plan":raw.get("commodityName"),
                "begin_ms":raw.get("gmtServedBegin"),"end_ms":raw.get("gmtServedEnd"),"raw":raw}
    return {"exists":None,"status":None,"serveType":None,"plan":None,"begin_ms":None,"end_ms":None,"raw":raw}

def build_media_entries(media_infos:List[Dict[str,Any]])->List[Dict[str,Any]]:
    out=[]
    for m in media_infos:
        p=m.get("prefix"); 
        if p is None: continue
        try: p=int(p)
        except: continue
        for s in m.get("segmentInfo") or []:
            try: s=int(s)
            except: continue
            out.append({"file":f"{p}_{s:04d}.media","prefix":p,"segment":s,"start":p+s})
    out.sort(key=lambda x:x["start"])
    return out

def _group_entries_by_date(entries: List[Dict[str, Any]], tz: Optional[timezone] = None) -> Dict[str, List[Dict[str, Any]]]:
    g = {}
    for e in entries:
        d = _fmt_s(e["start"], "%Y-%m-%d", tz=tz)
        g.setdefault(d, []).append(e)
    for d in g:
        g[d].sort(key=lambda x: x["start"])
    return g

def _print_time_menu(entries: List[Dict[str, Any]], allow_all: bool, tz: Optional[timezone] = None) -> None:
    print("\n[MEDIA] Select a time (number / {}b=Back / Enter=Cancel)".format("a=All / " if allow_all else ""))
    for i, e in enumerate(entries, 1):
        print(f" {i:3}. {_fmt_s(e['start'], '%H:%M:%S', tz=tz)}  -> {e['file']}")

def _select_time_entry(entries: List[Dict[str, Any]], *, base_path: Optional[str] = None, bucket_hint: Optional[str] = None,
                       allow_all: bool = False, tz: Optional[timezone] = None) -> Tuple[Optional[Union[Dict[str, Any], str]], bool]:
    if not entries:
        print("\n[MEDIA] No files available to select.")
        return None, True
    while True:
        _print_time_menu(entries, allow_all, tz=tz)
        sel = input(" - Enter a time index: ").strip().lower()
        if sel in {"", "b"}:
            return None, True
        if allow_all and sel in {"a", "all"}:
            return "ALL", False
        if not sel.isdigit() or not (1 <= int(sel) <= len(entries)):
            print("[INFO] Invalid input. Please try again.")
            continue
        chosen = entries[int(sel) - 1]
        print("\n[SELECTED MEDIA]")
        print(" - time:", _fmt_s(chosen["start"], "%H:%M:%S", tz=tz))
        print(" - filename:", chosen["file"])
        if base_path:
            print(" - path:", f"{base_path.rstrip('/')}/{chosen['file']}")
        if bucket_hint:
            print(" - bucket:", bucket_hint)
        return chosen, False

def show_device_extra_summary(dev_id: str, rtc_dec: Any, secret_dec: Any, served_dec: Any, tz: Optional[timezone] = None) -> None:
    print("\n[EXTRA] devId =", dev_id)
    rtc=unwrap_result(rtc_dec)
    if isinstance(rtc,dict):
        sess=(rtc.get("p2pConfig") or {}).get("session") or {}
        print(" - RTC.webrtc:", rtc.get("supportsWebrtc"), " p2pType:", rtc.get("p2pType"))
        print(" - RTC.sessionId:", sess.get("sessionId"))
        print(" - RTC.iceUfrag:", sess.get("iceUfrag"), " icePwd:", sess.get("icePassword"))
        if sess.get("aesKey"): print(" - RTC.session.aesKey:", sess.get("aesKey"))

    sec=unwrap_result(secret_dec)
    if isinstance(sec,dict):
        enc=sec.get("encryptKey")
        print(" - STORAGE.encryptKey:", enc)
        if enc:
            try: save_encrypt_key(dev_id, enc); print("   (saved to", ENCRYPT_KEYS_PATH, ")")
            except Exception as e: print("   (save failed:", e, ")")

    info=_interpret_served(served_dec)
    if info["exists"] is False:
        print(' - SERVICE: not subscribed (security_cloud_service)'); return
    if info["exists"] is None:
        print(" - SERVICE: unknown"); return
    status,plan,stype=info["status"] or "-",info["plan"] or "-",info["serveType"] or "-"
    begin_s, end_s = _fmt_ms(info["begin_ms"], tz=tz), _fmt_ms(info["end_ms"], tz=tz)
    if status=="running":
        now_ms=int(time.time()*1000); left_d=None
        if isinstance(info["end_ms"],(int,float)): left_d=int((info["end_ms"]-now_ms)//(1000*60*60*24))
        print(f" - SERVICE: running ({stype}) — plan: {plan} — expires: {end_s}{'' if left_d is None else f' (D{left_d:+d})'}")
        print(f"            period: {begin_s} → {end_s}")
    elif status=="expire":
        print(f" - SERVICE: expired ({stype}) — expired at: {end_s}")
        if info["begin_ms"]: print(f"            period: {begin_s} → {end_s}")
    else:
        print(f" - SERVICE: {status} ({stype}) — period: {begin_s} → {end_s} — plan: {plan}")

# =========================================================
# Download helpers
# =========================================================
def check_expiration(exp_str:str)->None:
    exp_dt=datetime.fromisoformat(exp_str.replace("Z","+00:00")).astimezone(timezone.utc)
    now_utc=datetime.now(timezone.utc)
    if now_utc>=exp_dt:
        print(f"[!] Token expired at {exp_dt.isoformat()} UTC"); sys.exit(2)
    left_sec=int((exp_dt-now_utc).total_seconds())
    print(f"[+] Token valid until {exp_dt.isoformat()} UTC (~{left_sec} seconds left)")

def s3_download(endpoint:str, region:str, ak:str, sk:str, token:str, bucket:str, object_key:str, output_file:str)->None:
    if not HAS_BOTO3:
        print("\n[ERROR] boto3 is not installed. Run: pip install boto3 botocore"); return

    dl_dir = ensure_download_dir()

    # ✅ If output_file is only a filename, save it under smartlife_download
    if not os.path.isabs(output_file):
        output_file = os.path.join(dl_dir, os.path.basename(output_file))

    s3 = boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        aws_session_token=token,
        endpoint_url=f"https://{endpoint}"
    )
    try:
        print(f"[+] Downloading s3://{bucket}/{object_key} -> {output_file}")
        s3.download_file(bucket, object_key, output_file)
        print(f"[+] Download complete: {output_file}")
    except ClientError as e:
        print(f"[ERROR] S3 download failed: {e}", file=sys.stderr)

def http_download(url:str, out_name:Optional[str]=None)->Optional[str]:
    try:
        dl_dir = ensure_download_dir()

        if not out_name:
            base = os.path.basename(urlsplit(url).path) or "download.bin"
            out_name = base

        # ✅ Fix the save path under smartlife_download
        base_name, ext = os.path.splitext(out_name)
        i = 1
        full_path = os.path.join(dl_dir, out_name)

        # ✅ Handle duplicate filenames inside the same download folder
        while os.path.exists(full_path):
            cand = f"{base_name}({i}){ext}"
            full_path = os.path.join(dl_dir, cand)
            i += 1

        print(f"[+] Downloading -> {full_path}")
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            size = int(r.headers.get("Content-Length") or 0)
            read = 0
            chunk = 8192
            last_pct = -1

            with open(full_path, "wb") as f:
                for buf in r.iter_content(chunk):
                    if not buf:
                        continue
                    f.write(buf)
                    read += len(buf)
                    if size > 0:
                        pct = int(read * 100 / size)
                        if pct != last_pct and pct % 10 == 0:
                            print(f"    ... {pct}%")
                            last_pct = pct

        print(f"[+] Download complete: {full_path}")
        return full_path

    except Exception as e:
        print(f"[ERROR] HTTP download failed: {e}")
        return None

# =========================================================
# Decrypt helpers
# =========================================================
def _aes_cbc_pkcs7_decrypt(ciphertext:bytes, key:bytes, iv:bytes)->bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(dec) + unpadder.finalize()

def _decrypt_picture_file(in_path:str, key_ascii:str, out_path:Optional[str]=None)->Optional[str]:
    if not os.path.exists(in_path):
        print(f"[DECRYPT][IMG] File not found: {in_path}"); return None
    with open(in_path,"rb") as f: blob=f.read()
    if len(blob)<PIC_HEADER_SIZE:
        print("[DECRYPT][IMG] Header (0x40) is missing/too small → treating as a non-encrypted image, skipping")
        return None
    encrypted_flag = struct.unpack_from("<I", blob, 0x0)[0]
    iv = blob[0x4:0x4+16]
    original_size = struct.unpack_from("<I", blob, 0x18)[0]
    body = blob[PIC_HEADER_SIZE:]
    print(f"[DECRYPT][IMG] flag={encrypted_flag} orig={original_size} iv={iv.hex()}")
    if encrypted_flag != 1:
        print("[DECRYPT][IMG] Encryption flag is not 1 → skipping")
        return None
    if len(body)%16!=0:
        print("[DECRYPT][IMG] Ciphertext length is not a multiple of 16 → skipping"); return None
    key = key_ascii.encode("ascii")
    if len(key)!=16:
        print("[DECRYPT][IMG] Invalid encryptKey length (must be 16 bytes) → skipping"); return None
    try:
        plain=_aes_cbc_pkcs7_decrypt(body, key, iv)
        if original_size>0: plain=plain[:original_size]
        base,ext=os.path.splitext(in_path)
        out = out_path or (base+"_decrypt.jpg")
        with open(out,"wb") as g: g.write(plain)
        if plain[:3]==b"\xFF\xD8\xFF": print("[DECRYPT][IMG] JPEG signature verified (FFD8FF)")
        print(f"[DECRYPT][IMG] Done -> {out} ({len(plain)}B)")
        return out
    except Exception as e:
        print(f"[DECRYPT][IMG] Failed: {e}")
        return None

import os, struct, binascii
from typing import Optional

def _decrypt_video_file(in_path: str, key_ascii: str, out_base: Optional[str] = None) -> Optional[tuple[str, str]]:
    """
    Video decryption (strip header + also save a header-included version)
    - For the "full" file, update the decrypted data length at header offset 0x4
    """
    if not os.path.exists(in_path):
        print(f"[DECRYPT][VID] File not found: {in_path}")
        return None

    key = key_ascii.encode("ascii")
    if len(key) != 16:
        print("[DECRYPT][VID] Invalid encryptKey length (must be 16 bytes) → skipping")
        return None

    iv = binascii.unhexlify(VID_FIXED_IV_HEX)
    base, _ = os.path.splitext(in_path)
    base = out_base or base
    out_nohdr = base + "_decrypt.h264"      # Header-stripped version
    out_full  = base + "_decrypt_full.h264" # Header-included version

    total = dec_blocks = copied = written_nohdr = written_full = 0
    with open(in_path, "rb") as fin, \
         open(out_nohdr, "wb") as fout_nohdr, \
         open(out_full,  "wb") as fout_full:

        while True:
            pos = fin.tell()
            hdr = fin.read(VID_HEADER_SIZE)
            if not hdr:
                break
            if len(hdr) < VID_HEADER_SIZE:
                print(f"[DECRYPT][VID] Incomplete header ({len(hdr)}B) @0x{pos:X} → stopping")
                break

            data_type, data_len = struct.unpack("<II", hdr[0:8])
            data = fin.read(data_len)
            if len(data) < data_len:
                print(f"[DECRYPT][VID] Not enough data: expected {data_len}, got {len(data)}")

            out_data = data
            if data_type in {1, 3}:  # Encrypted block
                if len(data) % 16 == 0 and len(data) > 0:
                    try:
                        out_data = _aes_cbc_pkcs7_decrypt(data, key, iv)
                        dec_blocks += 1
                    except Exception as e:
                        print(f"[DECRYPT][VID] Failed to decrypt block@0x{pos:X}: {e} → keeping original")
                else:
                    print(f"[DECRYPT][VID] Block@0x{pos:X} len={len(data)} (not a multiple of 16) → keeping original")
            else:
                copied += 1

            # --- Header-stripped version ---
            fout_nohdr.write(out_data)
            written_nohdr += len(out_data)

            # --- Header-included version ---
            # Copy the header, then update the data length (0x4~0x7) to the decrypted length
            new_hdr = bytearray(hdr)
            struct.pack_into("<I", new_hdr, 4, len(out_data))
            fout_full.write(new_hdr)
            fout_full.write(out_data)
            written_full += len(new_hdr) + len(out_data)

            total += 1

    print(f"[DECRYPT][VID] Done:")
    print(f"  blocks={total}, dec={dec_blocks}, copy={copied}")
    print(f"  no-header bytes={written_nohdr}, out={out_nohdr}")
    print(f"  full-header bytes={written_full}, out={out_full}")
    return out_nohdr, out_full


# =========================================================
# Logs menu (All download + decryption for msgType=1 pics)
# =========================================================
def _extract_urls_from_item(it:Dict[str,Any])->List[str]:
    urls=[]
    pics=it.get("attachPics"); vids=it.get("attachVideos")
    if isinstance(pics,str) and pics.strip(): urls.append(pics.strip())
    elif isinstance(pics,list):
        for u in pics:
            if isinstance(u,str) and u.strip(): urls.append(u.strip())
    if isinstance(vids,str) and vids.strip(): urls.append(vids.strip())
    elif isinstance(vids,list):
        for u in vids:
            if isinstance(u,str) and u.strip(): urls.append(u.strip())
    return urls

def _download_many(urls:List[str], *, gap_sec:int=2)->List[str]:
    paths=[]
    if not urls:
        print("[INFO] No URLs to download."); return paths
    for i,u in enumerate(urls,1):
        print(f"\n[DOWNLOAD] {i}/{len(urls)}")
        p=http_download(u)
        if p: paths.append(p)
        if i < len(urls):
            time.sleep(gap_sec)  # 2-second gap between files
    return paths

def ensure_encrypt_key(dev:Dict[str,Any], *, ecode:str, sid:str, gid:str, debug:bool=False)->Optional[str]:
    dev_id=dev.get("devId","")
    key=get_encrypt_key(dev_id)
    if key: return key
    print("[PROGRESS] encryptKey not found → calling tuya.m.ipc.storage.secret.get")
    product_id=dev.get("productId","")
    r=api_ipc_storage_secret_get(ecode, sid, dev_id, product_id, gid, v=V_IPC_SECRET, debug=debug)
    dec=unwrap_result(r.get("result_decrypted") or r.get("json"))
    if isinstance(dec,dict) and dec.get("encryptKey"):
        key=dec["encryptKey"]
        save_encrypt_key(dev_id, key)
        print("[PROGRESS] encryptKey acquired and saved")
        return key
    print("[WARN] Failed to obtain encryptKey.")
    return None

def try_decrypt_downloaded_if_pic(file_path:str, encrypt_key:str)->None:
    _decrypt_picture_file(file_path, encrypt_key)

def logs_menu(dev:Dict[str,Any], *, ecode:str, sid:str, gid:str, debug:bool=False)->None:
    dev_id=dev.get("devId","")
    print("\n[LOGS] Select type (1/2/3, b=back)")
    while True:
        t=input(" - Enter msgType: ").strip().lower()
        if t in {"","b"}: return
        if t not in {"1","2","3"}:
            print("[INFO] Please choose 1, 2, or 3."); continue
        msg_type=int(t)

        print("[PROGRESS] Starting message collection...")
        collected=fetch_all_messages(ecode, sid, dev_id, msg_type, debug=debug)
        items=collected["items"]; total=collected["total"]
        print(f"\n[LOGS] Collected {total} total (showing {len(items)})")

        if not items:
            print("[INFO] No logs to display."); return

        if msg_type == 1:
            print("\n[TYPE 1] Download image/video (number / a=All / b=back / Enter=cancel)")
            numbered=[]
            for i,it in enumerate(items,1):
                dt = _parse_any_datetime_to_utc_str(it.get("time"))
                if dt == "-" or dt.endswith("(raw)"):
                    dt2 = _parse_any_datetime_to_utc_str(it.get("dateTime"))
                    if dt2 != "-":
                        dt = dt2

                title=it.get("msgTitle") or "-"
                content=it.get("msgContent") or "-"
                urls=_extract_urls_from_item(it)
                print(f" {i:3}. {dt} | {title} | {content}")
                if urls:
                    for u in urls[:2]:
                        print(f"      URL: {u[:120]}{'...' if len(u)>120 else ''}")
                    if len(urls)>2: print(f"      (+{len(urls)-2} more)")
                numbered.append({"idx":i,"urls":urls})

            enc_key = ensure_encrypt_key(dev, ecode=ecode, sid=sid, gid=gid, debug=debug) or ""

            while True:
                sel=input(" - Enter a number to download, or (a): ").strip().lower()
                if sel in {"","b"}: return
                targets: List[str] = []
                if sel in {"a","all"}:
                    for row in numbered: targets.extend(row["urls"])
                else:
                    if not sel.isdigit() or not (1 <= int(sel) <= len(numbered)):
                        print("[INFO] Invalid input."); continue
                    row=numbered[int(sel)-1]
                    if not row["urls"]:
                        print("[WARN] No attached URLs."); continue
                    targets=row["urls"]

                paths=_download_many(targets, gap_sec=2)
                if enc_key:
                    for p in paths:
                        try_decrypt_downloaded_if_pic(p, enc_key)
                else:
                    print("[WARN] No encryptKey available, skipping decryption.")
                return
        else:
            for i,it in enumerate(items,1):
                dt=it.get("dateTime") or _fmt_s(it.get("time",0))
                title=it.get("msgTitle") or "-"
                content=it.get("msgContent") or "-"
                print(f" {i:3}. {dt} | {title} | {content}")
            return

# =========================================================
# Cloud video flow — with ALL options
# =========================================================
def _tz_offset_str_for_day(tzid: str, day_str: str) -> str:
    y, m, d = map(int, day_str.split("-"))
    z = ZoneInfo(tzid)
    dt = datetime(y, m, d, 12, 0, 0, tzinfo=z)
    off = dt.utcoffset() or timedelta(0)
    total_min = int(off.total_seconds() // 60)
    sign = "+" if total_min >= 0 else "-"
    total_min = abs(total_min)
    hh, mm = divmod(total_min, 60)
    return f"{sign}{hh:02d}:{mm:02d}"

def _local_day_to_utc_range(day_str: str, tzid: str) -> Tuple[int, int]:
    y, m, d = map(int, day_str.split("-"))
    z = ZoneInfo(tzid)
    start_local = datetime(y, m, d, 0, 0, 0, tzinfo=z)
    end_local   = datetime(y, m, d, 23, 59, 59, tzinfo=z)
    start_utc = start_local.astimezone(timezone.utc)
    end_utc   = end_local.astimezone(timezone.utc)
    return int(start_utc.timestamp()), int(end_utc.timestamp())

def _pick_utc_day(utc_days: List[str]) -> Tuple[Optional[str], Optional[str]]:
    if not utc_days:
        print("\n[INFO] No saved UTC dates found.")
        return None, None

    print("\n[UTC MEDIA DATES] Select a date (number / a=all / b=back / Enter=cancel)")
    for i, ds in enumerate(utc_days, 1):
        gt, lt = _utc_day_to_utc_range(ds)
        gt_s = _fmt_s(gt, "%Y-%m-%d %H:%M:%S", tz=timezone.utc)
        lt_s = _fmt_s(lt, "%Y-%m-%d %H:%M:%S", tz=timezone.utc)
        print(f" {i:2}. {ds}  (UTC+0)")

    while True:
        sel = input(" - Select date: ").strip().lower()
        if sel in {"", "b"}:
            return None, None
        if sel in {"a", "all"}:
            return "ALL", None
        if not sel.isdigit() or not (1 <= int(sel) <= len(utc_days)):
            print("[INFO] Invalid input.")
            continue
        return "ONE", utc_days[int(sel) - 1]


def _download_videos_from_entries(dev:Dict[str,Any], *, ecode:str, sid:str, gid:str,
                                  creds:Dict[str,Any], bucket_name:str, base_path:str,
                                  entries:List[Dict[str,Any]], gap_sec:int=2, debug:bool=False)->None:
    if not entries:
        print("[INFO] No items to download."); return
    ak,sk,token=creds.get("ak"),creds.get("sk"),creds.get("token")
    endpoint,region,expiration=creds.get("endpoint"),creds.get("region"),creds.get("expiration")
    if expiration: check_expiration(expiration)
    dev_id=dev.get("devId","")
    enc_key = get_encrypt_key(dev_id) or ensure_encrypt_key(dev, ecode=ecode, sid=sid, gid=gid, debug=debug)
    if not enc_key:
        print("[WARN] No encryptKey available → skipping decryption.")
    total=len(entries)
    for i,e in enumerate(entries,1):
        key=f"{base_path.lstrip('/')}/{e['file']}"
        print(f"\n[DOWNLOAD][{i}/{total}] s3://{bucket_name}/{key}")
        local_path = os.path.join(ensure_download_dir(), e['file'])
        s3_download(endpoint, region, ak, sk, token, bucket_name, key, local_path)
        if enc_key:
            _decrypt_video_file(local_path, enc_key)
        if i<total:
            time.sleep(gap_sec)

def _collect_utc_day_entries(ecode: str, sid: str, dev_id: str, utc_day_str: str, *, debug: bool = False) -> Tuple[List[Dict[str, Any]], Optional[str], Optional[str], Optional[List[int]], Any]:
    time_gt, time_lt = _utc_day_to_utc_range(utc_day_str)
    print(f"[PROGRESS] UTC day={utc_day_str} → UTC {time_gt}~{time_lt}")

    tl = api_ipc_storage_timeline_get(ecode, sid, dev_id, time_gt, time_lt, v=V_TIMELINE, debug=debug)
    tl_unwrapped = unwrap_result(tl.get("result_decrypted") or tl.get("json"))

    prefixes = []
    if isinstance(tl_unwrapped, list):
        prefixes = [int(x.get("prefix")) for x in tl_unwrapped if isinstance(x, dict) and "prefix" in x]
    elif isinstance(tl_unwrapped, dict):
        arr = tl_unwrapped.get("result")
        if isinstance(arr, list):
            prefixes = [int(x.get("prefix")) for x in arr if isinstance(x, dict) and "prefix" in x]
    prefixes = sorted(set(prefixes))

    if not prefixes:
        print("[INFO] No prefix found for this UTC day.");
        return [], None, None, None, None

    pf = api_ipc_storage_prefixs_get(ecode, sid, dev_id, prefixes, v=V_PREFIXS, debug=debug)
    pf_res = unwrap_result(pf.get("result_decrypted") or pf.get("json"))

    bucket14_name = None
    base_path = None
    media_infos = []
    buckets = None

    if isinstance(pf_res, dict):
        bucket14_name = pf_res.get("bucket14Days")
        base_path = pf_res.get("path")
        media_infos = pf_res.get("mediaStorageInfos") or []
        buckets = pf_res.get("buckets") or []

    entries = build_media_entries(media_infos)
    return entries, bucket14_name, base_path, buckets, pf_res

def cloud_video_flow(dev:Dict[str,Any], *, ecode:str, sid:str, gid:str, days_range:int, debug:bool=False)->None:
    dev_id, product_id, instance_id = dev.get("devId", ""), dev.get("productId", ""), dev.get("uuid", "")

    # ✅ device timezoneId
    tzid = dev.get("timezoneId") or TIMEZONE_ID or "Asia/Seoul"
    display_tz = timezone.utc  # ✅ cloud videos  UTC

    print("[PROGRESS] Collecting initial device info (RTC/SECRET/SERVED)...")

    rtc    = api_rtc_config_get(ecode, sid, dev_id, v=V_RTC_CONFIG, debug=debug)
    secret = api_ipc_storage_secret_get(ecode, sid, dev_id, product_id, gid, v=V_IPC_SECRET, debug=debug)
    served = api_customer_user_instance_served_get(ecode, sid, dev_id, product_id, instance_id, v=V_USER_SERVED, debug=debug)

    rtc_dec    = unwrap_result(rtc.get("result_decrypted")    or rtc.get("json"))
    secret_dec = unwrap_result(secret.get("result_decrypted") or secret.get("json"))
    served_dec = unwrap_result(served.get("result_decrypted") or served.get("json"))

    show_device_extra_summary(dev_id, rtc_dec, secret_dec, served_dec, tz=timezone.utc)

    info=_interpret_served(served_dec)
    if not (info["exists"] is True and info["status"]=="running"):
        print("\n[INFO] Cloud storage service is not in 'running' state."); return

    # 1) Fetch uploadDay list
    print("[PROGRESS] Fetching saved days (day.count)...")
    tz_offset_now = _tz_offset_str_for_day(tzid, datetime.now(ZoneInfo(tzid)).strftime("%Y-%m-%d"))

    dc = api_day_count(ecode, sid, dev_id, gid, tz_offset_now, v=V_DAY_COUNT, debug=debug)

    dc_res = unwrap_result(dc.get("result_decrypted") or dc.get("json")) or []
    days = []
    if isinstance(dc_res, list):
        for x in dc_res:
            if isinstance(x, dict) and x.get("uploadDay"):
                days.append(x["uploadDay"])
    days = sorted(sorted(set(days)))

    utc_days = build_utc_days_from_upload_days(days, tzid)

    mode, pick = _pick_utc_day(utc_days)
    if not mode:
        return

    # ===== Batch download for ALL days =====
    if mode == "ALL":
        print(f"[PROGRESS] Starting batch download for all UTC days ({len(utc_days)} days)")
        for di, utc_day in enumerate(utc_days, 1):
            print(f"\n=== [UTC DAY {di}/{len(utc_days)}] {utc_day} ===")

            entries, bucket14_name, base_path, buckets, _pf = _collect_utc_day_entries(
                ecode, sid, dev_id, utc_day, debug=debug
            )
            if not entries or not (bucket14_name and base_path and buckets):
                print("[INFO] Skipping (missing entries/bucket/path)")
                continue

            rd = api_ipc_storage_read_authority_get(ecode, sid, dev_id, buckets, v=V_READ_AUTH, debug=debug)
            rd_res = unwrap_result(rd.get("result_decrypted") or rd.get("json"))
            if not (isinstance(rd_res, list) and rd_res):
                print("[WARN] No ReadAuthority info → skipping")
                continue

            save_read_authority(dev_id, rd_res)
            _download_videos_from_entries(
                dev, ecode=ecode, sid=sid, gid=gid,
                creds=rd_res[0], bucket_name=bucket14_name,
                base_path=base_path, entries=entries, gap_sec=2, debug=debug
            )

        print("\n[PROGRESS] Completed batch download for all UTC days")
        return

    # ===== Single day processing =====
    # 2) Fetch timeline using the selected day's UTC range → build file list
    entries, bucket14_name, base_path, buckets, _pf = _collect_utc_day_entries(
        ecode, sid, dev_id, pick, debug=debug
    )
    if not entries:
        print("[INFO] No selectable media found for this UTC day.")
        return
    if not (bucket14_name and base_path and buckets):
        print("[WARN] Missing bucket/path info")
        return

    rd = api_ipc_storage_read_authority_get(ecode, sid, dev_id, buckets, v=V_READ_AUTH, debug=debug)
    rd_res = unwrap_result(rd.get("result_decrypted") or rd.get("json"))
    if not (isinstance(rd_res, list) and rd_res):
        print("[WARN] No ReadAuthority info")
        return
    save_read_authority(dev_id, rd_res)

    chosen, back = _select_time_entry(
        entries, base_path=base_path, bucket_hint=bucket14_name,
        allow_all=True, tz=display_tz
    )
    if back or not chosen:
        return

    creds = rd_res[0]
    if chosen == "ALL":
        print(f"[PROGRESS] Starting batch download for UTC '{pick}' ({len(entries)} files)")
        _download_videos_from_entries(
            dev, ecode=ecode, sid=sid, gid=gid,
            creds=creds, bucket_name=bucket14_name,
            base_path=base_path, entries=entries, gap_sec=2, debug=debug
        )
        print(f"[PROGRESS] Completed batch download for UTC '{pick}'")
        return

    # 5) Single item download + decrypt
    object_key=f"{base_path.lstrip('/')}/{chosen['file']}"
    ak,sk,token=creds.get("ak"),creds.get("sk"),creds.get("token")
    endpoint,region,expiration=creds.get("endpoint"),creds.get("region"),creds.get("expiration")
    if expiration: check_expiration(expiration)

    print("\n[DOWNLOAD INFO]")
    print(" - endpoint :", endpoint)
    print(" - region   :", region)
    print(" - bucket   :", bucket14_name)
    print(" - key      :", object_key)
    print(" - url(ex)  :", f"https://{bucket14_name}.{endpoint}/{object_key}")

    # ✅ Set download path
    local_path = os.path.join(ensure_download_dir(), chosen["file"])

    # ✅ Save to local_path
    s3_download(endpoint, region, ak, sk, token, bucket14_name, object_key, local_path)

    print("[PROGRESS] Preparing video decryption: checking encryptKey...")
    enc_key = get_encrypt_key(dev_id) or ensure_encrypt_key(dev, ecode=ecode, sid=sid, gid=gid, debug=debug)

    if not enc_key:
        print("[WARN] encryptKey not available, skipping decryption.")
        return

    print("[PROGRESS] Starting video decryption...")
    _decrypt_video_file(local_path, enc_key)


# =========================================================
# Device menus with back
# =========================================================
def device_inner_menu(dev:Dict[str,Any], *, ecode:str, sid:str, gid:str, days_range:int, debug:bool=False)->None:
    while True:
        print("\n[DEVICE MENU]")
        print(" 1) View logs")
        print(" 2) View cloud videos")
        print(" b) Back to previous menu (device list)")
        sel=input(" - Select: ").strip().lower()
        if sel in {"b",""}: return
        if sel=="1": logs_menu(dev, ecode=ecode, sid=sid, gid=gid, debug=debug)
        elif sel=="2": cloud_video_flow(dev, ecode=ecode, sid=sid, gid=gid, days_range=days_range, debug=debug)
        else: print("[INFO] Invalid input.")

def device_menu_loop(dev_list:List[Dict[str,Any]], *, ecode:str, sid:str, gid:str, days_range:int, debug:bool=False)->None:
    if not dev_list:
        print("\n[INFO] No devices found."); return
    while True:
        summarize_devices(dev_list)
        sel=input("\n[SELECT] Enter device number (1~{} / Enter or b = quit): ".format(len(dev_list))).strip().lower()
        if sel in {"","b"}:
            print("[INFO] Exiting."); return
        if not sel.isdigit(): print("[INFO] Please enter numbers only."); continue
        idx=int(sel)
        if not (1<=idx<=len(dev_list)): print("[INFO] Out of range."); continue
        dev=dev_list[idx-1]
        device_inner_menu(dev, ecode=ecode, sid=sid, gid=gid, days_range=days_range, debug=debug)

# =========================================================
# CLI
# =========================================================
def main():
    log_f = None
    old_stdout = old_stderr = None
    log_path = None
    debug = True

    try:
        # ✅ Create smartlife_log/<timestamp>.log on each run and apply tee logging
        log_f, log_path, _log_lock, old_stdout, old_stderr = setup_smartlife_logging("smartlife_log")

        ap=argparse.ArgumentParser(description="SmartLife CLI (uploadDay→day timeline, progress, throttled msg.list, All downloads, decrypt)")
        ap.add_argument("--email", required=True)
        ap.add_argument("--password", required=True)
        ap.add_argument("--country", default="1")
        ap.add_argument("--v-home", default=V_HOME_LIST)
        ap.add_argument("--gid", default="")
        ap.add_argument("--days", type=int, default=60)
        ap.add_argument("--no-sort", action="store_true")
        ap.add_argument("--no-list", action="store_true")
        ap.add_argument("--debug", action="store_true")
        args=ap.parse_args()

        tok = api_get_token(args.email, args.country, debug=debug)
        if not tok.get("result_decrypted"):
            print("\n[ERROR] token.get decryption failed"); sys.exit(1)

        login_res=api_login_email_password_fixed(args.email, args.password, tok, args.country, debug=debug)
        login_dec=login_res.get("result_decrypted")
        check_login_or_die(login_dec)

        user=extract_login_user_fields(login_dec)
        if not (user.get("ecode") and user.get("sid")):
            print("[ERROR] ecode/sid missing in login response"); sys.exit(1)

        home=api_home_space_list(user["ecode"], user["sid"], v=args.v_home, debug=debug)
        home_dec=home.get("result_decrypted") or home.get("json",{}).get("result")
        gid=args.gid.strip() or extract_gid_from_home_list(home_dec)
        user["gid"]=gid or ""
        print_user_info(user)

        if (gid is not None) and (not args.no_sort):
            _=api_group_device_sort_list(user["ecode"], user["sid"], gid, debug=debug)

        dev_list=[]
        if (gid is not None) and (not args.no_list):
            gl=api_group_device_list(user["ecode"], user["sid"], gid, debug=debug)
            payload=gl.get("result_decrypted") or gl.get("json",{}).get("result")
            payload=unwrap_result(payload)
            if isinstance(payload,list): dev_list=payload

        device_menu_loop(dev_list, ecode=user["ecode"], sid=user["sid"], gid=user["gid"], days_range=args.days, debug=debug)

    except SystemExit:
        # Let argparse/sys.exit pass through (cleanup happens in finally)
        raise
    except Exception:
        traceback.print_exc()
        if log_path:
            print(f"[!] Exception occurred. For details, check the log file: {log_path}")
        else:
            print("[!] Exception occurred.")
    finally:
        if log_f and old_stdout and old_stderr:
            teardown_smartlife_logging(log_f, old_stdout, old_stderr)


def run_smartlife(case_info):
    """
    Wrapper entry point for being called from an integrated main menu.
    Uses interactive input instead of argparse to gather required arguments.

    ✅ Folder layout:
      - <case_root>/smartlife_log
      - <case_root>/smartlife_download
    """

    global SMARTLIFE_ROOT, DOWNLOAD_DIR, LOG_DIR

    log_dir = os.path.join(case_info.case_root, "smartlife_log")
    dl_dir  = os.path.join(case_info.case_root, "smartlife_download")

    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(dl_dir, exist_ok=True)

    SMARTLIFE_ROOT = case_info.case_root
    LOG_DIR = log_dir
    DOWNLOAD_DIR = dl_dir

    log_f = None
    old_stdout = old_stderr = None
    log_path = None

    try:
        # ✅ Create smartlife_log/<timestamp>.log for each run and apply tee logging
        log_f, log_path, _log_lock, old_stdout, old_stderr = setup_smartlife_logging(LOG_DIR)

        print("[*] SmartLife Case Root :", SMARTLIFE_ROOT)
        print("[*] Log Dir             :", LOG_DIR)
        print("[*] Download Dir        :", DOWNLOAD_DIR)

        email = input("SmartLife Email: ").strip()
        password = input("SmartLife Password: ").strip()
        if not email or not password:
            print("[INFO] email/password is empty.")
            return

        country = input("Country code (default=1): ").strip() or "1"
        gid = input("GID (blank=auto): ").strip()
        days_str = input("Days range (default=60): ").strip()
        days = int(days_str) if days_str.isdigit() else 60

        debug = True  # ✅ Always keep debug logs in the file (dlog prevents console output)

        tok = api_get_token(email, country, debug=debug)
        if not tok.get("result_decrypted"):
            print("\n[ERROR] token.get decryption failed")
            return

        login_res = api_login_email_password_fixed(email, password, tok, country, debug=debug)
        login_dec = login_res.get("result_decrypted")
        check_login_or_die(login_dec)

        user = extract_login_user_fields(login_dec)
        if not (user.get("ecode") and user.get("sid")):
            print("[ERROR] ecode/sid missing in login response")
            return

        home = api_home_space_list(user["ecode"], user["sid"], v=V_HOME_LIST, debug=debug)
        home_dec = home.get("result_decrypted") or home.get("json", {}).get("result")
        auto_gid = extract_gid_from_home_list(home_dec)

        gid_final = gid or (auto_gid or "")
        user["gid"] = gid_final

        print_user_info(user)

        if gid_final:
            _ = api_group_device_sort_list(user["ecode"], user["sid"], gid_final, debug=debug)

            gl = api_group_device_list(user["ecode"], user["sid"], gid_final, debug=debug)
            payload = gl.get("result_decrypted") or gl.get("json", {}).get("result")
            payload = unwrap_result(payload)
            dev_list = payload if isinstance(payload, list) else []

            device_menu_loop(dev_list, ecode=user["ecode"], sid=user["sid"], gid=user["gid"], days_range=days, debug=debug)
        else:
            print("[WARN] Could not find gid. You may need to provide it via --gid.")

    except Exception:
        traceback.print_exc()
        if log_path:
            print(f"[!] Exception occurred. For details, check the log file: {log_path}")
        else:
            print("[!] Exception occurred.")
    finally:
        if log_f and old_stdout and old_stderr:
            teardown_smartlife_logging(log_f, old_stdout, old_stderr)
