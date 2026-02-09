#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import hashlib
import requests
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse, parse_qs
import sys
import re


# -------------------------
# Helpers
# -------------------------
def md5_upper(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest().upper()


def now_ms() -> int:
    return int(time.time() * 1000)


def strip_xiaomi_prefix(text: str) -> str:
    prefix = "&&&START&&&"
    t = text.strip()
    if t.startswith(prefix):
        t = t[len(prefix):].lstrip()
    return t


def parse_xiaomi_json(text: str) -> Dict[str, Any]:
    return json.loads(strip_xiaomi_prefix(text))


def extract_query_param(url: str, key: str) -> Optional[str]:
    q = parse_qs(urlparse(url).query)
    vals = q.get(key)
    return vals[0] if vals else None


def split_set_cookie_header(sc: str) -> List[str]:
    """
    Handle cases where requests merges multiple Set-Cookie headers into a single string.
    Keep commas inside values such as "Expires=Tue, 03-Mar-...".
    Only split on the delimiter pattern: ", <cookieName>=".
    """
    if not sc:
        return []
    return [p.strip() for p in re.split(r",(?=\s*[A-Za-z0-9_]+=)", sc) if p.strip()]


# -------------------------
# Data models
# -------------------------
@dataclass
class CookieToken:
    name: str
    value: str
    domain: Optional[str] = None
    path: Optional[str] = None


def extract_cookie_token_from_headers(headers: dict, cookie_name: str) -> Optional[CookieToken]:
    """
    Extract the cookie value, Domain, and Path for cookie_name from headers['Set-Cookie'].
    """
    sc = headers.get("Set-Cookie")
    if not sc:
        return None

    parts = split_set_cookie_header(sc)
    for p in parts:
        first = p.split(";", 1)[0].strip()
        if not first.startswith(cookie_name + "="):
            continue

        value = first.split("=", 1)[1]
        domain = None
        path = None

        attrs = [a.strip() for a in p.split(";")[1:]]
        for a in attrs:
            al = a.lower()
            if al.startswith("domain="):
                domain = a.split("=", 1)[1]
            elif al.startswith("path="):
                path = a.split("=", 1)[1]

        return CookieToken(name=cookie_name, value=value, domain=domain, path=path)

    return None


@dataclass
class Step1Context:
    qs: str
    sid: str
    callback: str
    sign: str
    location: str

    @staticmethod
    def from_step1_response(d: dict) -> "Step1Context":
        return Step1Context(
            qs=d.get("qs", ""),
            sid=d.get("sid", ""),
            callback=d.get("callback", ""),
            sign=d.get("_sign", ""),
            location=d.get("location", ""),
        )


@dataclass
class Step2Result:
    result: str
    code: int
    description: str
    securityStatus: int
    notificationUrl: Optional[str]
    location: str

    @staticmethod
    def from_step2_response(d: dict) -> "Step2Result":
        return Step2Result(
            result=d.get("result", ""),
            code=int(d.get("code", -1)),
            description=d.get("description", d.get("desc", "")),
            securityStatus=int(d.get("securityStatus", -1)),
            notificationUrl=d.get("notificationUrl"),
            location=d.get("location", ""),
        )


@dataclass
class Step3Result:
    notification_url: str
    context: str
    http_status: int


@dataclass
class Step5Result:
    raw: Dict[str, Any]
    identity_session: Optional[CookieToken]


@dataclass
class Step6Result:
    raw: Dict[str, Any]
    maskedEmail: Optional[str]
    contentType: Optional[int]


@dataclass
class Step7Result:
    raw: Dict[str, Any]
    code: int
    desc: str


@dataclass
class Step8Result:
    raw: Dict[str, Any]
    code: int
    location: Optional[str]


@dataclass
class Step9Result:
    http_status: int
    location: Optional[str]
    headers: Dict[str, Any]


@dataclass
class Step10Result:
    http_status: int
    location: Optional[str]           # URL from Step 11
    passToken: Optional[CookieToken]  # Extracted from Set-Cookie
    userId: Optional[int]             # Extracted from Set-Cookie
    cUserId: Optional[str]            # Extracted from Set-Cookie
    headers: Dict[str, Any]


@dataclass
class Step11Result:
    http_status: int
    serviceToken: Optional[CookieToken]  # Extracted from Set-Cookie
    headers: Dict[str, Any]


# ---- Common result for Steps 12–15 ----
@dataclass
class Step12to15ServiceLoginResult:
    raw: Dict[str, Any]
    sid: str
    code: int
    ssecurity: Optional[str]
    cUserId: Optional[str]
    userId: Optional[int]
    location: Optional[str]


# ---- Step 16 result: call location for each sid and store domain/serviceToken ----
@dataclass
class Step16STSResultItem:
    sid: str
    http_status: int
    location: str
    serviceToken: Optional[CookieToken]
    headers: Dict[str, Any]


@dataclass
class Step16Result:
    items: List[Step16STSResultItem]
    service_tokens_by_domain: Dict[str, CookieToken]  # domain -> serviceToken


# -------------------------
# Xiaomi login client
# -------------------------
class XiaomiLoginClient:
    BASE = "https://account.xiaomi.com"

    def __init__(self, device_id: str, timeout: int = 25, verify_tls: bool = True):
        self.device_id = device_id
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.sess = requests.Session()

        self.common_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Accept": "*/*",
        }

    def _headers_cookie_step1(self, user_id_cookie: str) -> dict:
        h = dict(self.common_headers)
        h["Cookie"] = f"userId={user_id_cookie}; deviceId={self.device_id}"
        return h

    def _headers_cookie_device_only(self) -> dict:
        h = dict(self.common_headers)
        h["Cookie"] = f"deviceId={self.device_id}"
        return h

    def _headers_cookie_with_identity_session(self, identity_session) -> dict:
        v = identity_session.value if isinstance(identity_session, CookieToken) else identity_session
        h = dict(self.common_headers)
        h["Cookie"] = f"deviceId={self.device_id}; identity_session={v}"
        return h

    def _headers_cookie_device_passtoken_userid(self, pass_token, user_id: int) -> dict:
        """
        Steps 12–15: Build Cookie header with deviceId + passToken + userId.
        pass_token: str or CookieToken
        """
        v = pass_token.value if isinstance(pass_token, CookieToken) else pass_token
        h = dict(self.common_headers)
        h["Cookie"] = f"deviceId={self.device_id}; passToken={v}; userId={user_id}"
        return h

    def _headers_no_cookie(self) -> dict:
        return dict(self.common_headers)

    # 1) GET serviceLogin
    def step1_service_login(self, user_id_cookie: str, locale: str = "en_US", sid: str = "xiaomiio") -> Step1Context:
        url = f"{self.BASE}/pass/serviceLogin"
        params = {"_json": "true", "sid": sid, "_locale": locale}

        r = self.sess.get(url, params=params, headers=self._headers_cookie_step1(user_id_cookie),
                          timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()

        data = parse_xiaomi_json(r.text)
        ctx = Step1Context.from_step1_response(data)

        missing = [k for k, v in {
            "qs": ctx.qs, "sid": ctx.sid, "callback": ctx.callback, "_sign": ctx.sign, "location": ctx.location
        }.items() if not v]
        if missing:
            raise RuntimeError(
                f"[STEP1] missing fields: {missing} | raw_code={data.get('code')} desc={data.get('description') or data.get('desc')}"
            )
        return ctx

    # 2) POST serviceLoginAuth2
    def step2_service_login_auth2(self, ctx: Step1Context, user: str, password: str, locale: str = "en_US") -> Step2Result:
        url = f"{self.BASE}/pass/serviceLoginAuth2"

        headers = self._headers_cookie_device_only()
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        form = {
            "qs": ctx.qs,
            "callback": ctx.callback,
            "_sign": ctx.sign,
            "sid": ctx.sid,
            "_json": "true",
            "user": user,
            "hash": md5_upper(password),
            "_locale": locale,
        }

        r = self.sess.post(url, data=form, headers=headers, timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()

        data = parse_xiaomi_json(r.text)
        return Step2Result.from_step2_response(data)

    # 3) GET notificationUrl (extract context)
    def step3_open_notification_url(self, notification_url: str) -> Step3Result:
        context = extract_query_param(notification_url, "context")
        if not context:
            raise RuntimeError("[STEP3] The notificationUrl does not contain a 'context' parameter.")

        r = self.sess.get(notification_url, headers=self._headers_cookie_device_only(),
                          timeout=self.timeout, verify=self.verify_tls, allow_redirects=True)
        return Step3Result(notification_url=notification_url, context=context, http_status=r.status_code)

    # 4) GET pass2/config
    def step4_get_pass2_config(self, locale: str = "en_US", sid: str = "xiaomiio", u_region: str = "") -> Dict[str, Any]:
        url = f"{self.BASE}/pass2/config"
        params: List[Tuple[str, str]] = [
            ("key", "login"),
            ("key", "register"),
            ("_locale", locale),
            ("sid", sid),
            ("_uRegion", u_region),
        ]
        r = self.sess.get(url, params=params, headers=self._headers_cookie_device_only(),
                          timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()

        txt = r.text.strip()
        try:
            return parse_xiaomi_json(txt)
        except Exception:
            return json.loads(txt)

    # 5) GET identity/list + extract identity_session from Set-Cookie
    def step5_identity_list(self, context: str, sid: str = "xiaomiio", supported_mask: int = 0) -> Step5Result:
        url = f"{self.BASE}/identity/list"
        params = {"sid": sid, "supportedMask": str(supported_mask), "context": context}

        r = self.sess.get(url, params=params, headers=self._headers_cookie_device_only(),
                          timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()

        data = parse_xiaomi_json(r.text)

        identity_session = extract_cookie_token_from_headers(r.headers, "identity_session")
        if not identity_session:
            v = data.get("identity_session")
            if v:
                identity_session = CookieToken(name="identity_session", value=v)

        return Step5Result(raw=data, identity_session=identity_session)

    # 6) GET verifyEmail?_flag=8&_json=true
    def step6_verify_email(self, identity_session, flag: int = 8) -> Step6Result:
        url = f"{self.BASE}/identity/auth/verifyEmail"
        params = {"_flag": str(flag), "_json": "true"}

        r = self.sess.get(url, params=params,
                          headers=self._headers_cookie_with_identity_session(identity_session),
                          timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()

        data = parse_xiaomi_json(r.text)
        return Step6Result(
            raw=data,
            maskedEmail=data.get("maskedEmail"),
            contentType=data.get("contentType"),
        )

    # 7) POST sendEmailTicket?_dc=<now_ms>
    def step7_send_email_ticket(self, identity_session, retry: int = 0) -> Step7Result:
        url = f"{self.BASE}/identity/auth/sendEmailTicket"
        params = {"_dc": str(now_ms())}

        headers = self._headers_cookie_with_identity_session(identity_session)
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        form = {
            "retry": str(retry),
            "icode": "",
            "_json": "true",
        }

        r = self.sess.post(url, params=params, data=form, headers=headers,
                           timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()

        data = parse_xiaomi_json(r.text)
        return Step7Result(
            raw=data,
            code=int(data.get("code", -1)),
            desc=data.get("desc", data.get("description", "")),
        )

    # 8) POST verifyEmail?_dc=<now_ms> (verify after entering the ticket)
    def step8_verify_email(self, identity_session, ticket: str, flag: int = 8) -> Step8Result:
        url = f"{self.BASE}/identity/auth/verifyEmail"
        params = {"_dc": str(now_ms())}

        headers = self._headers_cookie_with_identity_session(identity_session)
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        form = {
            "_flag": str(flag),
            "ticket": ticket,
            "trust": "false",
            "_json": "true",
        }

        r = self.sess.post(url, params=params, data=form, headers=headers,
                           timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()

        data = parse_xiaomi_json(r.text)
        return Step8Result(
            raw=data,
            code=int(data.get("code", -1)),
            location=data.get("location"),
        )

    # 9) GET Step8.location -> response header "Location" contains Step10 URL
    def step9_request_location(self, identity_session, url: str) -> Step9Result:
        headers = self._headers_cookie_with_identity_session(identity_session)

        r = self.sess.get(url, headers=headers,
                          timeout=self.timeout, verify=self.verify_tls, allow_redirects=False)

        loc = r.headers.get("Location")
        return Step9Result(
            http_status=r.status_code,
            location=loc,
            headers=dict(r.headers),
        )

    # 10) GET Step9.location (pass/serviceLoginAuth2/end...) with Cookie: deviceId only
    #     - response has Location(for step11)
    #     - Set-Cookie has passToken + userId + cUserId
    def step10_service_login_auth2_end(self, url: str) -> Step10Result:
        headers = self._headers_cookie_device_only()

        r = self.sess.get(url, headers=headers,
                          timeout=self.timeout, verify=self.verify_tls, allow_redirects=False)

        loc = r.headers.get("Location")

        passtoken = extract_cookie_token_from_headers(r.headers, "passToken")
        user_id_tok = extract_cookie_token_from_headers(r.headers, "userId")
        cuser_id_tok = extract_cookie_token_from_headers(r.headers, "cUserId")

        user_id_val: Optional[int] = None
        if user_id_tok and user_id_tok.value:
            try:
                user_id_val = int(user_id_tok.value)
            except Exception:
                user_id_val = None

        cuser_id_val: Optional[str] = cuser_id_tok.value if (cuser_id_tok and cuser_id_tok.value) else None

        return Step10Result(
            http_status=r.status_code,
            location=loc,
            passToken=passtoken,
            userId=user_id_val,
            cUserId=cuser_id_val,
            headers=dict(r.headers),
        )

    # 11) GET Step10.location (STS URL), extract serviceToken from Set-Cookie
    def step11_sts_get_service_token(self, url: str) -> Step11Result:
        headers = self._headers_no_cookie()

        r = self.sess.get(url, headers=headers,
                          timeout=self.timeout, verify=self.verify_tls, allow_redirects=False)

        service_token = extract_cookie_token_from_headers(r.headers, "serviceToken")

        return Step11Result(
            http_status=r.status_code,
            serviceToken=service_token,
            headers=dict(r.headers),
        )

    # 12~15) GET /pass/serviceLogin?_json=true&appName=com.xiaomi.smarthome&sid=<sid>&_locale=en_US
    #        Cookie: passToken + deviceId + userId
    def step12to15_service_login_smarthome(self, pass_token, user_id: int, sid: str, locale: str = "en_US") -> Step12to15ServiceLoginResult:
        url = f"{self.BASE}/pass/serviceLogin"
        params = {
            "_json": "true",
            "appName": "com.xiaomi.smarthome",
            "sid": sid,
            "_locale": locale,
        }

        headers = self._headers_cookie_device_passtoken_userid(pass_token, user_id=user_id)

        r = self.sess.get(url, params=params, headers=headers,
                          timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()

        data = parse_xiaomi_json(r.text)
        return Step12to15ServiceLoginResult(
            raw=data,
            sid=sid,
            code=int(data.get("code", -1)),
            ssecurity=data.get("ssecurity"),
            cUserId=data.get("cUserId"),
            userId=int(data.get("userId")) if data.get("userId") is not None else None,
            location=data.get("location"),
        )

    # 16) Call each location URL returned from Steps 12–15
    #     - Include deviceId in the Cookie header
    #     - Extract and store domain + serviceToken from Set-Cookie

    def step16_call_locations_and_collect_service_tokens(self, locations_by_sid: Dict[str, str]) -> Step16Result:
        items: List[Step16STSResultItem] = []
        by_domain: Dict[str, CookieToken] = {}

        headers = self._headers_cookie_device_only()

        for sid, loc in locations_by_sid.items():
            if not loc:
                continue

            r = self.sess.get(
                loc,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
                allow_redirects=False
            )

            st = extract_cookie_token_from_headers(r.headers, "serviceToken")
            if st and st.domain:
                by_domain[st.domain] = st

            items.append(
                Step16STSResultItem(
                    sid=sid,
                    http_status=r.status_code,
                    location=loc,
                    serviceToken=st,
                    headers=dict(r.headers),
                )
            )

        return Step16Result(items=items, service_tokens_by_domain=by_domain)

    # -------------------------
    # Convenience: run step1~16 and return (ssecurity, userId, cUserId, serviceToken)
    # -------------------------
    def run_flow_1_to_16(
        self,
        user_id_cookie: str,
        login_user: str,
        login_password: str,
        locale: str = "en_US",
    ) -> Tuple[Optional[str], Optional[int], Optional[str], CookieToken]:

        # 1~2
        s1 = self.step1_service_login(user_id_cookie=user_id_cookie, locale=locale, sid="xiaomiio")
        s2 = self.step2_service_login_auth2(s1, user=login_user, password=login_password, locale=locale)

        if not s2.notificationUrl:
            raise RuntimeError("[STEP2] notificationUrl is missing → cannot start the 2FA flow")

        # 3~5
        s3 = self.step3_open_notification_url(s2.notificationUrl)
        s5 = self.step5_identity_list(context=s3.context, sid="xiaomiio", supported_mask=0)

        if not s5.identity_session or not s5.identity_session.value:
            raise RuntimeError("[STEP5] Failed to extract identity_session")

        # 6~7
        _ = self.step6_verify_email(identity_session=s5.identity_session, flag=8)
        s7 = self.step7_send_email_ticket(identity_session=s5.identity_session, retry=0)

        if s7.code == 70022:
            raise RuntimeError("[STEP7] too many auth trial (code=70022)")

        # 8
        ticket = input("\n[STEP8] Enter the verification(ticket) sent to your email (press Enter to quit): ").strip()
        if not ticket:
            raise RuntimeError("[STEP8] No input provided")

        s8 = self.step8_verify_email(identity_session=s5.identity_session, ticket=ticket, flag=8)
        if s8.code != 0 or not s8.location:
            raise RuntimeError(f"[STEP8] Failed: code={s8.code} location={s8.location}")

        # 9
        s9 = self.step9_request_location(identity_session=s5.identity_session, url=s8.location)
        if not s9.location:
            raise RuntimeError("[STEP9] Missing Location header")

        # 10
        s10 = self.step10_service_login_auth2_end(s9.location)
        if not s10.passToken or not s10.passToken.value:
            raise RuntimeError("[STEP10] Failed to extract passToken")
        if not s10.userId:
            raise RuntimeError("[STEP10] userId is missing → cannot proceed to Steps 12–15")
        if not s10.location:
            raise RuntimeError("[STEP10] Location(Step 11 URL) is missing")

        # 11 (keep if needed)
        s11 = self.step11_sts_get_service_token(s10.location)
        if not s11.serviceToken or not s11.serviceToken.value:
            raise RuntimeError("[STEP11] Failed to extract serviceToken")

        pass_token = s10.passToken
        user_id = s10.userId

        # 12 xiaomiio
        s12 = self.step12to15_service_login_smarthome(pass_token, user_id=user_id, sid="xiaomiio", locale=locale)
        if s12.code != 0:
            raise RuntimeError(f"[STEP12] Failed: code={s12.code}")

        final_ssecurity = s12.ssecurity
        final_userId = s12.userId
        final_cUserId = s12.cUserId

        # 16 (xiaomiio location first)
        step16_first = self.step16_call_locations_and_collect_service_tokens({"xiaomiio": s12.location or ""})

        # ✅ Key fix: Step16Result does not contain a serviceToken field
        # 1) Prefer api.device.xiaomi.net
        final_serviceToken = None
        if step16_first and step16_first.service_tokens_by_domain:
            final_serviceToken = step16_first.service_tokens_by_domain.get("api.device.xiaomi.net")

        # 2) Fallback: partial match
        if not final_serviceToken and step16_first and step16_first.service_tokens_by_domain:
            for dom, tok in step16_first.service_tokens_by_domain.items():
                if dom and "api.device.xiaomi.net" in dom:
                    final_serviceToken = tok
                    break

        # 3) Fallback: use the first item token
        if not final_serviceToken and step16_first and step16_first.items:
            final_serviceToken = step16_first.items[0].serviceToken

        if not final_serviceToken or not final_serviceToken.value:
            raise RuntimeError("[STEP16] Failed to extract serviceToken")

        _ = self.step12to15_service_login_smarthome(pass_token, user_id=user_id, sid="xiaomihome", locale=locale)
        _ = self.step12to15_service_login_smarthome(pass_token, user_id=user_id, sid="passportapi", locale=locale)

        return final_ssecurity, final_userId, final_cUserId, final_serviceToken


# -------------------------
# External wrapper
# -------------------------
def run_xiaomi_2fa(deviceid: str, userid: str, password: str):
    cli = XiaomiLoginClient(device_id=deviceid, timeout=25, verify_tls=True)

    final_ssecurity, final_userId, final_cUserId, final_serviceToken = cli.run_flow_1_to_16(
        user_id_cookie=userid,
        login_user=userid,
        login_password=password,
        locale="en_US",
    )

    cookies = {
        "userId": userid,
        "deviceId": deviceid
    }

    return final_ssecurity, final_userId, final_cUserId, final_serviceToken, cookies


if __name__ == "__main__":
    # Example
    # DEVICE_ID = "android_xxx"
    # USER_ID = "your@email.com"
    # PASSWORD = "your_password"
    # print(run_xiaomi_2fa(DEVICE_ID, USER_ID, PASSWORD))
    pass
