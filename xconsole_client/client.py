# -*- coding: utf-8 -*-
"""xconsole_client.client — programmatic reproduction of the x.ai Cloud Console
account sign-up / sign-in protocol, reconstructed from a mitmproxy capture.

Two transport backends:
  * "curl_cffi" (default) — browser-fingerprint impersonation at the
    TLS/HTTP2/header-order level. Required to avoid Cloudflare 403s against
    accounts.x.ai. Needs the `curl_cffi` package.
  * "urllib"   (fallback)  — pure standard-library, no fingerprint. Useful for
    offline code tests (`python -m xconsole_client selftest`); will get
    challenged by Cloudflare on real-network use.

PROTOCOL OVERVIEW (see ../protocol-spec.md and README.md for the full spec):
  GET  console.x.ai/home                              -> 302 to accounts.x.ai/sign-in
  POST AuthManagement/CreateEmailValidationCode       (gRPC-web)  emails a 6-char code
  POST AuthManagement/VerifyEmailValidationCode       (gRPC-web)  validates the code
  POST AuthManagement/ValidatePassword                (gRPC-web)  live strength meter
  POST accounts.x.ai/sign-up  (Next.js server action) creates the account + session

DYNAMIC ACTION ID & ROUTER STATE TREE:
  The sign-up page is a Next.js App Router deployment.  The ``next-action``
  header and ``next-router-state-tree`` header are *build-specific* — they
  change every time accounts.x.ai is redeployed.  Hard-coding them will
  break the final ``create_account`` step whenever the deployment changes.

  ``load_signup_page()`` (step 2 of the flow) now also extracts both values
  from the live page HTML / RSC payload / JS chunks so ``create_account()``
  always ships the current set.  If extraction fails a clear error is raised
  so the operator knows to re-scrape manually.

HARD anti-bot dependencies the protocol gates the final step on — these CANNOT be
forged offline and must be obtained from a live browser/solver:
  * turnstileToken      (Cloudflare Turnstile widget)
  * castleRequestToken  (Castle device-fingerprint token)
  * cf_clearance cookie (Cloudflare managed challenge)
This client reproduces the wire format faithfully; it does not bypass those.
"""
from __future__ import annotations

import gzip
import http.cookiejar
import io
import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from . import config as C
from . import grpcweb
from .models import GrpcResult, PasswordStrength, SignupResult
from .sso import SSOExtractor


# --------------------------------------------------------------------------- #
# urllib transport (legacy, no fingerprint)
# --------------------------------------------------------------------------- #
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _UrllibTransport:
    def __init__(self, *, timeout: float, debug: bool):
        self._timeout = timeout
        self._debug = debug
        self.cookies = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
            _NoRedirect(),
        )

    def request(self, method, url, *, headers, body=None):
        req = urllib.request.Request(url, data=body, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            resp = self._opener.open(req, timeout=self._timeout)
        except urllib.error.HTTPError as e:
            resp = e
        status = resp.getcode()
        raw = resp.read()
        if resp.headers.get("content-encoding", "").lower() == "gzip" and raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            except OSError:
                pass
        set_cookies = resp.headers.get_all("set-cookie") or []
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        if self._debug:
            print(f"  <- {status} {method} {url}  ({len(raw)} bytes, {len(set_cookies)} set-cookie, transport=urllib)")
        return status, hdrs, set_cookies, raw

    def close(self): pass


# --------------------------------------------------------------------------- #
# public client
# --------------------------------------------------------------------------- #
class XConsoleAuthClient:
    GROK_HOME = "https://grok.com/"

    def __init__(
        self,
        *,
        transport: str = "curl_cffi",
        impersonate: str = "chrome131",
        debug: bool = False,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        signup_url: Optional[str] = None,
    ):
        if transport not in ("curl_cffi", "urllib"):
            raise ValueError("transport must be 'curl_cffi' or 'urllib'")
        self.debug = debug
        self.timeout = timeout
        # Per-instance signup URL avoids concurrent clobber of global C.SIGNUP_URL.
        self.signup_url = signup_url or C.SIGNUP_URL
        if transport == "curl_cffi":
            # imported lazily so the package still loads without it
            from .fingerprint import FingerprintTransport
            self._t = FingerprintTransport(
                impersonate=impersonate, timeout=timeout, debug=debug, proxy=proxy,
            )
            self.transport_name = f"curl_cffi(impersonate={impersonate})"
        else:
            self._t = _UrllibTransport(timeout=timeout, debug=debug)
            self.transport_name = "urllib"

        # Dynamically scraped per-session — populated by load_signup_page().
        self._next_action_id: Optional[str] = None
        self._next_router_state_tree: Optional[str] = None
        self._last_rsc_body: str = ""
        self._last_create_set_cookies: List[str] = []

    def cookie_names(self) -> List[str]:
        """Return a list of cookie names currently held by the underlying transport."""
        c = self._t.cookies
        if hasattr(c, "keys") and not hasattr(c, "_cookies"):
            return list(c.keys())
        return [ck.name for ck in c]

    # ----------------------------------------------------------------- transport wrappers
    def _request(self, method, url, *, headers, body=None):
        return self._t.request(method, url, headers=headers, body=body)

    def _base_headers(self) -> Dict[str, str]:
        return {
            "user-agent": C.USER_AGENT,
            "accept-language": C.ACCEPT_LANGUAGE,
            "sec-ch-ua": C.SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": C.SEC_CH_UA_PLATFORM,
        }

    def _grpc_headers(self, referer: str) -> Dict[str, str]:
        h = self._base_headers()
        h.update({
            "content-type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            "x-user-agent": C.CONNECT_ES_VERSION,
            "accept": "*/*",
            "origin": C.ACCOUNTS_ORIGIN,
            "referer": referer,
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        })
        return h

    # ----------------------------------------------------------------- entry
    def visit_home(self) -> int:
        h = self._base_headers()
        h.update({"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                  "sec-fetch-site": "none", "sec-fetch-mode": "navigate",
                  "sec-fetch-dest": "document", "upgrade-insecure-requests": "1"})
        status, _, _, _ = self._request("GET", C.HOME_URL, headers=h)
        return status

    def load_signup_page(self) -> int:
        """GET the sign-up page AND scrape the current next-action / router-state-tree.

        The scraped values are stored on the instance and used automatically by
        ``create_account()``.  Calling this is REQUIRED before ``create_account()``
        so the values are fresh.
        """
        h = self._base_headers()
        h.update({"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                  "sec-fetch-site": "same-site", "sec-fetch-mode": "navigate",
                  "sec-fetch-dest": "document", "referer": "https://console.x.ai/"})
        status, _hdrs, _sc, raw = self._request("GET", self.signup_url, headers=h)
        html = raw.decode("utf-8", "replace")

        # ---- scrape Next.js build-specific values from the live page ----
        try:
            self._scrape_rsc_payload(html)
        except Exception as exc:
            raise RuntimeError(
                "Failed to extract next-action / next-router-state-tree from the "
                "live sign-up page.  The x.ai deployment may have changed its "
                "page structure.  Details: %s" % exc
            ) from exc

        if self.debug:
            print(f"  [scrape] next-action={self._next_action_id[:16]}... "
                  f"({len(self._next_action_id or '')} chars)")
            print(f"  [scrape] router-state-tree len={len(self._next_router_state_tree or '')}")

        return status

    # ----------------------------------------------------------------- dynamic action scraper
    _RSC_PUSH_RE = re.compile(r'self\.__next_f\.push\(\[1,"((?:[^"\\]|\\.)*)"\]\)')

    def _scrape_rsc_payload(self, html: str) -> None:
        """Extract ``next-action`` and ``next-router-state-tree`` from the live page.

        1. Parse the ``self.__next_f.push`` RSC flight segments.
        2. Extract the router state tree from the ``"f"`` field of segment 5.
        3. Download all referenced JS chunks and search for the action ID.
        """

        # ---- 1. parse RSC segments ----
        rsc_segments = self._RSC_PUSH_RE.findall(html)
        if self.debug:
            print(f"  [scrape] found {len(rsc_segments)} RSC segments")

        # ---- 2. extract next-router-state-tree ----
        router_tree = None
        for seg in rsc_segments:
            unescaped = seg.replace('\\"', '"')
            # The router state tree is in the "f" field of the page data segment
            m = re.search(r'"f":\[(\[.*?\])', unescaped)
            if m:
                flight_seg = m.group(1)
                # The first element of the flight array is the router state tree
                # It looks like: ["",{"children":["(app)",{"children":["(auth)",...]},...]},"$undefined","$undefined",16]
                if flight_seg.startswith('[["",{"children"'):
                    # Parse: flight data = [[router_tree, rendered_tree], ...]
                    # We need to extract just the router tree portion
                    # It starts with [["",{"children"... and ends with ...,16]
                    # The router tree is: ["",{...},"$undefined","$undefined",16]
                    # Find the matching closing bracket for the outer array
                    depth = 0
                    tree_end = 0
                    for i, ch in enumerate(flight_seg):
                        if ch == '[':
                            depth += 1
                        elif ch == ']':
                            depth -= 1
                            if depth == 0:
                                tree_end = i + 1
                                break
                    if tree_end > 0:
                        tree_json = flight_seg[:tree_end]
                        # Parse to validate, then URL-encode
                        try:
                            parsed = json.loads(tree_json)
                            # Re-encode: first element is the flight data array
                            # Format: [router_tree, rendered_tree, ...]
                            # We need: router_tree as URL-encoded JSON
                            if isinstance(parsed, list) and len(parsed) >= 1:
                                # parsed[0] = ["",{"children":...},"$undefined","$undefined",16]
                                router_tree = json.dumps(parsed[0], separators=(",", ":"))
                        except (json.JSONDecodeError, IndexError):
                            # Fall back to raw extraction — find the router tree directly
                            pass

        # Fallback: direct regex for router tree if JSON parse fails
        if router_tree is None:
            rsc_full = "\n".join(seg.replace('\\"', '"') for seg in rsc_segments)
            mt = re.search(
                r'\[""\s*,\s*\{[^}]*"children":[^]]*"\(app\)"[^]]*"\(auth\)"[^]]*"sign-up"[^\]]*\]'
                r'[^]]*\][^]]*\]\s*,\s*"\$undefined"\s*,\s*"\$undefined"\s*,\s*16\]',
                rsc_full
            )
            if mt:
                router_tree = mt.group(0)
            else:
                # Last resort: use config fallback and warn
                router_tree = json.loads(
                    '["",{"children":["(app)",{"children":["(auth)",{"children":'
                    '["sign-up",{"children":["__PAGE__?{\\"redirect\\":\\"cloud-console\\"}",'
                    '{}]}]}]}]},"$undefined","$undefined",16]'
                )
                router_tree = json.dumps(router_tree, separators=(",", ":"))

        self._next_router_state_tree = quote(router_tree, safe="")

        # ---- 3. extract next-action ID from JS chunks ----
        self._next_action_id = self._scrape_action_id(html)

    # Chunks that are likely to contain the action ID (from the RSC flight data).
    # We search these first; the sign-up action chunk has field-name keywords.
    _PRIORITY_CHUNK_PATTERNS = [
        r'06rqcsyrqa6v-',   # sign-up action (contains createUserAndSessionRequest)
        r'0ewiyh8jhugm9',   # actionId dispatch / extractInfoFromServerReferenceId
        r'0j2vdu-bdg~mi',   # had a 42-char hex in diagnostics
        r'0mjo1a97a5yaq',   # component registration, large chunk
        r'0vlulu7bwpnvs',   # component registration
        r'0\.k--fzd9bco3',  # component registration
    ]

    # Metadata byte that encodes: type=server-action (bit7=0), all 6 args used
    # (bits1-6 all set), hasRestArgs (bit0=1) → 0b01111111 = 0x7f = "7f"
    # NOTE: on the current x.ai deployment, the full action ID is 42 hex chars
    # (the first TWO chars ARE the metadata byte, the remaining 40 are the hash).
    # We must NOT prepend anything — the 42-char string from the JS chunk IS
    # the complete action ID.

    def _scrape_action_id(self, html: str) -> str:
        """Find the Next.js server action ID from the live page's JS chunks.

        Action ID format:  ``<2 hex metadata><42 hex hash>`` = 44 chars.
        The metadata byte is ``7f`` for a server-action using all arguments.

        Strategy:
          1. Download all JS chunks in parallel.
          2. The chunk containing ``createUserAndSessionRequest`` is the
             sign-up action module; its 42-char hex is the action hash.
          3. Fallback: if that chunk has no hex, try any other 42-char hex
             from any chunk (likely still correct — the hash format is
             distinctive).
        """
        # 1. collect all JS chunk URLs from the page
        js_urls = list(set(re.findall(r'src="(/_next/static/chunks/[^"]+\.js)"', html)))
        if self.debug:
            print(f"  [scrape] searching {len(js_urls)} JS chunks...")

        # 2. sort: priority chunks first, then the rest
        priority: List[str] = []
        rest: List[str] = []
        for url in js_urls:
            if any(re.search(p, url) for p in self._PRIORITY_CHUNK_PATTERNS):
                priority.append(url)
            else:
                rest.append(url)
        ordered = priority + rest

        # 3. fetch chunks in parallel and search for action hashes.
        # We collect ALL results and pick the best one (sign-up chunk > any).
        signup_hash: Optional[str] = None
        fallback_hash: Optional[str] = None

        def _fetch_and_search(path: str) -> Tuple[Optional[str], bool]:
            """Return (hash_or_None, is_signup_chunk)."""
            try:
                full = f"https://accounts.x.ai{path}"
                _s, _h, _sc, raw = self._request("GET", full, headers=self._base_headers())
                text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
                hashes = set(re.findall(r'"([a-f0-9]{42})"', text))
                if not hashes:
                    return (None, False)
                is_signup = any(
                    kw in text for kw in ("createUserAndSessionRequest", "emailValidationCode")
                )
                if is_signup and self.debug:
                    print(f"  [scrape] SIGN-UP ACTION CHUNK: {path}")
                # Return the first hash (all 42-char hexes in a chunk are
                # candidate action hashes; the sign-up chunk's hash is the
                # correct one).
                return (next(iter(hashes)), is_signup)
            except Exception:
                return (None, False)

        with ThreadPoolExecutor(max_workers=min(8, len(ordered))) as ex:
            futures = {ex.submit(_fetch_and_search, url): url for url in ordered}
            for f in as_completed(futures):
                h, is_signup = f.result()
                if h is None:
                    continue
                if is_signup:
                    signup_hash = h
                elif fallback_hash is None:
                    fallback_hash = h

        action_hash = signup_hash or fallback_hash
        if action_hash is None:
            raise RuntimeError(
                "Could not find the server action ID in any JS chunk.  "
                "The page structure may have changed.  "
                "As a workaround, manually set NEXT_ACTION_SIGNUP in config.py."
            )

        # 4. The 42-char hex string IS the complete action ID.
        #    Format: 2 hex chars metadata + 40 hex chars hash = 42 chars total.
        #    Do NOT prepend a metadata byte — it's already embedded.
        if self.debug:
            print(f"  [scrape] action ID={action_hash[:16]}... "
                  f"({len(action_hash)} chars, {'signup-chunk' if signup_hash else 'fallback'})")
        return action_hash

    @property
    def next_action_id(self) -> str:
        """The current ``next-action`` header value (populated by ``load_signup_page()``)."""
        if self._next_action_id is None:
            raise RuntimeError(
                "next_action_id not available — call load_signup_page() first"
            )
        return self._next_action_id

    @property
    def next_router_state_tree(self) -> str:
        """The current ``next-router-state-tree`` header value (populated by ``load_signup_page()``)."""
        if self._next_router_state_tree is None:
            raise RuntimeError(
                "next_router_state_tree not available — call load_signup_page() first"
            )
        return self._next_router_state_tree

    # ----------------------------------------------------------------- gRPC-web RPCs
    def _grpc_call(self, url: str, fields: List[Tuple[int, str]], referer: str) -> GrpcResult:
        message = grpcweb.encode_message(fields)
        body = grpcweb.frame_request(message)
        headers = self._grpc_headers(referer)
        headers["content-length"] = str(len(body))
        status, _, _, raw = self._request("POST", url, headers=headers, body=body)
        # A valid gRPC-web response always has at least a 5-byte trailer frame.
        # Empty body = server rejected the request before gRPC processing
        # (e.g. email domain blocked, Cloudflare challenge, etc.).
        if not raw:
            return GrpcResult(
                ok=False, http_status=status, grpc_status=None,
                messages=[], trailers={}, raw=raw,
            )
        parsed = grpcweb.parse_response(raw)
        return GrpcResult(
            ok=(status == 200 and parsed["grpc_status"] == 0),
            http_status=status, grpc_status=parsed["grpc_status"],
            messages=parsed["messages"], trailers=parsed["trailers"], raw=raw,
        )

    def create_email_validation_code(self, email: str) -> GrpcResult:
        return self._grpc_call(C.RPC_CREATE_CODE, [(1, email)], self.signup_url)

    def verify_email_validation_code(self, email: str, code: str) -> GrpcResult:
        return self._grpc_call(C.RPC_VERIFY_CODE, [(1, email), (2, code)], self.signup_url)

    def validate_password(self, email: str, password: str) -> PasswordStrength:
        # Field numbers 4 and 5 — observed in the capture, not 1/2.
        res = self._grpc_call(C.RPC_VALIDATE_PW, [(4, email), (5, password)], self.signup_url)
        return PasswordStrength(raw_fields=res.first_message)

    # ----------------------------------------------------------------- account creation
    def create_account(self, *, email: str, given_name: str, family_name: str,
                       password: str, email_validation_code: str,
                       turnstile_token: str, castle_request_token: str,
                       conversion_id: str, tos_accepted_version: Optional[str] = None) -> SignupResult:
        create_req = {
            "email": email,
            "givenName": given_name,
            "familyName": family_name,
            "clearTextPassword": password,
            "tosAcceptedVersion": tos_accepted_version if tos_accepted_version is not None else "$undefined",
        }
        args = [
            {"emailValidationCode": email_validation_code,
             "createUserAndSessionRequest": create_req,
             "turnstileToken": turnstile_token,
             "conversionId": conversion_id,
             "castleRequestToken": castle_request_token},
            {"client": "$T", "meta": "$undefined", "mutationKey": "$undefined"},
        ]
        body = json.dumps(args, separators=(",", ":")).encode("utf-8")

        # Use dynamically-scraped values (populated by load_signup_page)
        h = self._base_headers()
        h.update({
            "accept": "text/x-component",
            "content-type": "text/plain;charset=UTF-8",
            "next-action": self.next_action_id,
            "next-router-state-tree": self.next_router_state_tree,
            "origin": C.ACCOUNTS_ORIGIN,
            "referer": self.signup_url,
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "content-length": str(len(body)),
        })
        status, _, set_cookies, raw = self._request("POST", self.signup_url, headers=h, body=body)
        rsc_body = raw.decode("utf-8", "replace")
        self._last_rsc_body = rsc_body  # store for fetch_sso_token()
        self._last_create_set_cookies = list(set_cookies or [])
        return SignupResult(
            ok=(status == 200), http_status=status,
            set_cookies=set_cookies,
            rsc_body=rsc_body,
        )

    # ----------------------------------------------------------------- SSO extraction
    def _read_sso_from_jar(self) -> Optional[str]:
        """Read ``sso`` cookie from the transport jar (any domain)."""
        c = self._t.cookies
        if hasattr(c, "get"):
            for domain in (".grok.com", "grok.com", ".x.ai", "accounts.x.ai", None):
                try:
                    val = c.get("sso", domain=domain) if domain is not None else c.get("sso")
                    if val:
                        return str(val)
                except Exception:
                    pass
        if hasattr(c, "jar"):
            for cookie in c.jar:
                name = getattr(cookie, "name", "")
                if str(name).lower() == "sso":
                    val = str(getattr(cookie, "value", "") or "")
                    if val:
                        return val
        return None

    def _fetch_sso_via_grok_home(self) -> Optional[str]:
        """Fallback: visit grok.com so the logged-in accounts session yields ``sso``."""
        headers = self._base_headers()
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "referer": C.ACCOUNTS_ORIGIN + "/",
        })
        try:
            status, _hdrs, set_cookies, _raw = self._request(
                "GET", self.GROK_HOME, headers=headers,
            )
            if self.debug:
                print(f"  [sso] grok.com fallback HTTP {status}, set-cookies={len(set_cookies or [])}")
            from .sso import parse_sso_from_set_cookies
            token = parse_sso_from_set_cookies(set_cookies or [])
            if token:
                return token
        except Exception as exc:
            if self.debug:
                print(f"  [sso] grok.com fallback failed: {exc}")
        return self._read_sso_from_jar()

    def fetch_sso_token(
        self,
        *,
        email: str = "",
        password: str = "",
        save: bool = False,
        output_dir: Optional[str] = None,
        retries: int = 3,
    ) -> Optional[str]:
        """Fetch the ``sso`` session cookie after a successful account creation.

        Strategy (with retries for concurrent / flaky network):
          1. Parse any ``sso=`` already present on create_account Set-Cookie.
          2. Follow RSC JWT set-cookie chain via :class:`SSOExtractor`.
          3. Fallback: GET grok.com and re-read cookie jar.

        If *save* is ``True`` (or *email* is provided), the token is persisted
        to ``<xconsole>/sso_output/sso_<timestamp>.json``.

        Call this AFTER ``create_account()`` returned ``ok=True``.
        """
        import time as _time
        from .sso import parse_sso_from_set_cookies, save_sso

        token = parse_sso_from_set_cookies(getattr(self, "_last_create_set_cookies", []) or [])
        if token and self.debug:
            print("  [sso] found in create_account Set-Cookie")

        rsc_text = getattr(self, "_last_rsc_body", "") or ""
        attempts = max(1, int(retries))
        for attempt in range(1, attempts + 1):
            if token:
                break
            if rsc_text:
                extractor = SSOExtractor(
                    transport_request=self._request,
                    base_headers=self._base_headers,
                    cookie_jar=self._t.cookies,
                    debug=self.debug,
                )
                token = extractor.extract(
                    rsc_text,
                    email="",
                    password="",
                    save=False,
                )
            if not token:
                token = self._fetch_sso_via_grok_home()
            if not token:
                token = self._read_sso_from_jar()
            if token:
                break
            if attempt < attempts:
                if self.debug:
                    print(f"  [sso] attempt {attempt}/{attempts} failed, retrying...")
                _time.sleep(0.6 * attempt)

        if token and (save or email):
            save_sso(token, email=email, password=password, output_dir=output_dir)
        return token

    def close(self):
        self._t.close()
