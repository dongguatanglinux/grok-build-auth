# -*- coding: utf-8 -*-
"""SSO session-cookie extraction for x.ai account sign-up.

After ``create_account`` succeeds, the RSC response body contains a JWT chain URL
that kicks off cross-domain SSO cookie propagation.  This module follows that chain
(HTTP only, no browser) and extracts the ``sso`` cookie — a JWT carrying a
``session_id``.

Usage::

    from xconsole_client.sso import SSOExtractor, parse_sso_jwt_payload

    res = client.create_account(...)
    extractor = SSOExtractor(client._t, client._base_headers, debug=True)
    sso_token = extractor.extract(res.rsc_body)
    if sso_token:
        print(parse_sso_jwt_payload(sso_token))   # {"session_id": "..."}

Protocol (reverse-engineered from the live flow, 2026-06-29):
    1. Parse the first JWT URL from the RSC body (``...set-cookie?q=<JWT>``).
    2. Decode the JWT payload — it carries a ``success_url`` pointing to
       ``auth.grokusercontent.com/set-cookie?q=<next-JWT>``.
    3. GET that URL.  The endpoint replies **303** but first sets the ``sso``
       cookie on ``.grok.com`` via ``Set-Cookie``.
    4. Read ``sso`` from the transport cookie jar.

The old 3-hop fan-out (grokipedia → grokusercontent → grok.com) is partially
decommissioned; only the ``grokusercontent`` hop is still functional.
"""
from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import config as C


# --------------------------------------------------------------------------- #
# public helpers
# --------------------------------------------------------------------------- #

def parse_sso_jwt_url(rsc_body: str) -> Optional[str]:
    """Return the first SSO ``set-cookie?q=<JWT>`` URL found in *rsc_body*."""
    m = re.search(
        r'https?://[^\s"\'<>]+set-cookie\?q='
        r'(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
        rsc_body,
    )
    return m.group(0) if m else None


def parse_jwt_payload(jwt: str) -> Optional[Dict[str, Any]]:
    """Decode the payload segment of a JWT (no signature verification)."""
    try:
        parts = jwt.split(".")
        if len(parts) < 2:
            return None
        raw = parts[1]
        raw += "=" * (4 - len(raw) % 4)
        return json.loads(base64.urlsafe_b64decode(raw))
    except Exception:
        return None


def parse_sso_jwt_payload(sso_token: str) -> Optional[Dict[str, Any]]:
    """Decode the ``sso`` cookie JWT payload (e.g. ``{"session_id":"..."}``)."""
    return parse_jwt_payload(sso_token)


def parse_sso_from_set_cookies(set_cookies: List[str]) -> Optional[str]:
    """Extract an ``sso=<JWT>`` value from raw Set-Cookie header strings."""
    if not set_cookies:
        return None
    for sc in set_cookies:
        if not sc:
            continue
        # Match sso=<jwt> at cookie start or after a comma-joined boundary.
        m = re.search(
            r'(?:^|,\s*)sso=(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
            sc,
            flags=re.IGNORECASE,
        )
        if m:
            return m.group(1)
    return None


def _extract_jwt_from_url(url: str) -> Optional[str]:
    """Pull the ``q=<JWT>`` parameter out of a set-cookie URL."""
    m = re.search(
        r'q=(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)', url
    )
    return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# SSOExtractor
# --------------------------------------------------------------------------- #

# Type for the transport request method:
#   (method, url, *, headers, body) -> (status, resp_headers, set_cookies, raw_bytes)
TransportRequest = Callable[
    [str, str, Dict[str, str], Optional[bytes]],
    Tuple[int, Dict[str, str], List[str], bytes],
]

# Type for base-headers factory: () -> Dict[str, str]
HeadersFactory = Callable[[], Dict[str, str]]

# Type for cookie-jar accessor (callable or property-like object)
CookieJarSource = Any


class SSOExtractor:
    """Follow the SSO cookie chain and return the ``sso`` token.

    Parameters
    ----------
    transport_request:
        A callable matching the signature of ``XConsoleAuthClient._request``
        (or ``FingerprintTransport.request``).  It is used to make the single
        GET to ``auth.grokusercontent.com/set-cookie``.
    base_headers:
        A zero-arg callable that returns a dict of common browser headers
        (like ``XConsoleAuthClient._base_headers``).
    cookie_jar:
        The cookie jar object attached to the transport.  Must have a ``.jar``
        attribute that is iterable, yielding objects with ``.name`` / ``.value``
        attributes (``curl_cffi.requests.cookies.Cookies`` satisfies this).
    debug:
        Print progress lines.
    """

    GROKUSERCONTENT_SET_COOKIE = "https://auth.grokusercontent.com/set-cookie"

    def __init__(
        self,
        transport_request: TransportRequest,
        base_headers: HeadersFactory,
        cookie_jar: CookieJarSource,
        *,
        debug: bool = False,
    ) -> None:
        self._request = transport_request
        self._base_headers = base_headers
        self._cookies = cookie_jar
        self.debug = debug

    # ----------------------------------------------------------------- public

    def extract(
        self,
        rsc_body: str,
        *,
        email: str = "",
        password: str = "",
        save: bool = False,
        output_dir: Optional[str | Path] = None,
    ) -> Optional[str]:
        """Extract the ``sso`` cookie value from *rsc_body*.

        *rsc_body* is the ``.rsc_body`` attribute of the ``SignupResult``
        returned by ``XConsoleAuthClient.create_account()``.

        If *save* is ``True`` (or *email* is provided), the token is
        persisted to ``<xconsole>/sso_output/sso_<timestamp>.json``
        via :func:`save_sso`.

        Returns the ``sso`` JWT string, or ``None`` if extraction fails.
        """
        # 1. find the JWT chain URL in the RSC body
        sso_url = parse_sso_jwt_url(rsc_body)
        if not sso_url:
            if self.debug:
                print("  [sso] no JWT set-cookie URL in RSC body")
            return None

        if self.debug:
            print(f"  [sso] JWT URL: {sso_url[:80]}...")

        # 2. decode the JWT to find the next hop (grokusercontent)
        jwt = _extract_jwt_from_url(sso_url)
        if not jwt:
            if self.debug:
                print("  [sso] could not extract JWT from URL")
            return None

        success_url = self._resolve_success_url(jwt)
        if self.debug:
            print(f"  [sso] success_url: {success_url[:80]}...")

        # 3. hit the grokusercontent endpoint (retry once on transport errors)
        headers = self._base_headers()
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "referer": C.ACCOUNTS_ORIGIN + "/",
        })
        set_cookies: List[str] = []
        last_exc: Optional[BaseException] = None
        for attempt in range(2):
            try:
                _status, _hdrs, set_cookies, _raw = self._request(
                    "GET", success_url, headers=headers, body=None,
                )
                last_exc = None
                if self.debug:
                    print(
                        f"  [sso] set-cookie hop HTTP {_status}, "
                        f"set-cookies={len(set_cookies or [])}"
                    )
                break
            except TypeError:
                # Some transports accept headers as keyword-only without body=.
                try:
                    _status, _hdrs, set_cookies, _raw = self._request(
                        "GET", success_url, headers=headers,
                    )
                    last_exc = None
                    break
                except Exception as exc:
                    last_exc = exc
            except Exception as exc:
                last_exc = exc
                if self.debug:
                    print(f"  [sso] request failed (attempt {attempt + 1}): {exc}")
                if attempt == 0:
                    import time as _time
                    _time.sleep(0.4)
        if last_exc is not None:
            if self.debug:
                print(f"  [sso] request failed: {last_exc}")
            return None

        # 4. prefer Set-Cookie header, then cookie jar
        token = parse_sso_from_set_cookies(set_cookies or []) or self._read_sso_from_jar()

        # 5. persist if requested
        if token and (save or email):
            path = save_sso(token, email=email, password=password,
                            output_dir=output_dir)
            if self.debug:
                print(f"  [sso] saved to: {path}")

        return token

    # ----------------------------------------------------------------- internal

    def _resolve_success_url(self, jwt: str) -> str:
        """Decode *jwt* and return its ``success_url``, falling back to
        the hard-coded ``auth.grokusercontent.com/set-cookie``."""
        payload = parse_jwt_payload(jwt)
        if payload:
            cfg = payload.get("config", {})
            url = cfg.get("success_url")
            if isinstance(url, str) and url.startswith("https://"):
                return url
        return self.GROKUSERCONTENT_SET_COOKIE

    def _read_sso_from_jar(self) -> Optional[str]:
        """Scan the transport cookie jar for an ``sso`` cookie."""
        cj = self._cookies
        if hasattr(cj, "jar"):
            for cookie in cj.jar:
                name = str(getattr(cookie, "name", ""))
                if name == "sso":
                    val = str(getattr(cookie, "value", ""))
                    if self.debug:
                        print(f"  [sso] extracted: {val[:60]}...")
                    return val
        return None


# --------------------------------------------------------------------------- #
# SSO persistence — save extracted tokens to a dedicated directory
# --------------------------------------------------------------------------- #

# Default output directory, resolved relative to the xconsole repo root.
def _default_output_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "sso_output"


def save_sso(
    token: str,
    *,
    email: str = "",
    password: str = "",
    output_dir: Optional[str | Path] = None,
) -> Path:
    """Save an extracted SSO token to a JSON file.

    Each file is named ``sso_<timestamp>.json`` and contains::

        {
            "email": "...",
            "password": "...",
            "sso": "eyJ...",
            "created_at": "2026-06-29T14:30:00Z"
        }

    Args:
        token: The ``sso`` cookie value (JWT string).
        email: Associated email address (optional, for bookkeeping).
        password: Associated password (optional, for bookkeeping).
        output_dir: Target directory.  Defaults to ``<xconsole>/sso_output/``.

    Returns:
        The path to the written file.
    """
    target = Path(output_dir) if output_dir else _default_output_dir()
    target.mkdir(parents=True, exist_ok=True)

    # Microsecond + short email salt so concurrent writers don't clobber.
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    email_slug = ""
    if email:
        email_slug = "_" + re.sub(r"[^a-zA-Z0-9._-]+", "_", email.split("@")[0])[:24]
    filename = f"sso_{ts}{email_slug}.json"
    record: Dict[str, Any] = {
        "email": email,
        "password": password,
        "sso": token,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    # If the JWT is decodable, include the payload for convenience.
    payload = parse_sso_jwt_payload(token)
    if payload:
        record["payload"] = payload

    filepath = target / filename
    filepath.write_text(
        json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return filepath


def list_saved_tokens(output_dir: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    """Load all saved SSO records from the output directory.

    Returns a list of dicts (newest first), or an empty list if the directory
    does not exist or is empty.
    """
    target = Path(output_dir) if output_dir else _default_output_dir()
    if not target.is_dir():
        return []
    records: List[Dict[str, Any]] = []
    for f in sorted(target.glob("sso_*.json"), reverse=True):
        try:
            records.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return records
