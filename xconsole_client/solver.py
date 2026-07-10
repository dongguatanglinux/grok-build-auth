# -*- coding: utf-8 -*-
"""YesCaptcha solver integration for x.ai Console protocol.

Provides automated solving of:
  - Cloudflare Turnstile tokens
  - Castle device fingerprint tokens (via browser automation if supported)
  - Cloudflare cf_clearance cookies (via challenge page if supported)

Usage:
    from xconsole_client.solver import YesCaptchaSolver
    solver = YesCaptchaSolver(api_key="your_key")
    turnstile_token = solver.solve_turnstile(
        website_url="https://accounts.x.ai/sign-up",
        website_key="0x4XXXXXXXXXXXXXXXXX"  # extract from browser DevTools
    )

API endpoints:
  - International: https://api.yescaptcha.com
  - China domestic: https://cn.yescaptcha.com

Task types:
  - TurnstileTaskProxyless (25 points): standard Turnstile solve
  - TurnstileTaskProxylessM1 (30 points): premium tier, higher success rate
  - CloudFlareTaskS2 (25 points): 5-second challenge (experimental)
"""
from __future__ import annotations

import time
from typing import Optional

import requests


class YesCaptchaSolver:
    """YesCaptcha API client for solving CAPTCHA challenges."""

    def __init__(
        self,
        api_key: str,
        *,
        endpoint: str = "https://api.yescaptcha.com",
        timeout: float = 120.0,
        poll_interval: float = 3.0,
        debug: bool = False,
    ):
        """Initialize the solver.

        Args:
            api_key: YesCaptcha clientKey (API key)
            endpoint: API endpoint (use cn.yescaptcha.com for China)
            timeout: Maximum seconds to wait for task completion
            poll_interval: Seconds between polling attempts
            debug: Print debug output
        """
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._debug = debug

    def _create_task(self, task: dict) -> str:
        """Create a task and return the taskId. Raises on error."""
        payload = {
            "clientKey": self._api_key,
            "task": task,
        }
        if self._debug:
            print(f"  [YesCaptcha] POST {self._endpoint}/createTask")
            print(f"    task type: {task.get('type')}")

        resp = requests.post(
            f"{self._endpoint}/createTask",
            json=payload,
            timeout=30,
        )
        data = resp.json()

        if data.get("errorId", 0) != 0:
            raise RuntimeError(
                f"YesCaptcha createTask failed: "
                f"{data.get('errorCode')}: {data.get('errorDescription')}"
            )

        task_id = data.get("taskId")
        if not task_id:
            raise RuntimeError(f"YesCaptcha createTask returned no taskId: {data}")

        if self._debug:
            print(f"    taskId: {task_id}")

        return task_id

    def _get_result(self, task_id: str) -> dict:
        """Poll for task result. Returns the full response dict when ready."""
        payload = {
            "clientKey": self._api_key,
            "taskId": task_id,
        }
        if self._debug:
            print(f"  [YesCaptcha] polling getTaskResult for {task_id[:16]}...")

        deadline = time.time() + self._timeout
        while time.time() < deadline:
            resp = requests.post(
                f"{self._endpoint}/getTaskResult",
                json=payload,
                timeout=30,
            )
            data = resp.json()

            if data.get("errorId", 0) != 0:
                raise RuntimeError(
                    f"YesCaptcha getTaskResult error: "
                    f"{data.get('errorCode')}: {data.get('errorDescription')}"
                )

            status = data.get("status")
            if status == "ready":
                if self._debug:
                    print(f"    solved in ~{int(time.time() - (deadline - self._timeout))}s")
                return data
            elif status == "processing":
                if self._debug:
                    print(f"    still processing, waiting {self._poll_interval}s...")
                time.sleep(self._poll_interval)
            else:
                raise RuntimeError(f"YesCaptcha unexpected status: {status}")

        raise TimeoutError(
            f"YesCaptcha task {task_id} did not complete within {self._timeout}s"
        )

    def solve_turnstile(
        self,
        website_url: str,
        website_key: str,
        *,
        premium: bool = False,
    ) -> str:
        """Solve a Cloudflare Turnstile challenge and return the token.

        Args:
            website_url: The page URL where Turnstile is embedded
            website_key: The Turnstile sitekey (format: 0x4...)
            premium: Use TurnstileTaskProxylessM1 (higher success rate, costs more)

        Returns:
            The Turnstile token string (valid for ~120s)

        Raises:
            RuntimeError: If the solver fails or returns an error
            TimeoutError: If the task exceeds the timeout
        """
        task_type = "TurnstileTaskProxylessM1" if premium else "TurnstileTaskProxyless"
        task = {
            "type": task_type,
            "websiteURL": website_url,
            "websiteKey": website_key,
        }

        task_id = self._create_task(task)
        result = self._get_result(task_id)

        solution = result.get("solution", {})
        token = solution.get("token")
        if not token:
            raise RuntimeError(f"YesCaptcha returned no token: {result}")

        return token

    def solve_cloudflare_challenge(
        self,
        website_url: str,
        website_key: Optional[str] = None,
    ) -> dict:
        """Solve a Cloudflare 5-second challenge (experimental).

        Args:
            website_url: The URL that triggers the Cloudflare challenge
            website_key: Optional sitekey if applicable

        Returns:
            A dict with 'cf_clearance' cookie value and other challenge cookies

        Raises:
            RuntimeError: If the solver fails
            TimeoutError: If the task exceeds the timeout

        Note:
            This uses CloudFlareTaskS2 which is in testing phase.
            For managed challenges (like cf_clearance on auth.grok.com),
            this may not work reliably.
        """
        task = {
            "type": "CloudFlareTaskS2",
            "websiteURL": website_url,
        }
        if website_key:
            task["websiteKey"] = website_key

        task_id = self._create_task(task)
        result = self._get_result(task_id)

        solution = result.get("solution", {})
        if not solution:
            raise RuntimeError(f"YesCaptcha returned no solution: {result}")

        return solution

    def solve_castle(self, website_url: str) -> str:
        """Solve a Castle device fingerprint challenge.

        Note:
            YesCaptcha does not have a dedicated Castle task type.
            Castle tokens are typically generated by running the Castle JS SDK
            in a real browser environment. This method raises NotImplementedError.

            Workaround: Use a headless browser (Puppeteer/Playwright) to load
            the Castle SDK and extract the request token.
        """
        raise NotImplementedError(
            "YesCaptcha does not support Castle device fingerprint tokens. "
            "Castle tokens must be generated by running the Castle JS SDK in a browser. "
            "Consider using Puppeteer/Playwright to load https://castlesdk.io and extract the token."
        )


# --------------------------------------------------------------------------- #
# Convenience factory
# --------------------------------------------------------------------------- #
def create_solver(api_key: Optional[str] = None, **kwargs) -> YesCaptchaSolver:
    """Create a YesCaptchaSolver instance.

    If api_key is not provided, reads from YESCAPTCHA_API_KEY environment variable.
    """
    import os
    key = api_key or os.environ.get("YESCAPTCHA_API_KEY")
    if not key:
        raise ValueError(
            "YesCaptcha API key required. Pass api_key= or set YESCAPTCHA_API_KEY env var."
        )
    return YesCaptchaSolver(key, **kwargs)
