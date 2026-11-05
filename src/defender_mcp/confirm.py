"""Two-step confirmation for admin actions.

First call (no token): the tool returns a preview and a short-lived HMAC token bound to
action + target + parameters + user. Second call with the token executes. The token proves
that the executed action is exactly the previewed one and comes from the same user; it does
not prove that a human clicked - keep admin tools in a separate agent with a small audience."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Awaitable, Callable, Optional

from . import runtime
from .auth.identity import user_key
from .errors import ConfirmationError

NEXT_STEP = ("Show this preview to the user and ask for explicit confirmation. Only after a clear 'yes', "
             "call the same tool again with identical arguments plus confirmation_token. "
             "Never confirm on the user's behalf.")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def params_digest(params: dict) -> str:
    raw = json.dumps(params, sort_keys=True, default=str, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()[:32]


class Confirmer:
    def __init__(self, key: bytes, ttl_seconds: int = 300, clock: Callable[[], float] = time.time) -> None:
        self._key = key
        self.ttl = ttl_seconds
        self._clock = clock

    def _sign(self, raw: bytes) -> bytes:
        return hmac.new(self._key, raw, hashlib.sha256).digest()[:20]

    def issue(self, action: str, target: str, params: dict, user: str) -> str:
        payload = {"a": action, "t": target, "h": params_digest(params), "u": user or "",
                   "e": int(self._clock() + self.ttl), "n": secrets.token_hex(6)}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return f"{_b64e(raw)}.{_b64e(self._sign(raw))}"

    def verify(self, token: str, action: str, target: str, params: dict, user: str) -> None:
        try:
            raw_part, sig_part = token.strip().split(".", 1)
            raw, sig = _b64d(raw_part), _b64d(sig_part)
        except Exception:  # noqa: BLE001
            raise ConfirmationError("Invalid confirmation_token. Request a new preview (call without token).") from None
        if not hmac.compare_digest(sig, self._sign(raw)):
            raise ConfirmationError("Invalid confirmation_token. Request a new preview (call without token).")
        payload = json.loads(raw)
        if int(payload.get("e", 0)) < self._clock():
            raise ConfirmationError("confirmation_token expired. Request a new preview and confirm again.")
        if payload.get("u", "") != (user or ""):
            raise ConfirmationError("confirmation_token was issued to a different user.")
        if (payload.get("a"), payload.get("t"), payload.get("h")) != (action, target, params_digest(params)):
            raise ConfirmationError("confirmation_token does not match this action, target or arguments. "
                                    "Request a new preview.")


async def two_step(*, action: str, target: str, params: dict, token: Optional[str],
                   preview: Callable[[], Awaitable[dict]], execute: Callable[[], Awaitable[dict]]) -> dict:
    confirmer: Confirmer = runtime.get().confirmer
    user = user_key()
    if not token:
        details = await preview()
        return {
            "status": "confirmation_required",
            "action": action,
            "preview": details,
            "confirmation_token": confirmer.issue(action, target, params, user),
            "expires_in_seconds": confirmer.ttl,
            "next_step": NEXT_STEP,
        }
    confirmer.verify(token, action, target, params, user)
    result: dict[str, Any] = await execute()
    return {"status": "done", "action": action, **result}
