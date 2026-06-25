"""Native mobile / desktop app clients.

Not a browser and not a crawler: a first-party app making requests through a
platform networking stack (Apple's CFNetwork, Flutter's dart:io, …) or a named
networking framework. The User-Agent names the stack, not a browser engine, so
these otherwise fall through to UNKNOWN despite being ordinary app traffic.
"""

from __future__ import annotations

import re
from functools import lru_cache

from ..dataload import load_list
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier
from .tags import identifies_as_known_agent

_APP_TOKENS = re.compile("|".join(re.escape(token) for token in load_list("app_clients")), re.I)


@lru_cache(maxsize=16384)
def app_stack_token(ua: str | None) -> str | None:
    """The native-app networking token in the UA, or None."""
    if not ua:
        return None
    match = _APP_TOKENS.search(ua)
    return match.group(0) if match else None


class AppClientClassifier(Classifier):
    label = Kind.APP
    name = "app"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        # A platform networking stack is the *weakest* identity: if the UA also
        # names a feed reader, crawler, or bot, that more specific identity wins
        # (a feed reader on CFNetwork is a feed reader, not just "an app").
        if identifies_as_known_agent(features):
            return []
        token = app_stack_token(features.user_agent)
        if token is None:
            return []
        # A platform networking stack is an unambiguous native-app identity, so one
        # match is enough to carry it past the unknown threshold on its own.
        return [self._signal(0.65, [f"native-app networking stack in User-Agent ({token})"])]
