"""The transport peer of the request being served — vendor-neutral, so the gate never
imports a transport SDK. Set per session by the transport (transport/slim.py)."""
from __future__ import annotations

import contextvars

from agenttrustsec.models import TransportPeer

CURRENT_PEER: contextvars.ContextVar[TransportPeer | None] = contextvars.ContextVar(
    "transport_peer", default=None)
