"""MCP over SLIM — the encrypted fabric between agents and the gateway (P3).

TrustSec analogy: the SLIM node is the switch fabric and MLS is MACsec. Agents and the
gateway dial OUT to the node (no inbound ports), open a point-to-point session, and
every MCP JSON-RPC message rides one MLS-encrypted SLIM message, so the node forwards
ciphertext only.

Identity: JWT mode — each app signs its own token with its private key; the receiving
app checks it against a trust JWKS. SLIM does NOT bind key<->name or routing
name<->subject (docs/P3-design.md §1), so this module only REPORTS who the peer is
(`SlimPeer`, pinned per session); the gate's `peer` check decides (PR3).

Verified against slim-bindings 3.3.6 (core 3.4.5) and mcp 2.3. Pattern from
agntcy/slim-mcp-python, which pins mcp 1.26 / bindings 1.4 and disables MLS.
"""
from __future__ import annotations

import contextvars
import datetime
import json
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any

import anyio
import mcp_types
import slim_bindings as sb
from mcp.shared.message import SessionMessage

from agenttrustsec.models import TransportPeer

log = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "http://127.0.0.1:46357"
ISSUER = "agenttrustsec-lab"
AUDIENCE = ["agenttrustsec"]
PEER_SUBJECT = "slim-peer-subject"
FIRST_MESSAGE_TIMEOUT = datetime.timedelta(seconds=30)


# Who is on the other end as SLIM reports it (SLIM checked the token vs the trust JWKS).
SlimPeer = TransportPeer


# The verified peer of the SLIM session serving the current MCP request (gateway side).
PEER: contextvars.ContextVar[SlimPeer | None] = contextvars.ContextVar("slim_peer", default=None)


class PeerChanged(Exception):
    """A message in a pinned session came from a different identity. Session is dropped."""


def jwt_identity(private_key_pem: str, subject: str, trust_jwks: list[dict[str, str]], *,
                 issuer: str = ISSUER, audience: list[str] = AUDIENCE,
                 ttl: datetime.timedelta = datetime.timedelta(hours=1)) -> tuple[Any, Any]:
    """(provider, verifier) for SLIM JWT identity: sign with our key, trust only `trust_jwks`."""
    if not trust_jwks:
        raise ValueError("empty trust JWKS would trust no one — refusing")
    if any(k.get("alg") != "RS256" for k in trust_jwks):
        # SLIM silently ignores keys without alg -> fail loudly instead (identity/keys.trust_jwk)
        raise ValueError("every trust JWK needs alg=RS256 (SLIM ignores keys without it)")
    enc = sb.JwtKeyConfig(algorithm=sb.JwtAlgorithm.RS256, format=sb.JwtKeyFormat.PEM,
                          key=sb.JwtKeyData.DATA(value=private_key_pem))
    dec = sb.JwtKeyConfig(algorithm=sb.JwtAlgorithm.RS256, format=sb.JwtKeyFormat.JWKS,
                          key=sb.JwtKeyData.DATA(value=json.dumps({"keys": trust_jwks})))
    provider = sb.IdentityProviderConfig.JWT(config=sb.ClientJwtAuth(
        key=sb.JwtKeyType.ENCODING(key=enc), audience=audience, issuer=issuer,
        subject=subject, duration=ttl))
    verifier = sb.IdentityVerifierConfig.JWT(config=sb.JwtAuth(
        key=sb.JwtKeyType.DECODING(key=dec), audience=audience, issuer=issuer,
        subject=None, duration=ttl))
    return provider, verifier


_service: Any = None
_connections: dict[str, int] = {}


def _get_service() -> Any:
    global _service
    if _service is None:
        sb.initialize_with_configs(tracing_config=sb.new_tracing_config(),
                                   runtime_config=sb.new_runtime_config(),
                                   service_config=[sb.new_service_config()])
        _service = sb.get_global_service()
    return _service


@dataclass
class SlimEndpoint:
    app: Any
    conn_id: int
    name: str


async def connect(local_name: str, identity: tuple[Any, Any],
                  endpoint: str = DEFAULT_ENDPOINT) -> SlimEndpoint:
    """Create a SLIM app under `local_name` with JWT `identity` and dial OUT to the node."""
    svc = _get_service()
    if endpoint not in _connections:
        _connections[endpoint] = await svc.connect_async(sb.new_insecure_client_config(endpoint))
    conn = _connections[endpoint]
    name = sb.Name.from_string(local_name)
    app = svc.create_app(name, *identity)
    await app.subscribe_async(name, conn)
    return SlimEndpoint(app=app, conn_id=conn, name=local_name)


def peer_of(ctx: Any) -> SlimPeer:
    return SlimPeer(source_name=str(ctx.source_name),
                    subject=(ctx.metadata or {}).get(PEER_SUBJECT, ""),
                    token=ctx.identity or "")


def _session_config(mls: bool, max_retries: int, interval: datetime.timedelta) -> Any:
    return sb.SessionConfig(
        session_type=sb.SessionType.POINT_TO_POINT, max_retries=max_retries,
        interval=interval, metadata={},
        mls_settings=sb.MlsSettings(header_integrity_validation_percent=100,
                                    max_seen_control_message_ids_size=None) if mls else None)


def _parse(payload: bytes) -> SessionMessage | Exception:
    try:
        return SessionMessage(mcp_types.jsonrpc_message_adapter.validate_json(payload, by_name=False))
    except ValueError as exc:
        log.warning("dropping non-JSON-RPC SLIM payload: %s", exc)
        return exc


@asynccontextmanager
async def _bridge(session: Any, *, pin: Callable[[SlimPeer], None],
                  first: Any = None) -> AsyncIterator[tuple[Any, Any]]:
    """SLIM session <-> MCP (read, write) streams. One JSON-RPC message per SLIM message."""
    read_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_stream, write_reader = anyio.create_memory_object_stream[SessionMessage](0)

    async def deliver(msg: Any) -> None:
        pin(peer_of(msg.context))           # raises PeerChanged on an identity switch
        await read_writer.send(_parse(msg.payload))

    async def reader() -> None:
        async with read_writer:
            try:
                if first is not None:
                    await deliver(first)
                while True:
                    await deliver(await session.get_message_async(timeout=None))
            except PeerChanged as exc:
                log.error("SLIM session dropped: %s", exc)
                await read_writer.send(exc)
            except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                pass
            except Exception as exc:  # noqa: BLE001 - session closed / transport error ends it
                if "closed" not in str(exc).lower():
                    log.warning("SLIM receive failed: %s", exc)

    async def writer() -> None:
        async with write_reader:
            async for sm in write_reader:
                data = sm.message.model_dump_json(by_alias=True, exclude_unset=True).encode()
                completion = await session.publish_async(data, None, None)
                await completion.wait_async()

    async with anyio.create_task_group() as tg:
        tg.start_soon(reader)
        tg.start_soon(writer)
        try:
            yield read_stream, write_stream
        finally:
            tg.cancel_scope.cancel()


def _pinner(on_first: Callable[[SlimPeer], None] | None = None) -> Callable[[SlimPeer], None]:
    pinned: list[SlimPeer] = []

    def pin(peer: SlimPeer) -> None:
        if not pinned:
            pinned.append(peer)
            if on_first:
                on_first(peer)
        elif (peer.subject, peer.source_name) != (pinned[0].subject, pinned[0].source_name):
            raise PeerChanged(f"peer changed mid-session: {pinned[0].subject!r} -> {peer.subject!r}")
    return pin


class SlimClientTransport:
    """mcp `Transport`: an MLS point-to-point SLIM session to `remote` (e.g. the gateway).

    After the first reply, `.peer` holds the remote's identity as SLIM reported it — the
    agent side checks it against the gateway's key binding (PR4)."""

    def __init__(self, endpoint: SlimEndpoint, remote: str, *, mls: bool = True,
                 max_retries: int = 3, interval: datetime.timedelta = datetime.timedelta(seconds=2)):
        self.endpoint = endpoint
        self.remote = remote
        self.mls = mls
        self.max_retries = max_retries
        self.interval = interval
        self.peer: SlimPeer | None = None
        self._stack: AsyncExitStack | None = None

    async def __aenter__(self) -> tuple[Any, Any]:
        app, conn = self.endpoint.app, self.endpoint.conn_id
        remote = sb.Name.from_string(self.remote)
        await app.set_route_async(remote, conn)
        ctx = await app.create_session_async(
            _session_config(self.mls, self.max_retries, self.interval), remote)
        await ctx.completion.wait_async()
        session = ctx.session
        self._stack = AsyncExitStack()
        self._stack.push_async_callback(self._delete, session)
        return await self._stack.enter_async_context(
            _bridge(session, pin=_pinner(lambda p: setattr(self, "peer", p))))

    async def __aexit__(self, *exc: Any) -> None:
        if self._stack is not None:
            await self._stack.aclose()

    async def _delete(self, session: Any) -> None:
        try:
            handle = await self.endpoint.app.delete_session_async(session)
            await handle.wait_async()
        except Exception as e:  # noqa: BLE001 - best-effort teardown
            log.debug("SLIM session delete: %s", e)


async def serve_slim(server: Any, endpoint: SlimEndpoint) -> None:
    """Serve an MCPServer on every inbound SLIM session until cancelled.

    Each session's peer is pinned from its first message and exposed via `PEER` to the
    middleware (GateMiddleware) for every request in that session."""
    low = server._lowlevel_server  # same access the mcp Client uses for in-process servers
    async with anyio.create_task_group() as tg:
        while True:
            session = await endpoint.app.listen_for_session_async(None)
            tg.start_soon(_serve_session, low, session)


async def _serve_session(low: Any, session: Any) -> None:
    try:
        first = await session.get_message_async(timeout=FIRST_MESSAGE_TIMEOUT)
        peer = peer_of(first.context)
        PEER.set(peer)      # this task's context; request handlers spawned below inherit it
        async with _bridge(session, pin=_pinner(), first=first) as (read, write):
            await low.run(read, write, low.create_initialization_options())
    except Exception as e:  # noqa: BLE001 - one bad session must not stop the gateway
        log.warning("SLIM session ended: %s", e)
