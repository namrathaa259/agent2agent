"""
MOQT Agent Server
Replaces A2AStarletteApplication + uvicorn for each friend agent.

Architecture
────────────
  QUIC connection (TLS 1.3, ALPN "moq-00")
      │
      ├── Control stream (bidi stream-0): MOQT handshake + subscribe/announce
      └── Data streams  (client uni):     OBJECT_STREAM carrying JSON-RPC requests

The server bridges incoming MOQT objects to the existing A2A DefaultRequestHandler
via an in-process ASGI call (httpx.ASGITransport).  This means the full a2a-sdk
stack (AgentExecutor, TaskStore, etc.) continues to work unchanged — only the
transport layer is swapped.

Discovery
─────────
When the host subscribes to the discovery track, the server immediately publishes
the AgentCard JSON as an OBJECT_STREAM so the host can build its remote-agent map.
"""

import asyncio
import logging
from typing import Optional

import httpx
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
)

from .protocol import (
    A2A_NAMESPACE,
    MOQT_ALPN,
    MOQT_VERSION,
    MsgType,
    Announce,
    AnnounceOk,
    ClientSetup,
    ObjectStream,
    ServerSetup,
    Subscribe,
    SubscribeNamespace,
    SubscribeNamespaceOk,
    SubscribeOk,
    decode_varint,
    parse_control_message,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# QUIC / MOQT session (one per client connection)
# ---------------------------------------------------------------------------

class MOQTAgentSession(QuicConnectionProtocol):
    """
    MOQT protocol handler for a single inbound QUIC connection.

    Each connected host gets one instance.  MOQT control messages arrive on
    the first client-initiated bidirectional stream (stream-id 0); request
    objects arrive on client-initiated unidirectional streams (ids 2, 6, …).
    """

    def __init__(
        self,
        quic,
        stream_handler=None,
        *,
        asgi_client: httpx.AsyncClient,
        agent_card_json: str,
    ):
        super().__init__(quic, stream_handler)
        self._asgi_client = asgi_client
        self._agent_card_json = agent_card_json

        # Control-stream receive buffer
        self._ctrl_buf: bytes = b""
        self._setup_done: bool = False

        # subscribe_id → (namespace, track_name, track_alias)
        self._subs: dict[int, tuple[list[str], str, int]] = {}
        # Per-subscription object-id counter
        self._obj_counters: dict[int, int] = {}

    # ------------------------------------------------------------------
    # aioquic event dispatch
    # ------------------------------------------------------------------

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            logger.debug("MOQT server: QUIC handshake complete")

        elif isinstance(event, StreamDataReceived):
            sid = event.stream_id
            # QUIC stream-ID semantics (RFC 9000 §2.1):
            #   sid % 4 == 0  → client-initiated bidirectional  (control)
            #   sid % 4 == 2  → client-initiated unidirectional (data / requests)
            if sid % 4 == 0:
                self._on_control_data(sid, event.data)
            elif sid % 4 == 2:
                asyncio.ensure_future(self._on_request_stream(event.data))

        elif isinstance(event, ConnectionTerminated):
            logger.info("MOQT server: connection terminated")

    # ------------------------------------------------------------------
    # Control-stream handling
    # ------------------------------------------------------------------

    def _on_control_data(self, stream_id: int, data: bytes) -> None:
        self._ctrl_buf += data
        while self._ctrl_buf:
            try:
                msg_type, payload, consumed = parse_control_message(self._ctrl_buf)
                self._ctrl_buf = self._ctrl_buf[consumed:]
                self._handle_control(stream_id, msg_type, payload)
            except BufferError:
                break  # wait for more bytes
            except Exception as exc:
                logger.error("MOQT server control error: %s", exc, exc_info=True)
                break

    def _handle_control(
        self, stream_id: int, msg_type: MsgType, payload: bytes
    ) -> None:
        logger.debug("MOQT server ← %s", msg_type.name)

        if msg_type == MsgType.CLIENT_SETUP:
            cs = ClientSetup.decode(payload)
            ver = (
                MOQT_VERSION
                if MOQT_VERSION in cs.supported_versions
                else cs.supported_versions[0]
            )
            # SERVER_SETUP
            self._ctrl_send(stream_id, ServerSetup(selected_version=ver).encode())
            self._setup_done = True
            # Announce A2A namespaces we publish on
            self._ctrl_send(stream_id, Announce(namespace=["a2a"]).encode())
            self._ctrl_send(stream_id, Announce(namespace=["a2a", "discovery"]).encode())
            self.transmit()
            logger.info("MOQT server: setup complete — namespaces announced")

        elif msg_type == MsgType.ANNOUNCE_OK:
            ack = AnnounceOk.decode(payload)
            logger.debug("MOQT server: ANNOUNCE_OK for %s", ack.namespace)

        elif msg_type == MsgType.SUBSCRIBE:
            sub = Subscribe.decode(payload)
            self._subs[sub.subscribe_id] = (
                sub.namespace,
                sub.track_name,
                sub.track_alias,
            )
            self._obj_counters[sub.subscribe_id] = 0
            self._ctrl_send(
                stream_id, SubscribeOk(subscribe_id=sub.subscribe_id).encode()
            )
            self.transmit()
            logger.info(
                "MOQT server: SUBSCRIBE %s/%s → sub_id=%d",
                sub.namespace,
                sub.track_name,
                sub.subscribe_id,
            )
            # If this is a discovery subscription, immediately publish AgentCard
            if "discovery" in sub.track_name or "discovery" in sub.namespace:
                asyncio.ensure_future(
                    self._publish_agent_card(sub.subscribe_id, sub.track_alias)
                )

        elif msg_type == MsgType.SUBSCRIBE_NAMESPACE:
            sns = SubscribeNamespace.decode(payload)
            self._ctrl_send(
                stream_id,
                SubscribeNamespaceOk(namespace_prefix=sns.namespace_prefix).encode(),
            )
            self.transmit()
            logger.info("MOQT server: SUBSCRIBE_NAMESPACE %s", sns.namespace_prefix)

    def _ctrl_send(self, stream_id: int, data: bytes) -> None:
        self._quic.send_stream_data(stream_id, data)

    # ------------------------------------------------------------------
    # Data-stream handling (incoming A2A requests)
    # ------------------------------------------------------------------

    async def _on_request_stream(self, data: bytes) -> None:
        """
        Parse an incoming OBJECT_STREAM, forward its JSON-RPC payload to the
        A2A handler via in-process ASGI, and publish the response back.
        """
        try:
            msg_type_val, offset = decode_varint(data)
            if MsgType(msg_type_val) != MsgType.OBJECT_STREAM:
                logger.warning("MOQT server: expected OBJECT_STREAM, got %d", msg_type_val)
                return

            obj = ObjectStream.decode(data[offset:])
            logger.info(
                "MOQT server: A2A request received (%d bytes)", len(obj.object_payload)
            )

            # Bridge: MOQT payload IS the JSON-RPC body (draft §3.3)
            http_resp = await self._asgi_client.post(
                "/",
                content=obj.object_payload,
                headers={"content-type": "application/json"},
            )

            # Find the response-track subscription opened by the host
            resp_sub_id, resp_alias = self._find_response_sub()
            await self._publish_object(
                subscribe_id=resp_sub_id,
                track_alias=resp_alias,
                publisher_priority=2,  # Priority 2 = real-time interaction (draft §3.4)
                payload=http_resp.content,
            )
            logger.info("MOQT server: response published (HTTP %d)", http_resp.status_code)

        except Exception as exc:
            logger.error("MOQT server: error processing request: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Publishing helpers
    # ------------------------------------------------------------------

    async def _publish_agent_card(self, subscribe_id: int, track_alias: int) -> None:
        """Publish AgentCard JSON on the discovery track."""
        await self._publish_object(
            subscribe_id=subscribe_id,
            track_alias=track_alias,
            publisher_priority=4,  # Priority 4 = discovery (draft §3.4)
            payload=self._agent_card_json.encode("utf-8"),
        )
        logger.info("MOQT server: AgentCard published on discovery track")

    async def _publish_object(
        self,
        subscribe_id: int,
        track_alias: int,
        publisher_priority: int,
        payload: bytes,
    ) -> None:
        obj_id = self._obj_counters.get(subscribe_id, 0)
        self._obj_counters[subscribe_id] = obj_id + 1

        obj = ObjectStream(
            subscribe_id=subscribe_id,
            track_alias=track_alias,
            group_id=0,
            object_id=obj_id,
            publisher_priority=publisher_priority,
            object_payload=payload,
        )
        # Server-initiated unidirectional streams: 3, 7, 11, …
        sid = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._quic.send_stream_data(sid, obj.encode(), end_stream=True)
        self.transmit()

    def _find_response_sub(self) -> tuple[int, int]:
        """Return (subscribe_id, track_alias) of the response-track subscription."""
        for sub_id, (ns, track, alias) in self._subs.items():
            if "response" in track:
                return sub_id, alias
        # Fallback to the last registered subscription
        if self._subs:
            sub_id = max(self._subs)
            return sub_id, self._subs[sub_id][2]
        return 0, 0


# ---------------------------------------------------------------------------
# High-level server — replaces A2AStarletteApplication + uvicorn.run()
# ---------------------------------------------------------------------------

class MOQTAgentServer:
    """
    Drop-in replacement for A2AStarletteApplication when using MOQT transport.

    The server reuses the existing A2A DefaultRequestHandler by routing MOQT
    requests through an in-process ASGI transport (no network round-trip).

    Usage
    -----
        server = MOQTAgentServer(
            agent_card=agent_card,
            http_handler=request_handler,   # same DefaultRequestHandler as before
            cert_file="moqt_certs/cert.pem",
            key_file="moqt_certs/key.pem",
        )
        asyncio.run(server.serve("localhost", 20002))
    """

    def __init__(
        self,
        agent_card,
        http_handler,
        cert_file: str,
        key_file: str,
    ):
        # Build the Starlette ASGI app (identical to HTTP mode)
        from a2a.server.apps import A2AStarletteApplication

        asgi_app = A2AStarletteApplication(
            agent_card=agent_card, http_handler=http_handler
        ).build()

        # In-process HTTP client — no network, no port
        self._asgi_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=asgi_app),
            base_url="http://a2a-agent",
        )
        self._agent_card_json: str = agent_card.model_dump_json()
        self._cert_file = cert_file
        self._key_file = key_file

    def _make_protocol(self, quic, stream_handler=None):
        return MOQTAgentSession(
            quic,
            stream_handler,
            asgi_client=self._asgi_client,
            agent_card_json=self._agent_card_json,
        )

    async def serve(self, host: str, port: int) -> None:
        """Start the MOQT/QUIC server and block until cancelled."""
        config = QuicConfiguration(
            alpn_protocols=[MOQT_ALPN],
            is_client=False,
        )
        config.load_cert_chain(self._cert_file, self._key_file)

        logger.info("MOQT agent server listening on %s:%d (QUIC/MOQT)", host, port)
        _server = await serve(
            host,
            port,
            configuration=config,
            create_protocol=self._make_protocol,
        )
        # Run until cancelled
        try:
            await asyncio.Event().wait()
        finally:
            _server.close()
            await self._asgi_client.aclose()



