"""
MOQT Agent Server
Replaces A2AStarletteApplication + uvicorn for each friend agent.

Supports two modes:
  1. Direct mode (original): agents connect directly to the server via QUIC.
  2. Relay mode (new): the server connects to a MoQ Lite Relay as a client,
     ANNOUNCE's its namespace, and handles SUBSCRIBEs forwarded by the relay.

Architecture (relay mode)
─────────────────────────
  Agent Server ──QUIC──> MoQ Lite Relay <──QUIC── Host Agent
       │                      │
       ANNOUNCE ["a2a"]       SUBSCRIBE_NAMESPACE ["a2a","discovery"]
       OBJECT (AgentCard)     ← relay forwards AgentCard
       ← SUBSCRIBE (request)  relay forwards subscriptions
       OBJECT (response) →    relay forwards response →

The server bridges incoming MOQT objects to the existing A2A DefaultRequestHandler
via an in-process ASGI call (httpx.ASGITransport).  The full a2a-sdk stack
(AgentExecutor, TaskStore, etc.) works unchanged -- only transport changes.
"""

import asyncio
import logging
import ssl
from typing import Optional

import httpx
from aioquic.asyncio import connect, serve
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
    MaxSubscribeId,
    ObjectStream,
    ServerSetup,
    Subscribe,
    SubscribeDone,
    SubscribeNamespace,
    SubscribeNamespaceOk,
    SubscribeOk,
    Unsubscribe,
    decode_varint,
    discovery_track,
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

        # Per unidirectional-stream reassembly buffers (same fragmentation fix as relay).
        self._data_bufs: dict[int, bytes] = {}

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
                self._data_bufs[sid] = self._data_bufs.get(sid, b"") + event.data
                if event.end_stream:
                    buf = self._data_bufs.pop(sid)
                    asyncio.ensure_future(self._on_request_stream(buf))

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

        elif msg_type == MsgType.UNSUBSCRIBE:
            unsub = Unsubscribe.decode(payload)
            if unsub.subscribe_id in self._subs:
                del self._subs[unsub.subscribe_id]
                self._obj_counters.pop(unsub.subscribe_id, None)
            done = SubscribeDone(subscribe_id=unsub.subscribe_id, status_code=0, reason="unsubscribed")
            self._ctrl_send(stream_id, done.encode())
            self.transmit()
            logger.info("MOQT server: UNSUBSCRIBE sub_id=%d", unsub.subscribe_id)

        elif msg_type == MsgType.SUBSCRIBE_NAMESPACE:
            sns = SubscribeNamespace.decode(payload)
            self._ctrl_send(
                stream_id,
                SubscribeNamespaceOk(namespace_prefix=sns.namespace_prefix).encode(),
            )
            self.transmit()
            logger.info("MOQT server: SUBSCRIBE_NAMESPACE %s", sns.namespace_prefix)

        elif msg_type == MsgType.MAX_SUBSCRIBE_ID:
            msi = MaxSubscribeId.decode(payload)
            logger.debug("MOQT server: MAX_SUBSCRIBE_ID=%d", msi.max_subscribe_id)

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
# Relay-connected agent protocol (agent acts as QUIC client to the relay)
# ---------------------------------------------------------------------------

class MOQTRelayAgentProtocol(QuicConnectionProtocol):
    """
    Protocol for an agent that connects *to* a relay as a QUIC client.
    It ANNOUNCEs its namespace, publishes its AgentCard, and handles
    SUBSCRIBEs forwarded by the relay.
    """

    def __init__(self, quic, stream_handler=None, *, asgi_client, agent_card_json, agent_id):
        super().__init__(quic, stream_handler)
        self._asgi_client = asgi_client
        self._agent_card_json = agent_card_json
        self._agent_id = agent_id

        self._ctrl_buf: bytes = b""
        self._setup_event = asyncio.Event()

        # Subscriptions FROM the relay (relay subscribing to our tracks)
        self._subs: dict[int, tuple[list[str], str, int]] = {}
        self._obj_counters: dict[int, int] = {}

        # Our subscriptions TO the relay (we subscribe to request track)
        self._sub_acks: dict[int, asyncio.Event] = {}
        self._next_sub_id: int = 100

        self._request_sub_id: int = 0
        self._request_alias: int = 0

        # Per unidirectional-stream reassembly buffers.
        self._data_bufs: dict[int, bytes] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            asyncio.ensure_future(self._send_client_setup())

        elif isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if sid % 4 == 0:
                self._on_control_data(sid, event.data)
            elif sid % 4 == 3:
                self._data_bufs[sid] = self._data_bufs.get(sid, b"") + event.data
                if event.end_stream:
                    buf = self._data_bufs.pop(sid)
                    asyncio.ensure_future(self._on_relay_data(buf))

        elif isinstance(event, ConnectionTerminated):
            logger.info("MOQT relay-agent: connection terminated")

    async def _send_client_setup(self) -> None:
        cs = ClientSetup(supported_versions=[MOQT_VERSION])
        self._quic.send_stream_data(0, cs.encode())
        self.transmit()

    def _on_control_data(self, stream_id: int, data: bytes) -> None:
        self._ctrl_buf += data
        while self._ctrl_buf:
            try:
                msg_type, payload, consumed = parse_control_message(self._ctrl_buf)
                self._ctrl_buf = self._ctrl_buf[consumed:]
                self._handle_control(stream_id, msg_type, payload)
            except BufferError:
                break
            except Exception as exc:
                logger.error("MOQT relay-agent control error: %s", exc, exc_info=True)
                break

    def _handle_control(self, stream_id: int, msg_type: MsgType, payload: bytes) -> None:
        logger.debug("MOQT relay-agent <- %s", msg_type.name)

        if msg_type == MsgType.SERVER_SETUP:
            ss = ServerSetup.decode(payload)
            logger.info("MOQT relay-agent: setup complete (version=0x%X)", ss.selected_version)
            self._setup_event.set()

        elif msg_type == MsgType.ANNOUNCE_OK:
            ack = AnnounceOk.decode(payload)
            logger.debug("MOQT relay-agent: ANNOUNCE_OK for %s", ack.namespace)

        elif msg_type == MsgType.SUBSCRIBE_OK:
            sok = SubscribeOk.decode(payload)
            event = self._sub_acks.get(sok.subscribe_id)
            if event:
                event.set()
            logger.debug("MOQT relay-agent: SUBSCRIBE_OK sub_id=%d", sok.subscribe_id)

        elif msg_type == MsgType.SUBSCRIBE:
            sub = Subscribe.decode(payload)
            self._subs[sub.subscribe_id] = (sub.namespace, sub.track_name, sub.track_alias)
            self._obj_counters[sub.subscribe_id] = 0
            self._quic.send_stream_data(
                stream_id, SubscribeOk(subscribe_id=sub.subscribe_id).encode()
            )
            self.transmit()
            logger.info(
                "MOQT relay-agent: SUBSCRIBE %s/%s sub_id=%d",
                sub.namespace, sub.track_name, sub.subscribe_id,
            )
            if "discovery" in sub.track_name or "discovery" in sub.namespace:
                asyncio.ensure_future(self._publish_agent_card(sub.subscribe_id, sub.track_alias))

        elif msg_type == MsgType.UNSUBSCRIBE:
            unsub = Unsubscribe.decode(payload)
            self._subs.pop(unsub.subscribe_id, None)
            self._obj_counters.pop(unsub.subscribe_id, None)
            done = SubscribeDone(subscribe_id=unsub.subscribe_id, status_code=0, reason="unsubscribed")
            self._quic.send_stream_data(stream_id, done.encode())
            self.transmit()
            logger.info("MOQT relay-agent: UNSUBSCRIBE sub_id=%d", unsub.subscribe_id)

        elif msg_type == MsgType.SUBSCRIBE_NAMESPACE:
            sns = SubscribeNamespace.decode(payload)
            self._quic.send_stream_data(
                stream_id,
                SubscribeNamespaceOk(namespace_prefix=sns.namespace_prefix).encode(),
            )
            self.transmit()

        elif msg_type == MsgType.MAX_SUBSCRIBE_ID:
            pass

    async def _on_relay_data(self, data: bytes) -> None:
        """Handle incoming OBJECT_STREAM from relay (forwarded requests)."""
        try:
            msg_type_val, offset = decode_varint(data)
            if MsgType(msg_type_val) != MsgType.OBJECT_STREAM:
                return
            obj = ObjectStream.decode(data[offset:])
            logger.info("MOQT relay-agent: request received (%d bytes)", len(obj.object_payload))

            http_resp = await self._asgi_client.post(
                "/",
                content=obj.object_payload,
                headers={"content-type": "application/json"},
            )

            resp_sub_id, resp_alias = self._find_response_sub()
            await self._publish_object(
                subscribe_id=resp_sub_id,
                track_alias=resp_alias,
                publisher_priority=2,
                payload=http_resp.content,
            )
            logger.info("MOQT relay-agent: response published (HTTP %d)", http_resp.status_code)
        except Exception as exc:
            logger.error("MOQT relay-agent: error processing request: %s", exc, exc_info=True)

    async def _publish_agent_card(self, subscribe_id: int, track_alias: int) -> None:
        await self._publish_object(
            subscribe_id=subscribe_id,
            track_alias=track_alias,
            publisher_priority=4,
            payload=self._agent_card_json.encode("utf-8"),
        )
        logger.info("MOQT relay-agent: AgentCard published on discovery track")

    async def _publish_object(self, subscribe_id, track_alias, publisher_priority, payload):
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
        sid = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._quic.send_stream_data(sid, obj.encode(), end_stream=True)
        self.transmit()

    def _find_response_sub(self) -> tuple[int, int]:
        for sub_id, (ns, track, alias) in self._subs.items():
            if "response" in track:
                return sub_id, alias
        if self._subs:
            sub_id = max(self._subs)
            return sub_id, self._subs[sub_id][2]
        return 0, 0

    async def wait_setup(self, timeout: float = 10.0) -> None:
        await asyncio.wait_for(self._setup_event.wait(), timeout)

    async def announce_and_publish(self) -> None:
        """ANNOUNCE namespaces, publish AgentCard, and subscribe to request track."""
        await self.wait_setup()

        self._quic.send_stream_data(0, Announce(namespace=["a2a"]).encode())
        self._quic.send_stream_data(0, Announce(namespace=["a2a", "discovery"]).encode())
        self.transmit()

        # Publish AgentCard as an OBJECT_STREAM on the discovery track
        ns, track = discovery_track(self._agent_id)
        await self._publish_object(
            subscribe_id=0,
            track_alias=0,
            publisher_priority=4,
            payload=self._agent_card_json.encode("utf-8"),
        )

        # Subscribe to request track so the relay can forward client requests to us
        from .protocol import request_track as get_request_track
        req_ns, req_track = get_request_track(self._agent_id)
        sub_id = self._next_sub_id
        alias = sub_id
        self._next_sub_id = sub_id + 1
        self._request_sub_id = sub_id
        self._request_alias = alias

        ack_event = asyncio.Event()
        self._sub_acks[sub_id] = ack_event

        sub = Subscribe(
            subscribe_id=sub_id,
            track_alias=alias,
            namespace=req_ns,
            track_name=req_track,
        )
        self._quic.send_stream_data(0, sub.encode())
        self.transmit()

        try:
            await asyncio.wait_for(ack_event.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("MOQT relay-agent: timeout waiting for request track subscription ack")

        logger.info("MOQT relay-agent: announced namespaces, published AgentCard, subscribed to request track")


# ---------------------------------------------------------------------------
# High-level server -- supports both direct and relay-connected modes
# ---------------------------------------------------------------------------

class MOQTAgentServer:
    """
    Drop-in replacement for A2AStarletteApplication when using MOQT transport.

    Supports two modes:
      - Direct mode: ``server.serve("localhost", 20002)``
      - Relay mode:  ``server.serve_via_relay("localhost", 20000, agent_id="karley")``

    Usage
    -----
        server = MOQTAgentServer(
            agent_card=agent_card,
            http_handler=request_handler,
            cert_file="moqt_certs/cert.pem",
            key_file="moqt_certs/key.pem",
        )
        # Direct mode:
        asyncio.run(server.serve("localhost", 20002))
        # Or relay mode:
        asyncio.run(server.serve_via_relay("localhost", 20000, agent_id="karley"))
    """

    def __init__(
        self,
        agent_card,
        http_handler,
        cert_file: str,
        key_file: str,
    ):
        from a2a.server.apps import A2AStarletteApplication

        asgi_app = A2AStarletteApplication(
            agent_card=agent_card, http_handler=http_handler
        ).build()

        self._asgi_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=asgi_app),
            base_url="http://a2a-agent",
        )
        self._agent_card = agent_card
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
        """Start in direct mode: listen for QUIC connections."""
        config = QuicConfiguration(
            alpn_protocols=[MOQT_ALPN],
            is_client=False,
        )
        config.load_cert_chain(self._cert_file, self._key_file)

        logger.info("MOQT agent server listening on %s:%d (QUIC/MOQT, direct mode)", host, port)
        _server = await serve(
            host,
            port,
            configuration=config,
            create_protocol=self._make_protocol,
        )
        try:
            await asyncio.Event().wait()
        finally:
            _server.close()
            await self._asgi_client.aclose()

    async def serve_via_relay(
        self,
        relay_host: str,
        relay_port: int,
        agent_id: Optional[str] = None,
        ca_cert: Optional[str] = None,
    ) -> None:
        """
        Start in relay mode: connect to a MoQ Lite Relay as a client,
        ANNOUNCE namespaces, and publish AgentCard for discovery.
        """
        if agent_id is None:
            agent_id = self._agent_card.name.lower().replace(" agent", "").replace(" ", "_")

        config = QuicConfiguration(
            alpn_protocols=[MOQT_ALPN],
            is_client=True,
        )
        if ca_cert:
            config.cafile = ca_cert
        else:
            config.verify_mode = ssl.CERT_NONE

        logger.info(
            "MOQT agent server connecting to relay %s:%d (agent_id=%s)",
            relay_host, relay_port, agent_id,
        )

        def _make_relay_protocol(quic, stream_handler=None):
            return MOQTRelayAgentProtocol(
                quic, stream_handler,
                asgi_client=self._asgi_client,
                agent_card_json=self._agent_card_json,
                agent_id=agent_id,
            )

        async with connect(
            relay_host,
            relay_port,
            configuration=config,
            create_protocol=_make_relay_protocol,
        ) as protocol:
            await protocol.announce_and_publish()
            logger.info("MOQT agent server: connected to relay, awaiting requests")
            try:
                await asyncio.Event().wait()
            finally:
                await self._asgi_client.aclose()



