"""
MOQT Agent Client
Replaces A2AClient (httpx) + A2ACardResolver used by the Host Agent.

Flow for get_agent_card()
─────────────────────────
  1. QUIC connect → MOQT CLIENT_SETUP / SERVER_SETUP
  2. SUBSCRIBE to discovery track  ["a2a","discovery"] / "agent-{id}"
  3. Server immediately publishes AgentCard as OBJECT_STREAM
  4. Parse and return AgentCard

Flow for send_message()
──────────────────────
  1. (reuse existing connection)
  2. SUBSCRIBE to response track  ["a2a"] / "agent-{id}/response"
  3. ANNOUNCE ["a2a"] so server knows we will publish
  4. PUBLISH request JSON-RPC on request track  ["a2a"] / "agent-{id}/request"
  5. Wait for OBJECT_STREAM on response track
  6. Parse and return SendMessageResponse
"""

import asyncio
import json
import logging
import ssl
from contextlib import asynccontextmanager
from typing import Optional

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
)

from .protocol import (
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
    SubscribeOk,
    decode_varint,
    frame_message,
    parse_control_message,
    discovery_track,
    request_track,
    response_track,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Low-level QUIC / MOQT protocol
# ---------------------------------------------------------------------------

class MOQTClientProtocol(QuicConnectionProtocol):
    """
    MOQT client-side protocol running over a single QUIC connection.

    Provides async primitives:
      - wait_setup()       — wait for MOQT handshake to complete
      - subscribe()        — subscribe to a track, return (sub_id, alias)
      - publish_object()   — send OBJECT_STREAM on a new uni stream
      - receive_object()   — await next incoming OBJECT_STREAM
    """

    def __init__(self, quic, stream_handler=None):
        super().__init__(quic, stream_handler)

        self._setup_event: asyncio.Event = asyncio.Event()
        self._ctrl_buf: bytes = b""

        # subscribe_id → asyncio.Event (set when SUBSCRIBE_OK received)
        self._sub_acks: dict[int, asyncio.Event] = {}

        # Incoming OBJECT_STREAMs from the server
        self._incoming: asyncio.Queue[ObjectStream] = asyncio.Queue()

        self._next_sub_id: int = 0
        self._next_alias: int = 0

    # ------------------------------------------------------------------
    # aioquic event dispatch
    # ------------------------------------------------------------------

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            # Open first client-initiated bidirectional stream (id=0) for control
            asyncio.ensure_future(self._send_client_setup())

        elif isinstance(event, StreamDataReceived):
            sid = event.stream_id
            # sid % 4 == 0 → client bidi (control stream responses from server)
            # sid % 4 == 3 → server-initiated unidirectional (OBJECT_STREAM from server)
            if sid % 4 == 0:
                self._on_control_data(sid, event.data)
            elif sid % 4 == 3:
                self._on_server_data(event.data)

    # ------------------------------------------------------------------
    # Control stream
    # ------------------------------------------------------------------

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
                logger.error("MOQT client control error: %s", exc, exc_info=True)
                break

    def _handle_control(
        self, stream_id: int, msg_type: MsgType, payload: bytes
    ) -> None:
        logger.debug("MOQT client ← %s", msg_type.name)

        if msg_type == MsgType.SERVER_SETUP:
            ss = ServerSetup.decode(payload)
            logger.info("MOQT client: setup complete (version=0x%X)", ss.selected_version)
            self._setup_event.set()

        elif msg_type == MsgType.SUBSCRIBE_OK:
            sok = SubscribeOk.decode(payload)
            event = self._sub_acks.get(sok.subscribe_id)
            if event:
                event.set()
            logger.debug("MOQT client: SUBSCRIBE_OK sub_id=%d", sok.subscribe_id)

        elif msg_type == MsgType.ANNOUNCE:
            ann = Announce.decode(payload)
            # Acknowledge server announcements
            ack = AnnounceOk(namespace=ann.namespace)
            self._quic.send_stream_data(stream_id, ack.encode())
            self.transmit()
            logger.debug("MOQT client: ANNOUNCE_OK sent for %s", ann.namespace)

        elif msg_type == MsgType.SUBSCRIBE_NAMESPACE:
            # Server is subscribing to our namespace — acknowledge
            sns = SubscribeNamespace.decode(payload)
            from .protocol import SubscribeNamespaceOk
            ok = SubscribeNamespaceOk(namespace_prefix=sns.namespace_prefix)
            self._quic.send_stream_data(stream_id, ok.encode())
            self.transmit()

    # ------------------------------------------------------------------
    # Incoming data stream (server → client OBJECT_STREAMs)
    # ------------------------------------------------------------------

    def _on_server_data(self, data: bytes) -> None:
        try:
            msg_type_val, offset = decode_varint(data)
            if MsgType(msg_type_val) == MsgType.OBJECT_STREAM:
                obj = ObjectStream.decode(data[offset:])
                self._incoming.put_nowait(obj)
        except Exception as exc:
            logger.error("MOQT client: error parsing server data: %s", exc)

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def wait_setup(self, timeout: float = 10.0) -> None:
        await asyncio.wait_for(self._setup_event.wait(), timeout)

    async def subscribe(
        self,
        namespace: list[str],
        track_name: str,
        timeout: float = 10.0,
    ) -> tuple[int, int]:
        """
        Send SUBSCRIBE and wait for SUBSCRIBE_OK.
        Returns (subscribe_id, track_alias).
        """
        await self.wait_setup()

        sub_id = self._next_sub_id
        alias = self._next_alias
        self._next_sub_id += 1
        self._next_alias += 1

        ack_event = asyncio.Event()
        self._sub_acks[sub_id] = ack_event

        sub = Subscribe(
            subscribe_id=sub_id,
            track_alias=alias,
            namespace=namespace,
            track_name=track_name,
        )
        self._quic.send_stream_data(0, sub.encode())
        self.transmit()

        await asyncio.wait_for(ack_event.wait(), timeout)
        logger.info(
            "MOQT client: subscribed to %s/%s (sub_id=%d)", namespace, track_name, sub_id
        )
        return sub_id, alias

    async def announce(self, namespace: list[str]) -> None:
        """Send ANNOUNCE so the server knows we will publish on this namespace."""
        await self.wait_setup()
        ann = Announce(namespace=namespace)
        self._quic.send_stream_data(0, ann.encode())
        self.transmit()
        logger.debug("MOQT client: ANNOUNCE %s", namespace)

    async def publish_object(
        self,
        subscribe_id: int,
        track_alias: int,
        payload: bytes,
        priority: int = 3,
    ) -> None:
        """Send an OBJECT_STREAM on a new client-initiated unidirectional stream."""
        obj = ObjectStream(
            subscribe_id=subscribe_id,
            track_alias=track_alias,
            group_id=0,
            object_id=0,
            publisher_priority=priority,
            object_payload=payload,
        )
        # Client-initiated unidirectional streams: 2, 6, 10, …
        sid = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._quic.send_stream_data(sid, obj.encode(), end_stream=True)
        self.transmit()
        logger.debug("MOQT client: published %d bytes on stream %d", len(payload), sid)

    async def receive_object(self, timeout: float = 30.0) -> ObjectStream:
        """Wait for the next OBJECT_STREAM from the server."""
        return await asyncio.wait_for(self._incoming.get(), timeout)


# ---------------------------------------------------------------------------
# High-level client — replaces A2AClient + A2ACardResolver
# ---------------------------------------------------------------------------

class MOQTAgentClient:
    """
    Manages a persistent MOQT connection to a single remote friend agent.

    Usage
    -----
        async with MOQTAgentClient("localhost", 20002, "karley", ca_cert="moqt_certs/cert.pem") as client:
            card  = await client.get_agent_card()
            resp  = await client.send_message(message_request)
    """

    def __init__(
        self,
        host: str,
        port: int,
        agent_id: str,
        ca_cert: Optional[str] = None,
    ):
        self._host = host
        self._port = port
        self._agent_id = agent_id
        self._ca_cert = ca_cert
        self._protocol: Optional[MOQTClientProtocol] = None
        self._connection_ctx = None

    async def __aenter__(self) -> "MOQTAgentClient":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def connect(self) -> None:
        config = QuicConfiguration(
            alpn_protocols=[MOQT_ALPN],
            is_client=True,
        )
        if self._ca_cert:
            # Trust only our dev CA cert — avoids CERT_NONE while supporting self-signed
            config.cafile = self._ca_cert
        else:
            # ⚠️ No CA cert supplied — disabling TLS verification (LOCAL DEV ONLY).
            # In production, supply a valid CA cert or use a public CA.
            config.verify_mode = ssl.CERT_NONE

        self._connection_ctx = connect(
            self._host,
            self._port,
            configuration=config,
            create_protocol=MOQTClientProtocol,
        )
        self._protocol = await self._connection_ctx.__aenter__()
        await self._protocol.wait_setup()
        logger.info(
            "MOQT client: connected to %s:%d (agent=%s)", self._host, self._port, self._agent_id
        )

    async def close(self) -> None:
        if self._connection_ctx:
            await self._connection_ctx.__aexit__(None, None, None)

    # ------------------------------------------------------------------
    # A2A-level operations
    # ------------------------------------------------------------------

    async def get_agent_card(self, timeout: float = 10.0):
        """
        Fetch the remote agent's AgentCard via MOQT discovery track.
        Replaces A2ACardResolver.get_agent_card().
        """
        from a2a.types import AgentCard

        ns, track = discovery_track(self._agent_id)
        await self._protocol.subscribe(ns, track, timeout=timeout)
        obj = await self._protocol.receive_object(timeout=timeout)
        card_data = json.loads(obj.object_payload)
        logger.info("MOQT client: got AgentCard for %s", self._agent_id)
        return AgentCard.model_validate(card_data)

    async def send_message(self, request, timeout: float = 30.0):
        """
        Send an A2A SendMessageRequest via MOQT and return SendMessageResponse.
        Replaces A2AClient.send_message().

        The JSON-RPC payload is identical to the HTTP transport (draft §3.3).
        """
        from a2a.types import SendMessageResponse

        # 1. Subscribe to response track so we can receive the reply
        resp_ns, resp_track = response_track(self._agent_id)
        resp_sub_id, resp_alias = await self._protocol.subscribe(
            resp_ns, resp_track, timeout=10.0
        )

        # 2. Announce that we will publish on the A2A namespace
        await self._protocol.announce(["a2a"])

        # 3. Publish request as OBJECT_STREAM (arbitrary sub/alias for publish direction)
        req_payload = request.model_dump_json().encode("utf-8")
        await self._protocol.publish_object(
            subscribe_id=resp_sub_id,    # correlate with response subscription
            track_alias=resp_alias + 1000,  # offset to distinguish publish alias
            payload=req_payload,
            priority=3,
        )
        logger.info("MOQT client: request published to agent=%s", self._agent_id)

        # 4. Wait for response object
        obj = await self._protocol.receive_object(timeout=timeout)
        response_data = json.loads(obj.object_payload)
        return SendMessageResponse.model_validate(response_data)


# ---------------------------------------------------------------------------
# Card resolver helper (mirrors A2ACardResolver interface)
# ---------------------------------------------------------------------------

class MOQTCardResolver:
    """
    Resolve an AgentCard from a MOQT agent URL.
    Replaces A2ACardResolver used in the host agent.

    Usage
    -----
        resolver = MOQTCardResolver("localhost", 20002, "karley", ca_cert="moqt_certs/cert.pem")
        card = await resolver.get_agent_card()
    """

    def __init__(
        self,
        host: str,
        port: int,
        agent_id: str,
        ca_cert: Optional[str] = None,
    ):
        self._host = host
        self._port = port
        self._agent_id = agent_id
        self._ca_cert = ca_cert

    async def get_agent_card(self):
        async with MOQTAgentClient(
            self._host, self._port, self._agent_id, ca_cert=self._ca_cert
        ) as client:
            return await client.get_agent_card()



