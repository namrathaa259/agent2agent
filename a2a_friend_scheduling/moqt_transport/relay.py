"""
MoQ Lite Relay -- Lightweight MOQT relay for A2A agent communication.

Implements relay behavior per:
  - draft-ietf-moq-transport Section 8 (Relay requirements)
  - draft-nandakumar-a2a-moqt-transport-00 Sections 4.1, 4.2, 4.3, 6

The relay is both a Publisher and a Subscriber (MoQT definition of a Relay).
All agents connect to it; it forwards SUBSCRIBE/ANNOUNCE/OBJECT_STREAM between
sessions based on namespace prefix matching and subscription tables.

Architecture
    QUIC listener (TLS 1.3, ALPN "moq-00")
        |
        +-- per-connection MOQTRelaySession
        |     +-- control stream: handshake, subscribe, announce, unsubscribe
        |     +-- data streams: OBJECT_STREAM forwarding
        |
        +-- shared RelayState
              +-- namespace registry (who publishes what)
              +-- subscription table (who subscribes to what)
              +-- priority dispatcher (forwarding order)
              +-- object cache (3-tier TTL)
"""

import asyncio
import heapq
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

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
    MOQT_ALPN,
    MOQT_VERSION,
    FullTrackName,
    MsgType,
    Announce,
    AnnounceOk,
    ClientSetup,
    GoAway,
    MaxSubscribeId,
    ObjectStream,
    ServerSetup,
    Subscribe,
    SubscribeDone,
    SubscribeDoneStatus,
    SubscribeError,
    SubscribeNamespace,
    SubscribeNamespaceOk,
    SubscribeOk,
    Unannounce,
    Unsubscribe,
    decode_varint,
    encode_varint,
    namespace_prefix_match,
    parse_control_message,
)

logger = logging.getLogger(__name__)

# Maximum subscribe ID sent to each client during setup
_MAX_SUBSCRIBE_ID = 1024


# ---------------------------------------------------------------------------
# Object Cache (3-tier, in-memory, TTL-based)
# ---------------------------------------------------------------------------

class CacheTier:
    HOT = "hot"
    WARM = "warm"
    COLD = "cold"


# Default TTLs in seconds
_TIER_TTL = {
    CacheTier.HOT: 5.0,
    CacheTier.WARM: 300.0,
    CacheTier.COLD: 3600.0,
}

# Priority -> cache tier mapping (draft Section 3.4 + Section 6.2)
_PRIORITY_TIER = {
    1: CacheTier.HOT,
    2: CacheTier.HOT,
    3: CacheTier.WARM,
    4: CacheTier.WARM,
    5: CacheTier.COLD,
}


@dataclass
class CachedObject:
    namespace: tuple[str, ...]
    track_name: str
    group_id: int
    object_id: int
    priority: int
    payload: bytes
    cached_at: float
    tier: str


class ObjectCache:
    """Three-tier in-memory object cache with TTL eviction."""

    def __init__(self):
        self._store: dict[tuple, CachedObject] = {}

    def _key(self, ns: tuple[str, ...], track: str, gid: int, oid: int) -> tuple:
        return (ns, track, gid, oid)

    def put(self, obj: ObjectStream, namespace: tuple[str, ...], track_name: str) -> None:
        tier = _PRIORITY_TIER.get(obj.publisher_priority, CacheTier.WARM)
        k = self._key(namespace, track_name, obj.group_id, obj.object_id)
        self._store[k] = CachedObject(
            namespace=namespace,
            track_name=track_name,
            group_id=obj.group_id,
            object_id=obj.object_id,
            priority=obj.publisher_priority,
            payload=obj.object_payload,
            cached_at=time.monotonic(),
            tier=tier,
        )

    def get_for_track(self, namespace: tuple[str, ...], track_name: str) -> list[CachedObject]:
        """Return all non-expired cached objects for a track, ordered by object_id."""
        now = time.monotonic()
        results = []
        expired_keys = []
        for k, co in self._store.items():
            if co.namespace == namespace and co.track_name == track_name:
                ttl = _TIER_TTL.get(co.tier, 5.0)
                if now - co.cached_at > ttl:
                    expired_keys.append(k)
                else:
                    results.append(co)
        for k in expired_keys:
            del self._store[k]
        results.sort(key=lambda c: (c.group_id, c.object_id))
        return results

    def get_for_namespace(self, ns_prefix: tuple[str, ...]) -> list[CachedObject]:
        """Return cached objects whose namespace starts with the given prefix."""
        now = time.monotonic()
        results = []
        expired_keys = []
        for k, co in self._store.items():
            if namespace_prefix_match(ns_prefix, co.namespace):
                ttl = _TIER_TTL.get(co.tier, 5.0)
                if now - co.cached_at > ttl:
                    expired_keys.append(k)
                else:
                    results.append(co)
        for k in expired_keys:
            del self._store[k]
        results.sort(key=lambda c: (c.namespace, c.track_name, c.group_id, c.object_id))
        return results

    def evict_expired(self) -> int:
        """Remove all expired entries. Returns count of evicted items."""
        now = time.monotonic()
        expired = [
            k for k, co in self._store.items()
            if now - co.cached_at > _TIER_TTL.get(co.tier, 5.0)
        ]
        for k in expired:
            del self._store[k]
        return len(expired)


# ---------------------------------------------------------------------------
# Priority Dispatcher
# ---------------------------------------------------------------------------

@dataclass(order=True)
class PrioritizedForward:
    priority: int
    enqueued: float = field(compare=True)
    session_id: str = field(compare=False)
    subscribe_id: int = field(compare=False)
    track_alias: int = field(compare=False)
    obj: ObjectStream = field(compare=False)


class PriorityDispatcher:
    """
    Queues outbound objects and dispatches them in priority order.
    Lower priority number = higher urgency (draft Section 3.4).
    """

    def __init__(self):
        self._queue: list[PrioritizedForward] = []
        self._pending = asyncio.Event()

    def enqueue(
        self,
        session_id: str,
        subscribe_id: int,
        track_alias: int,
        obj: ObjectStream,
    ) -> None:
        item = PrioritizedForward(
            priority=obj.publisher_priority,
            enqueued=time.monotonic(),
            session_id=session_id,
            subscribe_id=subscribe_id,
            track_alias=track_alias,
            obj=obj,
        )
        heapq.heappush(self._queue, item)
        self._pending.set()

    async def drain(self, sessions: dict[str, "MOQTRelaySession"]) -> None:
        """Continuously drain the priority queue, forwarding objects to sessions."""
        while True:
            await self._pending.wait()
            self._pending.clear()

            while self._queue:
                item = heapq.heappop(self._queue)
                session = sessions.get(item.session_id)
                if session is None:
                    continue
                try:
                    session.forward_object(item.subscribe_id, item.track_alias, item.obj)
                except Exception as exc:
                    logger.error(
                        "Relay: failed to forward object to session %s: %s",
                        item.session_id, exc,
                    )


# ---------------------------------------------------------------------------
# Downstream / Upstream subscription records
# ---------------------------------------------------------------------------

@dataclass
class DownstreamSub:
    """A subscriber's interest in a specific track."""
    session_id: str
    subscribe_id: int
    track_alias: int
    priority: int


@dataclass
class UpstreamSub:
    """The relay's upstream subscription to a publisher for a track."""
    publisher_session_id: str
    relay_subscribe_id: int
    relay_track_alias: int
    established: bool = False


# ---------------------------------------------------------------------------
# Shared Relay State
# ---------------------------------------------------------------------------

class RelayState:
    """Global state shared by all MOQTRelaySession instances."""

    def __init__(self):
        self.sessions: dict[str, "MOQTRelaySession"] = {}

        # namespace_prefix (tuple) -> set of session_ids that SUBSCRIBE_NAMESPACE'd
        self.ns_subscribers: dict[tuple[str, ...], set[str]] = {}
        # namespace_prefix (tuple) -> set of session_ids that ANNOUNCE'd / PUBLISH_NAMESPACE'd
        self.ns_publishers: dict[tuple[str, ...], set[str]] = {}

        # FullTrackName -> list of downstream subscribers
        self.downstream_subs: dict[FullTrackName, list[DownstreamSub]] = {}
        # FullTrackName -> upstream subscription (relay -> publisher)
        self.upstream_subs: dict[FullTrackName, UpstreamSub] = {}

        self.cache = ObjectCache()
        self.dispatcher = PriorityDispatcher()

        # relay_sub_id -> list of (downstream_session_id, downstream_subscribe_id)
        # Tracks pending downstream acks waiting for upstream SUBSCRIBE_OK
        self.pending_sub_oks: dict[int, list[tuple[str, int]]] = {}

        self._relay_sub_counter = 0

    def next_relay_sub_id(self) -> int:
        self._relay_sub_counter += 1
        return self._relay_sub_counter

    def find_publishers_for_track(self, namespace: list[str], track_name: str) -> list[str]:
        """Find all sessions that have announced a namespace matching this track."""
        ns_tuple = tuple(namespace)
        matching = []
        for pub_prefix, session_ids in self.ns_publishers.items():
            if namespace_prefix_match(pub_prefix, ns_tuple):
                matching.extend(session_ids)
        return list(set(matching))

    def find_ns_subscribers(self, namespace: tuple[str, ...]) -> set[str]:
        """Find all sessions that have SUBSCRIBE_NAMESPACE'd a prefix matching namespace."""
        result: set[str] = set()
        for prefix, session_ids in self.ns_subscribers.items():
            if namespace_prefix_match(prefix, namespace):
                result.update(session_ids)
        return result

    def remove_session(self, session_id: str) -> None:
        """Clean up all state for a disconnected session."""
        # Remove from namespace tables
        for prefix in list(self.ns_subscribers.keys()):
            self.ns_subscribers[prefix].discard(session_id)
            if not self.ns_subscribers[prefix]:
                del self.ns_subscribers[prefix]
        for prefix in list(self.ns_publishers.keys()):
            self.ns_publishers[prefix].discard(session_id)
            if not self.ns_publishers[prefix]:
                del self.ns_publishers[prefix]

        # Remove downstream subscriptions
        for ftn in list(self.downstream_subs.keys()):
            self.downstream_subs[ftn] = [
                ds for ds in self.downstream_subs[ftn] if ds.session_id != session_id
            ]
            if not self.downstream_subs[ftn]:
                del self.downstream_subs[ftn]
                if ftn in self.upstream_subs:
                    upstream = self.upstream_subs[ftn]
                    pub_session = self.sessions.get(upstream.publisher_session_id)
                    if pub_session:
                        pub_session.send_unsubscribe(upstream.relay_subscribe_id)
                    del self.upstream_subs[ftn]

        # Remove upstream subs where this session was the publisher
        for ftn in list(self.upstream_subs.keys()):
            if self.upstream_subs[ftn].publisher_session_id == session_id:
                del self.upstream_subs[ftn]

        self.sessions.pop(session_id, None)


# ---------------------------------------------------------------------------
# Per-connection relay session
# ---------------------------------------------------------------------------

class MOQTRelaySession(QuicConnectionProtocol):
    """
    MOQT relay handler for a single inbound QUIC connection.

    Conforms to MoQT relay requirements (draft-ietf-moq-transport Section 8):
    - Terminates transport sessions
    - Forwards subscriptions between publishers and subscribers
    - Forwards objects with priority ordering
    - Caches objects for late-joining subscribers
    """

    def __init__(self, quic, stream_handler=None, *, state: RelayState):
        super().__init__(quic, stream_handler)
        self._state = state
        self._session_id = f"session-{id(self)}"
        self._ctrl_buf: bytes = b""
        self._setup_done: bool = False

        # Track alias -> FullTrackName mapping for this session's published tracks
        self._alias_to_track: dict[int, FullTrackName] = {}
        # subscribe_id -> FullTrackName for this session's subscriptions
        self._local_subs: dict[int, FullTrackName] = {}

        # Per-subscription object-id counter for forwarded objects
        self._obj_counters: dict[int, int] = {}

    @property
    def session_id(self) -> str:
        return self._session_id

    # ------------------------------------------------------------------
    # aioquic event dispatch
    # ------------------------------------------------------------------

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            logger.debug("Relay session %s: QUIC handshake complete", self._session_id)

        elif isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if sid % 4 == 0:
                self._on_control_data(sid, event.data)
            elif sid % 4 == 2:
                self._on_client_data(event.data)

        elif isinstance(event, ConnectionTerminated):
            logger.info("Relay session %s: connection terminated", self._session_id)
            self._state.remove_session(self._session_id)

    # ------------------------------------------------------------------
    # Control stream
    # ------------------------------------------------------------------

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
                logger.error("Relay session %s control error: %s", self._session_id, exc, exc_info=True)
                break

    def _handle_control(self, stream_id: int, msg_type: MsgType, payload: bytes) -> None:
        logger.debug("Relay %s <- %s", self._session_id, msg_type.name)

        if msg_type == MsgType.CLIENT_SETUP:
            self._handle_client_setup(stream_id, payload)

        elif msg_type == MsgType.ANNOUNCE:
            self._handle_announce(stream_id, payload)

        elif msg_type == MsgType.ANNOUNCE_OK:
            pass

        elif msg_type == MsgType.UNANNOUNCE:
            self._handle_unannounce(payload)

        elif msg_type == MsgType.SUBSCRIBE:
            self._handle_subscribe(stream_id, payload)

        elif msg_type == MsgType.SUBSCRIBE_OK:
            self._handle_subscribe_ok(payload)

        elif msg_type == MsgType.SUBSCRIBE_ERROR:
            self._handle_subscribe_error(payload)

        elif msg_type == MsgType.UNSUBSCRIBE:
            self._handle_unsubscribe(stream_id, payload)

        elif msg_type == MsgType.SUBSCRIBE_DONE:
            self._handle_subscribe_done(payload)

        elif msg_type == MsgType.SUBSCRIBE_NAMESPACE:
            self._handle_subscribe_namespace(stream_id, payload)

        elif msg_type == MsgType.SUBSCRIBE_NAMESPACE_OK:
            pass

        elif msg_type == MsgType.GOAWAY:
            logger.info("Relay %s: received GOAWAY", self._session_id)

    # ------------------------------------------------------------------
    # CLIENT_SETUP handling
    # ------------------------------------------------------------------

    def _handle_client_setup(self, stream_id: int, payload: bytes) -> None:
        cs = ClientSetup.decode(payload)
        ver = MOQT_VERSION if MOQT_VERSION in cs.supported_versions else cs.supported_versions[0]

        self._ctrl_send(stream_id, ServerSetup(selected_version=ver).encode())
        self._ctrl_send(stream_id, MaxSubscribeId(max_subscribe_id=_MAX_SUBSCRIBE_ID).encode())
        self.transmit()

        self._setup_done = True
        self._state.sessions[self._session_id] = self
        logger.info("Relay session %s: setup complete (version=0x%X, role=%d)", self._session_id, ver, cs.role)

    # ------------------------------------------------------------------
    # ANNOUNCE handling (publisher registering a namespace)
    # ------------------------------------------------------------------

    def _handle_announce(self, stream_id: int, payload: bytes) -> None:
        ann = Announce.decode(payload)
        ns_tuple = tuple(ann.namespace)

        if ns_tuple not in self._state.ns_publishers:
            self._state.ns_publishers[ns_tuple] = set()
        self._state.ns_publishers[ns_tuple].add(self._session_id)

        self._ctrl_send(stream_id, AnnounceOk(namespace=ann.namespace).encode())
        self.transmit()
        logger.info("Relay %s: ANNOUNCE %s registered", self._session_id, ann.namespace)

        # Check if there are pending downstream subscriptions for tracks in this namespace
        for ftn, ds_list in list(self._state.downstream_subs.items()):
            ns, track = ftn
            if namespace_prefix_match(ns_tuple, ns) and ftn not in self._state.upstream_subs:
                self._create_upstream_subscription(ftn, self._session_id)

    def _handle_unannounce(self, payload: bytes) -> None:
        ua = Unannounce.decode(payload)
        ns_tuple = tuple(ua.namespace)
        if ns_tuple in self._state.ns_publishers:
            self._state.ns_publishers[ns_tuple].discard(self._session_id)
            if not self._state.ns_publishers[ns_tuple]:
                del self._state.ns_publishers[ns_tuple]
        logger.info("Relay %s: UNANNOUNCE %s", self._session_id, ua.namespace)

    # ------------------------------------------------------------------
    # SUBSCRIBE handling (subscriber requesting a track)
    # ------------------------------------------------------------------

    def _handle_subscribe(self, stream_id: int, payload: bytes) -> None:
        sub = Subscribe.decode(payload)
        ftn: FullTrackName = (tuple(sub.namespace), sub.track_name)

        ds = DownstreamSub(
            session_id=self._session_id,
            subscribe_id=sub.subscribe_id,
            track_alias=sub.track_alias,
            priority=sub.subscriber_priority,
        )

        if ftn not in self._state.downstream_subs:
            self._state.downstream_subs[ftn] = []
        self._state.downstream_subs[ftn].append(ds)

        logger.info(
            "Relay %s: SUBSCRIBE %s/%s sub_id=%d",
            self._session_id, sub.namespace, sub.track_name, sub.subscribe_id,
        )

        # Check if upstream subscription already exists and is established
        upstream = self._state.upstream_subs.get(ftn)
        if upstream and upstream.established:
            # Aggregation: reply immediately
            self._ctrl_send(stream_id, SubscribeOk(subscribe_id=sub.subscribe_id).encode())
            self.transmit()

            # Deliver any cached objects for this track
            cached = self._state.cache.get_for_track(ftn[0], ftn[1])
            for co in cached:
                forwarded_obj = ObjectStream(
                    subscribe_id=sub.subscribe_id,
                    track_alias=sub.track_alias,
                    group_id=co.group_id,
                    object_id=co.object_id,
                    publisher_priority=co.priority,
                    object_payload=co.payload,
                )
                self.forward_object(sub.subscribe_id, sub.track_alias, forwarded_obj)
            return

        # Need to create an upstream subscription
        if ftn not in self._state.upstream_subs:
            publishers = self._state.find_publishers_for_track(sub.namespace, sub.track_name)
            if publishers:
                pub_session_id = publishers[0]
                relay_sub_id = self._create_upstream_subscription(ftn, pub_session_id)
                # Track pending downstream ack
                if relay_sub_id not in self._state.pending_sub_oks:
                    self._state.pending_sub_oks[relay_sub_id] = []
                self._state.pending_sub_oks[relay_sub_id].append(
                    (self._session_id, sub.subscribe_id)
                )
            else:
                # No publisher yet; reply OK optimistically (cached content may arrive later)
                self._ctrl_send(stream_id, SubscribeOk(subscribe_id=sub.subscribe_id).encode())
                self.transmit()
        else:
            # Upstream sub exists but not yet established -- queue for ack
            upstream = self._state.upstream_subs[ftn]
            relay_sub_id = upstream.relay_subscribe_id
            if relay_sub_id not in self._state.pending_sub_oks:
                self._state.pending_sub_oks[relay_sub_id] = []
            self._state.pending_sub_oks[relay_sub_id].append(
                (self._session_id, sub.subscribe_id)
            )

    def _create_upstream_subscription(self, ftn: FullTrackName, pub_session_id: str) -> int:
        """Send SUBSCRIBE to a publisher session on behalf of a downstream subscriber."""
        relay_sub_id = self._state.next_relay_sub_id()
        relay_alias = relay_sub_id

        upstream = UpstreamSub(
            publisher_session_id=pub_session_id,
            relay_subscribe_id=relay_sub_id,
            relay_track_alias=relay_alias,
        )
        self._state.upstream_subs[ftn] = upstream

        pub_session = self._state.sessions.get(pub_session_id)
        if pub_session:
            ns_list = list(ftn[0])
            sub_msg = Subscribe(
                subscribe_id=relay_sub_id,
                track_alias=relay_alias,
                namespace=ns_list,
                track_name=ftn[1],
            )
            pub_session._ctrl_send(0, sub_msg.encode())
            pub_session.transmit()
            # Register the alias mapping on the publisher session
            pub_session._alias_to_track[relay_alias] = ftn
            pub_session._local_subs[relay_sub_id] = ftn
            logger.info(
                "Relay: upstream SUBSCRIBE %s/%s -> session %s (relay_sub=%d)",
                ns_list, ftn[1], pub_session_id, relay_sub_id,
            )
        return relay_sub_id

    def _handle_subscribe_ok(self, payload: bytes) -> None:
        """Publisher replied SUBSCRIBE_OK to our upstream subscription."""
        sok = SubscribeOk.decode(payload)
        relay_sub_id = sok.subscribe_id

        # Find the matching upstream sub and mark established
        for ftn, upstream in self._state.upstream_subs.items():
            if upstream.relay_subscribe_id == relay_sub_id:
                upstream.established = True
                logger.info("Relay: upstream sub %d established for %s", relay_sub_id, ftn)

                # Send SUBSCRIBE_OK to all pending downstream subscribers
                pending = self._state.pending_sub_oks.pop(relay_sub_id, [])
                for ds_session_id, ds_sub_id in pending:
                    ds_session = self._state.sessions.get(ds_session_id)
                    if ds_session:
                        ds_session._ctrl_send(0, SubscribeOk(subscribe_id=ds_sub_id).encode())
                        ds_session.transmit()
                break

    def _handle_subscribe_error(self, payload: bytes) -> None:
        """Publisher replied SUBSCRIBE_ERROR."""
        serr = SubscribeError.decode(payload)
        relay_sub_id = serr.subscribe_id
        logger.warning("Relay: upstream SUBSCRIBE_ERROR sub_id=%d code=%d", relay_sub_id, serr.error_code)

        pending = self._state.pending_sub_oks.pop(relay_sub_id, [])
        for ds_session_id, ds_sub_id in pending:
            ds_session = self._state.sessions.get(ds_session_id)
            if ds_session:
                err = SubscribeError(subscribe_id=ds_sub_id, error_code=serr.error_code, reason=serr.reason)
                ds_session._ctrl_send(0, err.encode())
                ds_session.transmit()

    # ------------------------------------------------------------------
    # UNSUBSCRIBE handling (cancellation propagation)
    # ------------------------------------------------------------------

    def _handle_unsubscribe(self, stream_id: int, payload: bytes) -> None:
        unsub = Unsubscribe.decode(payload)
        logger.info("Relay %s: UNSUBSCRIBE sub_id=%d", self._session_id, unsub.subscribe_id)

        # Find and remove the downstream subscription
        for ftn in list(self._state.downstream_subs.keys()):
            ds_list = self._state.downstream_subs[ftn]
            self._state.downstream_subs[ftn] = [
                ds for ds in ds_list
                if not (ds.session_id == self._session_id and ds.subscribe_id == unsub.subscribe_id)
            ]

            # Send SUBSCRIBE_DONE back to the unsubscribing client
            done = SubscribeDone(
                subscribe_id=unsub.subscribe_id,
                status_code=SubscribeDoneStatus.UNSUBSCRIBED,
                reason="unsubscribed",
            )
            self._ctrl_send(stream_id, done.encode())
            self.transmit()

            # If no more downstream subscribers, unsubscribe upstream
            if not self._state.downstream_subs[ftn]:
                del self._state.downstream_subs[ftn]
                upstream = self._state.upstream_subs.pop(ftn, None)
                if upstream:
                    pub_session = self._state.sessions.get(upstream.publisher_session_id)
                    if pub_session:
                        pub_session.send_unsubscribe(upstream.relay_subscribe_id)
                    logger.info("Relay: upstream UNSUBSCRIBE propagated for %s", ftn)
            break

    def _handle_subscribe_done(self, payload: bytes) -> None:
        """Publisher sent SUBSCRIBE_DONE -- propagate to downstream."""
        sd = SubscribeDone.decode(payload)
        relay_sub_id = sd.subscribe_id
        for ftn, upstream in list(self._state.upstream_subs.items()):
            if upstream.relay_subscribe_id == relay_sub_id:
                for ds in self._state.downstream_subs.get(ftn, []):
                    ds_session = self._state.sessions.get(ds.session_id)
                    if ds_session:
                        done = SubscribeDone(
                            subscribe_id=ds.subscribe_id,
                            status_code=sd.status_code,
                            reason=sd.reason,
                        )
                        ds_session._ctrl_send(0, done.encode())
                        ds_session.transmit()
                self._state.downstream_subs.pop(ftn, None)
                del self._state.upstream_subs[ftn]
                break

    def send_unsubscribe(self, subscribe_id: int) -> None:
        """Send UNSUBSCRIBE to this session (called by relay state when propagating)."""
        unsub = Unsubscribe(subscribe_id=subscribe_id)
        self._ctrl_send(0, unsub.encode())
        self.transmit()

    # ------------------------------------------------------------------
    # SUBSCRIBE_NAMESPACE handling (discovery, draft Section 4.1)
    # ------------------------------------------------------------------

    def _handle_subscribe_namespace(self, stream_id: int, payload: bytes) -> None:
        sns = SubscribeNamespace.decode(payload)
        ns_prefix = tuple(sns.namespace_prefix)

        if ns_prefix not in self._state.ns_subscribers:
            self._state.ns_subscribers[ns_prefix] = set()
        self._state.ns_subscribers[ns_prefix].add(self._session_id)

        self._ctrl_send(stream_id, SubscribeNamespaceOk(namespace_prefix=sns.namespace_prefix).encode())
        self.transmit()
        logger.info("Relay %s: SUBSCRIBE_NAMESPACE %s", self._session_id, sns.namespace_prefix)

        # Deliver cached objects matching this namespace prefix (discovery cards, etc.)
        cached = self._state.cache.get_for_namespace(ns_prefix)
        for co in cached:
            forwarded_obj = ObjectStream(
                subscribe_id=0,
                track_alias=0,
                group_id=co.group_id,
                object_id=co.object_id,
                publisher_priority=co.priority,
                object_payload=co.payload,
            )
            self.forward_object(0, 0, forwarded_obj)

    # ------------------------------------------------------------------
    # Data stream: incoming OBJECT_STREAM from a publisher
    # ------------------------------------------------------------------

    def _on_client_data(self, data: bytes) -> None:
        try:
            msg_type_val, offset = decode_varint(data)
            if MsgType(msg_type_val) != MsgType.OBJECT_STREAM:
                logger.warning("Relay %s: unexpected data msg type %d", self._session_id, msg_type_val)
                return

            obj = ObjectStream.decode(data[offset:])
            asyncio.ensure_future(self._forward_incoming_object(obj))
        except Exception as exc:
            logger.error("Relay %s: error parsing data stream: %s", self._session_id, exc)

    def _get_announced_namespaces(self) -> list[tuple[str, ...]]:
        """Return all namespace prefixes this session has ANNOUNCE'd."""
        return [
            ns for ns, sids in self._state.ns_publishers.items()
            if self._session_id in sids
        ]

    async def _forward_incoming_object(self, obj: ObjectStream) -> None:
        """Route an incoming OBJECT_STREAM to all matching downstream subscribers."""
        ftn = self._resolve_object_track(obj)

        if ftn:
            ns_tuple, track_name = ftn
            self._state.cache.put(obj, ns_tuple, track_name)

            for ds in self._state.downstream_subs.get(ftn, []):
                ds_session = self._state.sessions.get(ds.session_id)
                if ds_session and ds.session_id != self._session_id:
                    forwarded = ObjectStream(
                        subscribe_id=ds.subscribe_id,
                        track_alias=ds.track_alias,
                        group_id=obj.group_id,
                        object_id=obj.object_id,
                        publisher_priority=obj.publisher_priority,
                        object_payload=obj.object_payload,
                    )
                    self._state.dispatcher.enqueue(
                        ds.session_id, ds.subscribe_id, ds.track_alias, forwarded,
                    )

            ns_subs = self._state.find_ns_subscribers(ns_tuple)
            for sub_session_id in ns_subs:
                if sub_session_id == self._session_id:
                    continue
                already_direct = any(
                    ds.session_id == sub_session_id
                    for ds in self._state.downstream_subs.get(ftn, [])
                )
                if not already_direct:
                    sub_session = self._state.sessions.get(sub_session_id)
                    if sub_session:
                        forwarded = ObjectStream(
                            subscribe_id=0, track_alias=0,
                            group_id=obj.group_id, object_id=obj.object_id,
                            publisher_priority=obj.publisher_priority,
                            object_payload=obj.object_payload,
                        )
                        self._state.dispatcher.enqueue(sub_session_id, 0, 0, forwarded)

            self._state.dispatcher._pending.set()
            logger.debug(
                "Relay %s: forwarded object for %s/%s (prio=%d, %d bytes)",
                self._session_id, list(ns_tuple), track_name,
                obj.publisher_priority, len(obj.object_payload),
            )
        else:
            # Unresolved object: the publisher sent this proactively (e.g., discovery
            # AgentCard, or a request directed at an agent). Cache it under the
            # publisher's announced namespaces and forward to matching subscribers.
            announced = self._get_announced_namespaces()
            if not announced:
                logger.warning(
                    "Relay %s: unresolvable object with no announced namespaces (alias=%d sub_id=%d)",
                    self._session_id, obj.track_alias, obj.subscribe_id,
                )
                return

            announced.sort(key=len, reverse=True)
            ns_tuple = announced[0]
            synthetic_track = f"_proactive_{self._session_id}"
            self._state.cache.put(obj, ns_tuple, synthetic_track)

            forwarded_to: set[str] = set()

            # Forward to SUBSCRIBE_NAMESPACE subscribers matching any announced namespace
            for ns in announced:
                ns_subs = self._state.find_ns_subscribers(ns)
                for sub_session_id in ns_subs:
                    if sub_session_id == self._session_id or sub_session_id in forwarded_to:
                        continue
                    forwarded_to.add(sub_session_id)
                    sub_session = self._state.sessions.get(sub_session_id)
                    if sub_session:
                        forwarded = ObjectStream(
                            subscribe_id=0, track_alias=0,
                            group_id=obj.group_id, object_id=obj.object_id,
                            publisher_priority=obj.publisher_priority,
                            object_payload=obj.object_payload,
                        )
                        self._state.dispatcher.enqueue(sub_session_id, 0, 0, forwarded)

            # Also forward to downstream subscribers on tracks in matching namespaces.
            # This handles the case where a client publishes a request and the agent
            # has subscribed to its request track via the relay.
            for ns in announced:
                for ftn, ds_list in self._state.downstream_subs.items():
                    if namespace_prefix_match(ns, ftn[0]):
                        for ds in ds_list:
                            if ds.session_id == self._session_id or ds.session_id in forwarded_to:
                                continue
                            forwarded_to.add(ds.session_id)
                            ds_session = self._state.sessions.get(ds.session_id)
                            if ds_session:
                                forwarded = ObjectStream(
                                    subscribe_id=ds.subscribe_id,
                                    track_alias=ds.track_alias,
                                    group_id=obj.group_id, object_id=obj.object_id,
                                    publisher_priority=obj.publisher_priority,
                                    object_payload=obj.object_payload,
                                )
                                self._state.dispatcher.enqueue(
                                    ds.session_id, ds.subscribe_id, ds.track_alias, forwarded,
                                )

            if forwarded_to:
                self._state.dispatcher._pending.set()
            logger.debug(
                "Relay %s: proactive object cached under %s, forwarded to %d sessions",
                self._session_id, list(ns_tuple), len(forwarded_to),
            )

    def _resolve_object_track(self, obj: ObjectStream) -> Optional[FullTrackName]:
        """Resolve an incoming object to its FullTrackName using alias/sub_id mappings."""
        # Check local alias mapping first
        ftn = self._alias_to_track.get(obj.track_alias)
        if ftn:
            return ftn

        # Check via subscribe_id in local subs
        ftn = self._local_subs.get(obj.subscribe_id)
        if ftn:
            return ftn

        # Check upstream subs (the publisher is responding to a relay-initiated subscription)
        for ftn, upstream in self._state.upstream_subs.items():
            if (upstream.publisher_session_id == self._session_id
                    and upstream.relay_subscribe_id == obj.subscribe_id):
                return ftn

        # Fallback: check all downstream subs for matching subscribe_id
        for ftn, ds_list in self._state.downstream_subs.items():
            for ds in ds_list:
                if ds.session_id == self._session_id and ds.track_alias == obj.track_alias:
                    return ftn

        return None

    # ------------------------------------------------------------------
    # Object forwarding
    # ------------------------------------------------------------------

    def forward_object(self, subscribe_id: int, track_alias: int, obj: ObjectStream) -> None:
        """Write an OBJECT_STREAM onto a new server-initiated unidirectional stream."""
        forwarded = ObjectStream(
            subscribe_id=subscribe_id,
            track_alias=track_alias,
            group_id=obj.group_id,
            object_id=obj.object_id,
            publisher_priority=obj.publisher_priority,
            object_payload=obj.object_payload,
        )
        sid = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._quic.send_stream_data(sid, forwarded.encode(), end_stream=True)
        self.transmit()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ctrl_send(self, stream_id: int, data: bytes) -> None:
        self._quic.send_stream_data(stream_id, data)


# ---------------------------------------------------------------------------
# High-level Relay Server
# ---------------------------------------------------------------------------

class MOQTRelay:
    """
    Lightweight MOQT relay for A2A agents.

    All agents connect to this single relay process. The relay forwards
    subscriptions, objects, and discovery between them.

    Usage
    -----
        relay = MOQTRelay(cert_file="moqt_certs/cert.pem", key_file="moqt_certs/key.pem")
        asyncio.run(relay.serve("localhost", 20000))
    """

    def __init__(self, cert_file: str, key_file: str):
        self._cert_file = cert_file
        self._key_file = key_file
        self._state = RelayState()

    def _make_protocol(self, quic, stream_handler=None):
        return MOQTRelaySession(quic, stream_handler, state=self._state)

    async def serve(self, host: str, port: int) -> None:
        config = QuicConfiguration(
            alpn_protocols=[MOQT_ALPN],
            is_client=False,
        )
        config.load_cert_chain(self._cert_file, self._key_file)

        logger.info("MoQ Lite Relay listening on %s:%d (QUIC/MOQT)", host, port)

        _server = await serve(
            host,
            port,
            configuration=config,
            create_protocol=self._make_protocol,
        )

        # Start the priority dispatcher and cache evictor
        dispatch_task = asyncio.create_task(
            self._state.dispatcher.drain(self._state.sessions)
        )
        evict_task = asyncio.create_task(self._evict_cache_loop())

        try:
            await asyncio.Event().wait()
        finally:
            dispatch_task.cancel()
            evict_task.cancel()
            _server.close()

    async def _evict_cache_loop(self) -> None:
        """Periodically evict expired cache entries."""
        while True:
            await asyncio.sleep(10.0)
            evicted = self._state.cache.evict_expired()
            if evicted:
                logger.debug("Relay cache: evicted %d expired entries", evicted)
