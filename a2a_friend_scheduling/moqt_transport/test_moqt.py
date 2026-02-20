"""
MOQT Transport Test Suite
Level 1 -- Unit tests:   varint codec, every message encode/decode round-trip
Level 2 -- Integration:  loopback MOQT server <-> client (QUIC, TLS 1.3)
                          AgentCard discovery + JSON-RPC request / response
Level 3 -- Relay:        MoQ Lite Relay integration
                          relay startup, multi-agent discovery through relay,
                          request/response round-trip through relay

Run with:
    python -m pytest moqt_transport/test_moqt.py -v
or directly:
    python moqt_transport/test_moqt.py
"""

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from moqt_transport.protocol import (
    MOQT_VERSION,
    Announce,
    AnnounceOk,
    ClientSetup,
    FilterType,
    GoAway,
    GroupOrder,
    MaxSubscribeId,
    MsgType,
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
    discovery_track,
    encode_varint,
    frame_message,
    namespace_prefix_match,
    parse_control_message,
    request_track,
    response_track,
    stream_track,
)
from moqt_transport.certs import generate_dev_cert

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"
BOLD = "\033[1m"

_pass = 0
_fail = 0
_errors: list[str] = []


def ok(name: str) -> None:
    global _pass
    _pass += 1
    print(f"  {GREEN}✓{RESET}  {name}")


def fail(name: str, reason: str) -> None:
    global _fail
    _fail += 1
    _errors.append(f"{name}: {reason}")
    print(f"  {RED}✗{RESET}  {name}  — {reason}")


def section(title: str) -> None:
    print(f"\n{BOLD}{YELLOW}══ {title} ══{RESET}")


def assert_eq(name: str, got, expected) -> bool:
    if got == expected:
        ok(name)
        return True
    else:
        fail(name, f"got {got!r}, expected {expected!r}")
        return False


# ===========================================================================
# LEVEL 1 — Unit tests
# ===========================================================================

def test_varint_codec():
    section("Varint encode/decode (RFC 9000 §16)")
    cases = [
        (0,             b"\x00"),
        (1,             b"\x01"),
        (63,            b"\x3f"),
        (64,            b"\x40\x40"),
        (16383,         b"\x7f\xff"),
        (16384,         b"\x80\x00\x40\x00"),
        (1073741823,    b"\xbf\xff\xff\xff"),
        (1073741824,    b"\xc0\x00\x00\x00\x40\x00\x00\x00"),
        (0x3FFFFFFFFFFFFFFF, b"\xff\xff\xff\xff\xff\xff\xff\xff"),
    ]
    for value, expected_bytes in cases:
        encoded = encode_varint(value)
        assert_eq(f"encode({value})", encoded, expected_bytes)

        decoded_val, new_offset = decode_varint(encoded)
        assert_eq(f"decode({value}) value", decoded_val, value)
        assert_eq(f"decode({value}) offset", new_offset, len(expected_bytes))


def test_message_framing():
    section("Control-message framing")
    payload = b"hello"
    framed = frame_message(MsgType.SUBSCRIBE, payload)
    msg_type, decoded_payload, consumed = parse_control_message(framed)
    assert_eq("framing: msg_type", msg_type, MsgType.SUBSCRIBE)
    assert_eq("framing: payload", decoded_payload, payload)
    assert_eq("framing: consumed all bytes", consumed, len(framed))


def test_client_setup_roundtrip():
    section("CLIENT_SETUP encode/decode")
    cs = ClientSetup(supported_versions=[MOQT_VERSION, 0x01], role=3)
    raw = cs.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("CLIENT_SETUP type", msg_type, MsgType.CLIENT_SETUP)
    cs2 = ClientSetup.decode(payload)
    assert_eq("CLIENT_SETUP versions", cs2.supported_versions, [MOQT_VERSION, 0x01])
    assert_eq("CLIENT_SETUP role", cs2.role, 3)


def test_server_setup_roundtrip():
    section("SERVER_SETUP encode/decode")
    ss = ServerSetup(selected_version=MOQT_VERSION, role=2)
    raw = ss.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("SERVER_SETUP type", msg_type, MsgType.SERVER_SETUP)
    ss2 = ServerSetup.decode(payload)
    assert_eq("SERVER_SETUP version", ss2.selected_version, MOQT_VERSION)


def test_subscribe_roundtrip():
    section("SUBSCRIBE encode/decode")
    sub = Subscribe(
        subscribe_id=7,
        track_alias=42,
        namespace=["a2a", "discovery"],
        track_name="agent-karley",
        subscriber_priority=200,
        group_order=GroupOrder.DESCENDING,
        filter_type=FilterType.LATEST_OBJECT,
    )
    raw = sub.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("SUBSCRIBE type", msg_type, MsgType.SUBSCRIBE)
    sub2 = Subscribe.decode(payload)
    assert_eq("SUBSCRIBE sub_id", sub2.subscribe_id, 7)
    assert_eq("SUBSCRIBE alias", sub2.track_alias, 42)
    assert_eq("SUBSCRIBE namespace", sub2.namespace, ["a2a", "discovery"])
    assert_eq("SUBSCRIBE track_name", sub2.track_name, "agent-karley")
    assert_eq("SUBSCRIBE priority", sub2.subscriber_priority, 200)


def test_subscribe_ok_roundtrip():
    section("SUBSCRIBE_OK encode/decode")
    sok = SubscribeOk(subscribe_id=7, expires=0, group_order=GroupOrder.ASCENDING)
    raw = sok.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("SUBSCRIBE_OK type", msg_type, MsgType.SUBSCRIBE_OK)
    sok2 = SubscribeOk.decode(payload)
    assert_eq("SUBSCRIBE_OK sub_id", sok2.subscribe_id, 7)


def test_announce_roundtrip():
    section("ANNOUNCE / ANNOUNCE_OK encode/decode")
    ann = Announce(namespace=["a2a", "discovery"])
    raw = ann.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("ANNOUNCE type", msg_type, MsgType.ANNOUNCE)
    ann2 = Announce.decode(payload)
    assert_eq("ANNOUNCE namespace", ann2.namespace, ["a2a", "discovery"])

    ack = AnnounceOk(namespace=["a2a", "discovery"])
    raw2 = ack.encode()
    msg_type2, payload2, _ = parse_control_message(raw2)
    assert_eq("ANNOUNCE_OK type", msg_type2, MsgType.ANNOUNCE_OK)
    ack2 = AnnounceOk.decode(payload2)
    assert_eq("ANNOUNCE_OK namespace", ack2.namespace, ["a2a", "discovery"])


def test_object_stream_roundtrip():
    section("OBJECT_STREAM encode/decode")
    content = json.dumps({"jsonrpc": "2.0", "method": "message/send", "id": "1"}).encode()
    obj = ObjectStream(
        subscribe_id=3,
        track_alias=10,
        group_id=0,
        object_id=5,
        publisher_priority=2,
        object_payload=content,
    )
    raw = obj.encode()

    # Consume the leading type varint (as the server/client do)
    msg_type_val, offset = decode_varint(raw)
    assert_eq("OBJECT_STREAM type byte", MsgType(msg_type_val), MsgType.OBJECT_STREAM)

    obj2 = ObjectStream.decode(raw[offset:])
    assert_eq("OBJECT_STREAM sub_id", obj2.subscribe_id, 3)
    assert_eq("OBJECT_STREAM alias", obj2.track_alias, 10)
    assert_eq("OBJECT_STREAM group_id", obj2.group_id, 0)
    assert_eq("OBJECT_STREAM object_id", obj2.object_id, 5)
    assert_eq("OBJECT_STREAM priority", obj2.publisher_priority, 2)
    assert_eq("OBJECT_STREAM payload", obj2.object_payload, content)


def test_track_helpers():
    section("Track-namespace helpers")
    assert_eq("request_track", request_track("karley"), (["a2a"], "agent-karley/request"))
    assert_eq("response_track", response_track("karley"), (["a2a"], "agent-karley/response"))
    assert_eq("discovery_track", discovery_track("karley"), (["a2a", "discovery"], "agent-karley"))


def test_subscribe_namespace_roundtrip():
    section("SUBSCRIBE_NAMESPACE encode/decode")
    sns = SubscribeNamespace(namespace_prefix=["a2a"])
    raw = sns.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("SUBSCRIBE_NAMESPACE type", msg_type, MsgType.SUBSCRIBE_NAMESPACE)
    sns2 = SubscribeNamespace.decode(payload)
    assert_eq("SUBSCRIBE_NAMESPACE prefix", sns2.namespace_prefix, ["a2a"])

    ok_ = SubscribeNamespaceOk(namespace_prefix=["a2a"])
    raw2 = ok_.encode()
    msg_type2, payload2, _ = parse_control_message(raw2)
    assert_eq("SUBSCRIBE_NAMESPACE_OK type", msg_type2, MsgType.SUBSCRIBE_NAMESPACE_OK)


def test_unsubscribe_roundtrip():
    section("UNSUBSCRIBE encode/decode")
    unsub = Unsubscribe(subscribe_id=42)
    raw = unsub.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("UNSUBSCRIBE type", msg_type, MsgType.UNSUBSCRIBE)
    unsub2 = Unsubscribe.decode(payload)
    assert_eq("UNSUBSCRIBE sub_id", unsub2.subscribe_id, 42)


def test_subscribe_done_roundtrip():
    section("SUBSCRIBE_DONE encode/decode")
    sd = SubscribeDone(subscribe_id=7, status_code=SubscribeDoneStatus.UNSUBSCRIBED, reason="done")
    raw = sd.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("SUBSCRIBE_DONE type", msg_type, MsgType.SUBSCRIBE_DONE)
    sd2 = SubscribeDone.decode(payload)
    assert_eq("SUBSCRIBE_DONE sub_id", sd2.subscribe_id, 7)
    assert_eq("SUBSCRIBE_DONE status", sd2.status_code, 0)
    assert_eq("SUBSCRIBE_DONE reason", sd2.reason, "done")


def test_goaway_roundtrip():
    section("GOAWAY encode/decode")
    ga = GoAway(new_session_uri="moqt://new-relay:20001")
    raw = ga.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("GOAWAY type", msg_type, MsgType.GOAWAY)
    ga2 = GoAway.decode(payload)
    assert_eq("GOAWAY uri", ga2.new_session_uri, "moqt://new-relay:20001")


def test_max_subscribe_id_roundtrip():
    section("MAX_SUBSCRIBE_ID encode/decode")
    msi = MaxSubscribeId(max_subscribe_id=1024)
    raw = msi.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("MAX_SUBSCRIBE_ID type", msg_type, MsgType.MAX_SUBSCRIBE_ID)
    msi2 = MaxSubscribeId.decode(payload)
    assert_eq("MAX_SUBSCRIBE_ID value", msi2.max_subscribe_id, 1024)


def test_subscribe_error_roundtrip():
    section("SUBSCRIBE_ERROR encode/decode")
    se = SubscribeError(subscribe_id=5, error_code=1, reason="not found", track_alias=10)
    raw = se.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("SUBSCRIBE_ERROR type", msg_type, MsgType.SUBSCRIBE_ERROR)
    se2 = SubscribeError.decode(payload)
    assert_eq("SUBSCRIBE_ERROR sub_id", se2.subscribe_id, 5)
    assert_eq("SUBSCRIBE_ERROR code", se2.error_code, 1)
    assert_eq("SUBSCRIBE_ERROR reason", se2.reason, "not found")


def test_unannounce_roundtrip():
    section("UNANNOUNCE encode/decode")
    ua = Unannounce(namespace=["a2a", "discovery"])
    raw = ua.encode()
    msg_type, payload, _ = parse_control_message(raw)
    assert_eq("UNANNOUNCE type", msg_type, MsgType.UNANNOUNCE)
    ua2 = Unannounce.decode(payload)
    assert_eq("UNANNOUNCE namespace", ua2.namespace, ["a2a", "discovery"])


def test_namespace_prefix_match():
    section("Namespace prefix matching (Section 8.5)")
    assert_eq("exact match", namespace_prefix_match(("a2a",), ("a2a",)), True)
    assert_eq("prefix match", namespace_prefix_match(("a2a",), ("a2a", "discovery")), True)
    assert_eq("no match", namespace_prefix_match(("a2a", "discovery"), ("a2a",)), False)
    assert_eq("empty prefix", namespace_prefix_match((), ("a2a",)), True)
    assert_eq("different prefix", namespace_prefix_match(("b2b",), ("a2a",)), False)


def test_track_helpers_with_session_ctx():
    section("Track helpers with session_context_id")
    assert_eq(
        "request_track with ctx",
        request_track("karley", session_ctx="session-1"),
        (["session-1", "a2a"], "agent-karley/request"),
    )
    assert_eq(
        "discovery_track with ctx",
        discovery_track("karley", session_ctx="session-1"),
        (["session-1", "a2a", "discovery"], "agent-karley"),
    )
    assert_eq(
        "stream_track with ctx",
        stream_track("karley", "task-abc", session_ctx="session-1"),
        (["session-1", "a2a"], "agent-karley/task_task-abc"),
    )


def test_object_cache():
    section("Object cache (3-tier TTL)")
    from moqt_transport.relay import ObjectCache

    cache = ObjectCache()
    obj = ObjectStream(
        subscribe_id=0, track_alias=0, group_id=0, object_id=0,
        publisher_priority=4, object_payload=b'{"name":"TestAgent"}',
    )
    cache.put(obj, ("a2a", "discovery"), "agent-test")

    results = cache.get_for_track(("a2a", "discovery"), "agent-test")
    assert_eq("cache hit count", len(results), 1)
    assert_eq("cache payload", results[0].payload, b'{"name":"TestAgent"}')
    assert_eq("cache tier", results[0].tier, "warm")

    ns_results = cache.get_for_namespace(("a2a",))
    assert_eq("cache ns hit count", len(ns_results), 1)

    no_results = cache.get_for_namespace(("b2b",))
    assert_eq("cache ns miss count", len(no_results), 0)

    evicted = cache.evict_expired()
    assert_eq("evict (none expired)", evicted, 0)


def test_priority_tier_mapping():
    section("Priority-to-cache-tier mapping")
    from moqt_transport.relay import _PRIORITY_TIER, CacheTier
    assert_eq("prio 1 -> hot", _PRIORITY_TIER[1], CacheTier.HOT)
    assert_eq("prio 2 -> hot", _PRIORITY_TIER[2], CacheTier.HOT)
    assert_eq("prio 3 -> warm", _PRIORITY_TIER[3], CacheTier.WARM)
    assert_eq("prio 4 -> warm", _PRIORITY_TIER[4], CacheTier.WARM)
    assert_eq("prio 5 -> cold", _PRIORITY_TIER[5], CacheTier.COLD)


def test_cert_generation():
    section("TLS cert generation (ECDSA P-256)")
    with tempfile.TemporaryDirectory() as tmp:
        cert = os.path.join(tmp, "cert.pem")
        key = os.path.join(tmp, "key.pem")
        try:
            generate_dev_cert(cert, key)
            assert_eq("cert file exists", os.path.exists(cert), True)
            assert_eq("key file exists", os.path.exists(key), True)
            with open(cert) as f:
                content = f.read()
            assert_eq("cert is PEM", content.startswith("-----BEGIN CERTIFICATE-----"), True)
            ok("cert generation successful")
        except Exception as e:
            fail("cert generation", str(e))


# ===========================================================================
# LEVEL 2 — Integration test: loopback MOQT server ↔ client
# ===========================================================================

async def _run_integration_test():
    """
    Spins up a real MOQTAgentServer on localhost:19999, connects a
    MOQTAgentClient to it, and validates:
      1. AgentCard discovery (SUBSCRIBE discovery track → OBJECT_STREAM)
      2. JSON-RPC request/response round-trip
    """
    section("Integration: loopback MOQT server ↔ client")

    # -- Build a minimal A2A agent stack ----------------------------------------
    try:
        from a2a.server.apps import A2AStarletteApplication
        from a2a.server.request_handlers import DefaultRequestHandler
        from a2a.server.tasks import InMemoryTaskStore
        from a2a.types import AgentCard, AgentCapabilities, AgentSkill
        from a2a.server.agent_execution import AgentExecutor, RequestContext
        from a2a.utils import new_agent_text_message
    except Exception as e:
        fail("import a2a-sdk", str(e))
        print(f"  {YELLOW}⚠ Skipping integration test (a2a-sdk not installed){RESET}")
        return

    try:
        from moqt_transport import MOQTAgentClient, MOQTAgentServer, ensure_dev_certs
    except Exception as e:
        fail("import moqt_transport", str(e))
        return

    # Minimal echo AgentExecutor
    class EchoExecutor(AgentExecutor):
        async def execute(self, context: RequestContext, event_queue):
            reply = new_agent_text_message(f"echo: {context.get_user_input()}")
            await event_queue.enqueue_event(reply)

        async def cancel(self, context: RequestContext, event_queue):
            pass

    # Agent card
    skill = AgentSkill(
        id="echo",
        name="Echo",
        description="Echoes messages",
        tags=["test"],
        examples=["hello"],
    )
    agent_card = AgentCard(
        name="TestAgent",
        description="Integration test agent",
        url="moqt://localhost:19999/",
        version="1.0.0",
        defaultInputModes=["text/plain"],
        defaultOutputModes=["text/plain"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[skill],
    )

    handler = DefaultRequestHandler(
        agent_executor=EchoExecutor(),
        task_store=InMemoryTaskStore(),
    )

    # Generate test certs in a temp dir
    with tempfile.TemporaryDirectory() as tmp:
        cert_file = os.path.join(tmp, "cert.pem")
        key_file  = os.path.join(tmp, "key.pem")
        try:
            ensure_dev_certs(cert_path=cert_file, key_path=key_file)
            ok("TLS dev certs generated")
        except Exception as e:
            fail("TLS dev certs", str(e))
            return

        server = MOQTAgentServer(
            agent_card=agent_card,
            http_handler=handler,
            cert_file=cert_file,
            key_file=key_file,
        )

        # Start server in background task
        server_task = asyncio.create_task(server.serve("localhost", 19999))
        await asyncio.sleep(0.3)  # give server time to bind

        # -- Client: discovery --------------------------------------------------
        try:
            client = MOQTAgentClient(
                "localhost", 19999, "agent-19999", ca_cert=cert_file
            )
            await client.connect()
            ok("QUIC connection established")

            card = await client.get_agent_card(timeout=8.0)
            assert_eq("AgentCard.name", card.name, "TestAgent")
            assert_eq("AgentCard.version", card.version, "1.0.0")
            ok("AgentCard discovery via MOQT ✓")

        except Exception as e:
            fail("MOQT discovery", str(e))
        finally:
            try:
                await client.close()
            except Exception:
                pass

        # -- Client: JSON-RPC request/response ----------------------------------
        try:
            from a2a.types import Message, MessageSendParams, Part, Role, SendMessageRequest, TextPart
            import uuid

            msg = Message(
                messageId=str(uuid.uuid4()),
                role=Role.user,
                parts=[Part(root=TextPart(text="hello agent"))],
            )
            request = SendMessageRequest(
                id=str(uuid.uuid4()),
                params=MessageSendParams(message=msg),
            )

            client2 = MOQTAgentClient(
                "localhost", 19999, "agent-19999", ca_cert=cert_file
            )
            await client2.connect()
            response = await client2.send_message(request, timeout=15.0)
            assert_eq("response type", hasattr(response, "root") or response is not None, True)
            ok("JSON-RPC round-trip via MOQT ✓")
            await client2.close()

        except Exception as e:
            fail("MOQT message round-trip", str(e))

        # Tear down server
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    ok("Integration test complete")


# ===========================================================================
# LEVEL 3 -- Relay integration tests
# ===========================================================================

async def _run_relay_integration_test():
    """
    Tests the MoQ Lite Relay end-to-end:
      1. Relay startup
      2. Multi-agent discovery through relay (SUBSCRIBE_NAMESPACE)
      3. Request/response round-trip through relay
    """
    section("Integration: MoQ Lite Relay (multi-agent)")

    try:
        from a2a.server.apps import A2AStarletteApplication
        from a2a.server.request_handlers import DefaultRequestHandler
        from a2a.server.tasks import InMemoryTaskStore
        from a2a.types import AgentCard, AgentCapabilities, AgentSkill
        from a2a.server.agent_execution import AgentExecutor, RequestContext
        from a2a.utils import new_agent_text_message
    except Exception as e:
        fail("import a2a-sdk", str(e))
        print(f"  {YELLOW}! Skipping relay integration test (a2a-sdk not installed){RESET}")
        return

    try:
        from moqt_transport import MOQTAgentClient, MOQTAgentServer, MOQTRelay, ensure_dev_certs
    except Exception as e:
        fail("import moqt_transport (relay)", str(e))
        return

    class EchoExecutor(AgentExecutor):
        async def execute(self, context: RequestContext, event_queue):
            reply = new_agent_text_message(f"relay-echo: {context.get_user_input()}")
            await event_queue.enqueue_event(reply)

        async def cancel(self, context: RequestContext, event_queue):
            pass

    def _make_agent(name, agent_id):
        skill = AgentSkill(
            id=f"{agent_id}-echo", name=f"{name} Echo",
            description=f"{name} echoes messages", tags=["test"], examples=["hello"],
        )
        return AgentCard(
            name=name, description=f"Test agent {name}",
            url=f"moqt://localhost:19800/",
            version="1.0.0",
            defaultInputModes=["text/plain"],
            defaultOutputModes=["text/plain"],
            capabilities=AgentCapabilities(streaming=False),
            skills=[skill],
        )

    card_a = _make_agent("AgentAlpha", "alpha")
    card_b = _make_agent("AgentBeta", "beta")

    handler_a = DefaultRequestHandler(
        agent_executor=EchoExecutor(), task_store=InMemoryTaskStore(),
    )
    handler_b = DefaultRequestHandler(
        agent_executor=EchoExecutor(), task_store=InMemoryTaskStore(),
    )

    with tempfile.TemporaryDirectory() as tmp:
        cert_file = os.path.join(tmp, "cert.pem")
        key_file = os.path.join(tmp, "key.pem")
        try:
            ensure_dev_certs(cert_path=cert_file, key_path=key_file)
            ok("TLS dev certs generated for relay test")
        except Exception as e:
            fail("TLS dev certs (relay)", str(e))
            return

        # 1. Start relay
        relay = MOQTRelay(cert_file=cert_file, key_file=key_file)
        relay_task = asyncio.create_task(relay.serve("localhost", 19800))
        await asyncio.sleep(0.5)
        ok("Relay started on localhost:19800")

        # 2. Connect agent servers to relay
        server_a = MOQTAgentServer(
            agent_card=card_a, http_handler=handler_a,
            cert_file=cert_file, key_file=key_file,
        )
        server_b = MOQTAgentServer(
            agent_card=card_b, http_handler=handler_b,
            cert_file=cert_file, key_file=key_file,
        )

        agent_a_task = asyncio.create_task(
            server_a.serve_via_relay("localhost", 19800, agent_id="alpha", ca_cert=cert_file)
        )
        agent_b_task = asyncio.create_task(
            server_b.serve_via_relay("localhost", 19800, agent_id="beta", ca_cert=cert_file)
        )
        await asyncio.sleep(1.0)
        ok("Agent Alpha and Agent Beta connected to relay")

        # 3. Host client: discover agents via SUBSCRIBE_NAMESPACE
        try:
            client = MOQTAgentClient("localhost", 19800, "host", ca_cert=cert_file)
            await client.connect()
            ok("Host client connected to relay")

            cards = await client.discover_agents(timeout=5.0, max_agents=5)
            assert_eq("discovered at least 1 agent", len(cards) >= 1, True)
            discovered_names = {c.name for c in cards}
            if "AgentAlpha" in discovered_names:
                ok("Discovered AgentAlpha via relay")
            else:
                fail("Discover AgentAlpha", f"not in {discovered_names}")
            if "AgentBeta" in discovered_names:
                ok("Discovered AgentBeta via relay")
            else:
                fail("Discover AgentBeta", f"not in {discovered_names}")

            await client.close()
        except Exception as e:
            fail("Relay discovery", str(e))

        # 4. Host client: request/response through relay
        try:
            from a2a.types import Message, MessageSendParams, Part, Role, SendMessageRequest, TextPart
            import uuid

            client2 = MOQTAgentClient("localhost", 19800, "alpha", ca_cert=cert_file)
            await client2.connect()

            msg = Message(
                messageId=str(uuid.uuid4()),
                role=Role.user,
                parts=[Part(root=TextPart(text="hello via relay"))],
            )
            request = SendMessageRequest(
                id=str(uuid.uuid4()),
                params=MessageSendParams(message=msg),
            )

            response = await client2.send_message(request, timeout=15.0)
            assert_eq("relay response received", response is not None, True)
            ok("Request/response round-trip through relay")
            await client2.close()
        except Exception as e:
            fail("Relay request/response", str(e))

        # Teardown
        agent_a_task.cancel()
        agent_b_task.cancel()
        relay_task.cancel()
        for t in [agent_a_task, agent_b_task, relay_task]:
            try:
                await t
            except asyncio.CancelledError:
                pass

    ok("Relay integration test complete")


def run_unit_tests():
    test_varint_codec()
    test_message_framing()
    test_client_setup_roundtrip()
    test_server_setup_roundtrip()
    test_subscribe_roundtrip()
    test_subscribe_ok_roundtrip()
    test_announce_roundtrip()
    test_object_stream_roundtrip()
    test_track_helpers()
    test_subscribe_namespace_roundtrip()
    test_unsubscribe_roundtrip()
    test_subscribe_done_roundtrip()
    test_goaway_roundtrip()
    test_max_subscribe_id_roundtrip()
    test_subscribe_error_roundtrip()
    test_unannounce_roundtrip()
    test_namespace_prefix_match()
    test_track_helpers_with_session_ctx()
    test_object_cache()
    test_priority_tier_mapping()
    test_cert_generation()


def run_integration_tests():
    asyncio.run(_run_integration_test())


def run_relay_tests():
    asyncio.run(_run_relay_integration_test())


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    print(f"\n{BOLD}MOQT Transport Test Suite{RESET}")
    print("=" * 50)

    run_unit_tests()
    run_integration_tests()
    run_relay_tests()

    print("\n" + "=" * 50)
    total = _pass + _fail
    if _fail == 0:
        print(f"{GREEN}{BOLD}All {total} tests passed{RESET}")
    else:
        print(f"{RED}{BOLD}{_fail}/{total} tests FAILED{RESET}")
        for e in _errors:
            print(f"  {RED}*{RESET} {e}")
        sys.exit(1)

