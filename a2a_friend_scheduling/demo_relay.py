"""
MoQ Lite Relay -- Interactive Discovery Demo

Starts the relay + two mock agents, then shows inter-agent discovery
and a request/response in real time. No Google API key required.

Usage:
    python demo_relay.py

What it demonstrates:
  1. Relay starts on localhost:20000
  2. Agent "karley" and agent "nate" connect and announce themselves
  3. A "host" client does SUBSCRIBE_NAMESPACE discovery and sees both cards
  4. Host sends a message to karley and gets a reply -- all through the relay
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(__file__))

# Show INFO from our modules only
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("moqt_transport").setLevel(logging.INFO)

from moqt_transport import MOQTAgentClient, MOQTAgentServer, MOQTRelay, ensure_dev_certs

RELAY_PORT = 20000
BOLD = "\033[1m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def banner(msg: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {msg}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}")


def step(msg: str) -> None:
    print(f"  {GREEN}▶{RESET} {msg}")


async def run_demo():
    # ------------------------------------------------------------------
    # 1. Import A2A SDK types
    # ------------------------------------------------------------------
    try:
        from a2a.server.request_handlers import DefaultRequestHandler
        from a2a.server.tasks import InMemoryTaskStore
        from a2a.types import (
            AgentCard, AgentCapabilities, AgentSkill,
            Message, MessageSendParams, Part, Role,
            SendMessageRequest, TextPart,
        )
        from a2a.server.agent_execution import AgentExecutor, RequestContext
        from a2a.utils import new_agent_text_message
    except ImportError:
        print("ERROR: a2a-sdk not installed. Run: pip install a2a-sdk")
        return

    # ------------------------------------------------------------------
    # 2. Define minimal echo agents
    # ------------------------------------------------------------------
    class EchoExecutor(AgentExecutor):
        def __init__(self, name: str):
            self.name = name

        async def execute(self, context: RequestContext, event_queue):
            user_input = context.get_user_input()
            reply = new_agent_text_message(f"[{self.name}] Got: {user_input!r}")
            await event_queue.enqueue_event(reply)

        async def cancel(self, context: RequestContext, event_queue):
            pass

    def make_card(name: str, agent_id: str) -> AgentCard:
        return AgentCard(
            name=name,
            description=f"Demo agent: {name}",
            url=f"moqt://localhost:{RELAY_PORT}/",
            version="1.0.0",
            defaultInputModes=["text/plain"],
            defaultOutputModes=["text/plain"],
            capabilities=AgentCapabilities(streaming=False),
            skills=[AgentSkill(id=agent_id, name=name, description=name, tags=["demo"], examples=["hello"])],
        )

    # ------------------------------------------------------------------
    # 3. Create TLS certs (shared, reuse existing ones if present)
    # ------------------------------------------------------------------
    cert_dir = os.path.join(os.path.dirname(__file__), "moqt_certs")
    os.makedirs(cert_dir, exist_ok=True)
    cert_file, key_file = ensure_dev_certs(
        cert_path=os.path.join(cert_dir, "cert.pem"),
        key_path=os.path.join(cert_dir, "key.pem"),
    )

    banner("Step 1 — Start MoQ Lite Relay")
    step(f"Relay starting on localhost:{RELAY_PORT} (QUIC/MOQT)")
    relay = MOQTRelay(cert_file=cert_file, key_file=key_file)
    relay_task = asyncio.create_task(relay.serve("localhost", RELAY_PORT))
    await asyncio.sleep(0.5)
    step(f"Relay is up. Agents connect via: moqt://localhost:{RELAY_PORT}")

    # ------------------------------------------------------------------
    # 4. Connect friend agents to relay
    # ------------------------------------------------------------------
    banner("Step 2 — Friend Agents Connect to Relay")

    karley_card = make_card("Karley Agent", "karley")
    nate_card = make_card("Nate Agent", "nate")

    karley_handler = DefaultRequestHandler(
        agent_executor=EchoExecutor("Karley"), task_store=InMemoryTaskStore(),
    )
    nate_handler = DefaultRequestHandler(
        agent_executor=EchoExecutor("Nate"), task_store=InMemoryTaskStore(),
    )

    karley_server = MOQTAgentServer(
        agent_card=karley_card, http_handler=karley_handler,
        cert_file=cert_file, key_file=key_file,
    )
    nate_server = MOQTAgentServer(
        agent_card=nate_card, http_handler=nate_handler,
        cert_file=cert_file, key_file=key_file,
    )

    step("Karley Agent connecting to relay...")
    karley_task = asyncio.create_task(
        karley_server.serve_via_relay("localhost", RELAY_PORT, agent_id="karley", ca_cert=cert_file)
    )
    await asyncio.sleep(0.8)
    step("Karley Agent: connected, ANNOUNCE'd ['a2a'], published AgentCard")

    step("Nate Agent connecting to relay...")
    nate_task = asyncio.create_task(
        nate_server.serve_via_relay("localhost", RELAY_PORT, agent_id="nate", ca_cert=cert_file)
    )
    await asyncio.sleep(0.8)
    step("Nate Agent: connected, ANNOUNCE'd ['a2a'], published AgentCard")

    # ------------------------------------------------------------------
    # 5. Host discovers agents via SUBSCRIBE_NAMESPACE
    # ------------------------------------------------------------------
    banner("Step 3 — Host Agent Discovers Friends via SUBSCRIBE_NAMESPACE")
    step("Host connecting to relay...")
    host_client = MOQTAgentClient("localhost", RELAY_PORT, "host", ca_cert=cert_file)
    await host_client.connect()
    step("Host: QUIC + MOQT handshake complete")

    step("Host: sending SUBSCRIBE_NAMESPACE ['a2a', 'discovery'] ...")
    cards = await host_client.discover_agents(timeout=4.0, max_agents=5)
    print()
    if cards:
        step(f"Host received {len(cards)} AgentCard(s) from relay cache:")
        for card in cards:
            print(f"      {YELLOW}→ {card.name}{RESET} — {card.description}")
            print(f"        Skills: {[s.name for s in card.skills]}")
    else:
        print("  No agents discovered (try increasing the sleep below)")

    await host_client.close()

    # ------------------------------------------------------------------
    # 6. Request/response through relay
    # ------------------------------------------------------------------
    banner("Step 4 — Request/Response Through Relay")

    host_client2 = MOQTAgentClient("localhost", RELAY_PORT, "karley", ca_cert=cert_file)
    await host_client2.connect()

    msg = Message(
        messageId=str(uuid.uuid4()),
        role=Role.user,
        parts=[Part(root=TextPart(text="Are you free Saturday?"))],
    )
    request = SendMessageRequest(
        id=str(uuid.uuid4()),
        params=MessageSendParams(message=msg),
    )

    step("Host → Relay → Karley: 'Are you free Saturday?'")
    response = await host_client2.send_message(request, timeout=10.0)
    step(f"Karley → Relay → Host: response received ({response is not None})")

    if response and hasattr(response, "root"):
        result = response.root
        if hasattr(result, "result"):
            print(f"\n      {YELLOW}Response:{RESET} {result.result}")

    await host_client2.close()

    # ------------------------------------------------------------------
    # 7. Teardown
    # ------------------------------------------------------------------
    banner("Demo Complete")
    step("Stopping agents and relay...")
    karley_task.cancel()
    nate_task.cancel()
    relay_task.cancel()
    for t in [karley_task, nate_task, relay_task]:
        try:
            await t
        except asyncio.CancelledError:
            pass
    step("Done.")


if __name__ == "__main__":
    asyncio.run(run_demo())
