"""
Remote agent connection — MOQT transport edition.
Replaces the previous httpx / A2AClient (HTTP) implementation.
"""

import os
import sys
from typing import Callable

from a2a.types import (
    AgentCard,
    SendMessageRequest,
    SendMessageResponse,
    Task,
    TaskArtifactUpdateEvent,
    TaskStatusUpdateEvent,
)
from dotenv import load_dotenv

# Shared MOQT transport library
# __file__ = host_agent_adk/host/remote_agent_connection.py  →  "../.." = a2a_friend_scheduling/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from moqt_transport import MOQTAgentClient

load_dotenv()

TaskCallbackArg = Task | TaskStatusUpdateEvent | TaskArtifactUpdateEvent
TaskUpdateCallback = Callable[[TaskCallbackArg, AgentCard], Task]

# Shared dev CA cert (generated alongside the agent certs)
_CA_CERT = os.path.join(
    os.path.dirname(__file__), "..", "..", "moqt_certs", "cert.pem"
)


class RemoteAgentConnections:
    """
    Manages a MOQT connection to a single remote friend agent.

    Replaces:
        httpx.AsyncClient + A2AClient (HTTP/JSON-RPC over TCP)
    With:
        MOQTAgentClient (MOQT/JSON-RPC over QUIC)
    """

    def __init__(self, agent_card: AgentCard, agent_url: str):
        print(f"agent_card: {agent_card}")
        print(f"agent_url: {agent_url}")  # now a moqt:// URL

        self.card = agent_card
        self.conversation_name = None
        self.conversation = None
        self.pending_tasks = set()

        # Parse "moqt://host:port/" → host, port, agent_id
        # agent_id is derived from the agent name (lowercased)
        host, port = _parse_moqt_url(agent_url)
        agent_id = agent_card.name.lower().replace(" agent", "").replace(" ", "_")

        ca_cert = _CA_CERT if os.path.exists(_CA_CERT) else None
        self._moqt_client = MOQTAgentClient(
            host=host,
            port=port,
            agent_id=agent_id,
            ca_cert=ca_cert,
        )

    def get_agent(self) -> AgentCard:
        return self.card

    async def send_message(
        self, message_request: SendMessageRequest
    ) -> SendMessageResponse:
        """
        Send an A2A message to the remote friend agent via MOQT.
        Opens a fresh QUIC connection per request (stateless for simplicity).
        """
        async with self._moqt_client as client:
            return await client.send_message(message_request)


def _parse_moqt_url(url: str) -> tuple[str, int]:
    """
    Parse a moqt://host:port[/path] URL into (host, port).
    Falls back gracefully for http:// URLs (backwards compat during transition).
    """
    url = url.rstrip("/")
    if url.startswith("moqt://"):
        hostport = url[len("moqt://"):]
    elif url.startswith("http://"):
        hostport = url[len("http://"):]
    else:
        hostport = url

    # strip any path component
    hostport = hostport.split("/")[0]

    if ":" in hostport:
        host, port_str = hostport.rsplit(":", 1)
        return host, int(port_str)
    return hostport, 20002  # default MOQT port
