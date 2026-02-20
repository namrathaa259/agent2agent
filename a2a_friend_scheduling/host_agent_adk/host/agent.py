import asyncio
import json
import os
import sys
import uuid
from datetime import datetime
from typing import Any, AsyncIterable, List

# MOQT transport — replaces A2ACardResolver + httpx
# __file__ = host_agent_adk/host/agent.py  →  "../.." = a2a_friend_scheduling/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from moqt_transport import MOQTAgentClient, MOQTCardResolver

# Set MOQT_RELAY_URL=moqt://localhost:20000 in .env to enable relay mode.
# In relay mode the host discovers all friend agents automatically via
# SUBSCRIBE_NAMESPACE; no hardcoded per-agent ports are needed.
_RELAY_URL = os.getenv("MOQT_RELAY_URL")

from a2a.types import (
    AgentCard,
    MessageSendParams,
    SendMessageRequest,
    SendMessageResponse,
    SendMessageSuccessResponse,
    Task,
)
from dotenv import load_dotenv
from google.adk import Agent
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.models.lite_llm import LiteLlm
from google.adk.artifacts import InMemoryArtifactService
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from .pickleball_tools import (
    book_pickleball_court,
    list_court_availabilities,
)
from .remote_agent_connection import RemoteAgentConnections

load_dotenv()


def _build_llm():
    """
    Return the LLM for the Host Agent.

    Priority:
      1. Azure OpenAI  — when AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT are set
      2. Gemini        — fallback (requires GOOGLE_API_KEY)
    """
    azure_key = os.getenv("AZURE_OPENAI_API_KEY")
    azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    if azure_key and azure_endpoint:
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4o")
        api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")
        return LiteLlm(
            model=f"azure/{deployment}",
            api_key=azure_key,
            api_base=azure_endpoint,
            api_version=api_version,
        )
    return "gemini-2.5-flash"


# ---------------------------------------------------------------------------
# MOQT URL helpers
# ---------------------------------------------------------------------------

def _parse_moqt_url(url: str) -> tuple[str, int]:
    """Parse 'moqt://host:port' → (host, port). Falls back to HTTP-style URLs."""
    url = url.rstrip("/")
    for scheme in ("moqt://", "http://", "https://"):
        if url.startswith(scheme):
            url = url[len(scheme):]
            break
    if ":" in url:
        host, port_str = url.rsplit(":", 1)
        return host, int(port_str)
    return url, 9999  # default MOQT port


def _agent_id_from_url(url: str) -> str:
    """Derive a stable agent-id string from the URL (used for track names)."""
    _, port = _parse_moqt_url(url)
    return f"agent-{port}"


class HostAgent:
    """The Host agent."""

    def __init__(self):
        self.remote_agent_connections: dict[str, RemoteAgentConnections] = {}
        self.cards: dict[str, AgentCard] = {}
        self.agents: str = ""
        # _connections_ready: True once agents have been discovered.
        # _connecting: True while a discovery coroutine is in-flight (prevents
        #              duplicate concurrent discoveries).
        self._connections_ready = False
        self._connecting = False
        self._agent = self.create_agent()
        self._user_id = "host_agent"
        self._runner = Runner(
            app_name=self._agent.name,
            agent=self._agent,
            artifact_service=InMemoryArtifactService(),
            session_service=InMemorySessionService(),
            memory_service=InMemoryMemoryService(),
        )

    async def _ensure_connections(self) -> None:
        """
        Open MOQT connections / run relay discovery.

        Safe to call concurrently: the _connecting flag prevents duplicate
        in-flight discoveries.  Sets _connections_ready when agents are found.
        """
        if self._connections_ready:
            return
        if self._connecting:
            # Another coroutine is already discovering — wait a moment then return.
            await asyncio.sleep(0.5)
            return
        self._connecting = True
        try:
            if _RELAY_URL:
                await self._async_init_via_relay(_RELAY_URL)
            else:
                await self._async_init_components([
                    "moqt://localhost:20002",  # Karley Agent
                    "moqt://localhost:20003",  # Nate Agent
                    "moqt://localhost:20004",  # Kaitlynn Agent
                ])
            self._connections_ready = True
        except Exception as exc:
            print(f"WARNING: Could not connect to friend agents: {exc}")
            self.agents = "No friends available right now — are the agents running?"
        finally:
            self._connecting = False

    async def _async_init_components(self, remote_agent_addresses: List[str]):
        _ca_cert_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "moqt_certs", "cert.pem"
        )
        ca_cert = _ca_cert_path if os.path.exists(_ca_cert_path) else None

        for address in remote_agent_addresses:
            # Parse "moqt://host:port" into components for MOQTCardResolver
            host, port = _parse_moqt_url(address)
            # agent_id is a placeholder; actual id discovered from AgentCard name
            agent_id = _agent_id_from_url(address)
            card_resolver = MOQTCardResolver(host, port, agent_id, ca_cert=ca_cert)
            try:
                card = await card_resolver.get_agent_card()
                remote_connection = RemoteAgentConnections(
                    agent_card=card, agent_url=address
                )
                self.remote_agent_connections[card.name] = remote_connection
                self.cards[card.name] = card
            except Exception as e:
                print(f"ERROR: Failed to initialize connection for {address}: {e}")

        agent_info = [
            json.dumps({"name": card.name, "description": card.description})
            for card in self.cards.values()
        ]
        print("agent_info:", agent_info)
        self.agents = "\n".join(agent_info) if agent_info else "No friends found"

    @classmethod
    async def create(
        cls,
        remote_agent_addresses: List[str],
    ):
        instance = cls()
        await instance._async_init_components(remote_agent_addresses)
        return instance

    @classmethod
    async def create_via_relay(cls, relay_url: str):
        """
        Relay mode: discover all friend agents automatically via
        SUBSCRIBE_NAMESPACE, then wire up RemoteAgentConnections pointing
        at the relay so that every send_message is routed through it.
        """
        instance = cls()
        await instance._async_init_via_relay(relay_url)
        return instance

    async def _async_init_via_relay(self, relay_url: str):
        ca_cert_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "moqt_certs", "cert.pem"
        )
        ca_cert = ca_cert_path if os.path.exists(ca_cert_path) else None

        relay_host, relay_port = _parse_moqt_url(relay_url)
        print(f"Host Agent: discovering friends via relay {relay_host}:{relay_port} …")

        discovery_client = MOQTAgentClient(
            relay_host, relay_port, "host-discovery", ca_cert=ca_cert
        )
        await discovery_client.connect()
        try:
            cards = await discovery_client.discover_agents(timeout=6.0, max_agents=10)
        finally:
            await discovery_client.close()

        if not cards:
            print("WARNING: No agents discovered via relay. Is the relay running?")

        for card in cards:
            # All outbound messages are routed through the relay; the
            # agent_id (derived from card.name) tells the relay who to
            # deliver to.
            remote_connection = RemoteAgentConnections(
                agent_card=card, agent_url=relay_url
            )
            self.remote_agent_connections[card.name] = remote_connection
            self.cards[card.name] = card

        agent_info = [
            json.dumps({"name": card.name, "description": card.description})
            for card in self.cards.values()
        ]
        print("agent_info:", agent_info)
        self.agents = "\n".join(agent_info) if agent_info else "No friends found"

    def create_agent(self) -> Agent:
        return Agent(
            model=_build_llm(),
            name="Host_Agent",
            instruction=self.root_instruction,
            description="This Host agent orchestrates scheduling pickleball with friends.",
            tools=[
                self.send_message,
                book_pickleball_court,
                list_court_availabilities,
            ],
        )

    def root_instruction(self, context: ReadonlyContext) -> str:
        # Kick off MOQT discovery the first time the instruction is rendered
        # (i.e., on the very first user message).  The event loop is running
        # at this point because we are inside an ADK/uvicorn request handler.
        if not self._connections_ready and not self._connecting:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._ensure_connections())
            except Exception:
                pass

        if self._connections_ready and self.agents:
            agents_section = self.agents
        elif self._connecting:
            agents_section = (
                "⏳ Discovering friend agents via the relay — this takes a few seconds. "
                "Please reply with your request again and I will be ready."
            )
        else:
            agents_section = "No friend agents are currently connected."

        return f"""
        **Role:** You are the Host Agent, an expert scheduler for pickleball games. Your primary function is to coordinate with friend agents to find a suitable time to play and then book a court.

        **Core Directives:**

        *   **Initiate Planning:** When asked to schedule a game, first determine who to invite and the desired date range from the user.
        *   **Task Delegation:** Use the `send_message` tool to ask each friend for their availability.
            *   Frame your request clearly (e.g., "Are you available for pickleball between 2024-08-01 and 2024-08-03?").
            *   Make sure you pass in the official name of the friend agent for each message request.
        *   **Analyze Responses:** Once you have availability from all friends, analyze the responses to find common timeslots.
        *   **Check Court Availability:** Before proposing times to the user, use the `list_court_availabilities` tool to ensure the court is also free at the common timeslots.
        *   **Propose and Confirm:** Present the common, court-available timeslots to the user for confirmation.
        *   **Book the Court:** After the user confirms a time, use the `book_pickleball_court` tool to make the reservation. This tool requires a `start_time` and an `end_time`.
        *   **Transparent Communication:** Relay the final booking confirmation, including the booking ID, to the user. Do not ask for permission before contacting friend agents.
        *   **Tool Reliance:** Strictly rely on available tools to address user requests. Do not generate responses based on assumptions.
        *   **Readability:** Make sure to respond in a concise and easy to read format (bullet points are good).
        *   Each available agent represents a friend. So Bob_Agent represents Bob.
        *   When asked for which friends are available, you should return the names of the available friends (aka the agents that are active).
        *   If agent discovery is still in progress, tell the user politely and ask them to repeat their request in a moment.

        **Today's Date (YYYY-MM-DD):** {datetime.now().strftime("%Y-%m-%d")}

        <Available Agents>
        {agents_section}
        </Available Agents>
        """

    async def stream(
        self, query: str, session_id: str
    ) -> AsyncIterable[dict[str, Any]]:
        """
        Streams the agent's response to a given query.
        """
        await self._ensure_connections()
        session = await self._runner.session_service.get_session(
            app_name=self._agent.name,
            user_id=self._user_id,
            session_id=session_id,
        )
        content = types.Content(role="user", parts=[types.Part.from_text(text=query)])
        if session is None:
            session = await self._runner.session_service.create_session(
                app_name=self._agent.name,
                user_id=self._user_id,
                state={},
                session_id=session_id,
            )
        async for event in self._runner.run_async(
            user_id=self._user_id, session_id=session.id, new_message=content
        ):
            if event.is_final_response():
                response = ""
                if (
                    event.content
                    and event.content.parts
                    and event.content.parts[0].text
                ):
                    response = "\n".join(
                        [p.text for p in event.content.parts if p.text]
                    )
                yield {
                    "is_task_complete": True,
                    "content": response,
                }
            else:
                yield {
                    "is_task_complete": False,
                    "updates": "The host agent is thinking...",
                }

    async def send_message(self, agent_name: str, task: str, tool_context: ToolContext):
        """Sends a task to a remote friend agent."""
        await self._ensure_connections()
        if agent_name not in self.remote_agent_connections:
            raise ValueError(f"Agent {agent_name} not found")
        client = self.remote_agent_connections[agent_name]

        if not client:
            raise ValueError(f"Client not available for {agent_name}")

        # Simplified task and context ID management
        state = tool_context.state
        task_id = state.get("task_id", str(uuid.uuid4()))
        context_id = state.get("context_id", str(uuid.uuid4()))
        message_id = str(uuid.uuid4())

        payload = {
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": task}],
                "messageId": message_id,
                "taskId": task_id,
                "contextId": context_id,
            },
        }

        message_request = SendMessageRequest(
            id=message_id, params=MessageSendParams.model_validate(payload)
        )
        send_response: SendMessageResponse = await client.send_message(message_request)
        print("send_response", send_response)

        if not isinstance(
            send_response.root, SendMessageSuccessResponse
        ) or not isinstance(send_response.root.result, Task):
            print("Received a non-success or non-task response. Cannot proceed.")
            return

        response_content = send_response.root.model_dump_json(exclude_none=True)
        json_content = json.loads(response_content)

        resp = []
        if json_content.get("result", {}).get("artifacts"):
            for artifact in json_content["result"]["artifacts"]:
                if artifact.get("parts"):
                    resp.extend(artifact["parts"])
        return resp


# ---------------------------------------------------------------------------
# Module-level root_agent required by `adk web`.
#
# We create the HostAgent synchronously with zero network I/O so that the
# module always imports cleanly — even when no friend agents or relay are
# running yet.  The actual MOQT connections are established lazily on the
# first call to stream() or send_message() via _ensure_connections().
# ---------------------------------------------------------------------------
print("Initialising HostAgent (lazy MOQT connections)…")
_host_instance = HostAgent()
root_agent = _host_instance.create_agent()
print("HostAgent ready — friend-agent connections will be established on first request.")
