import asyncio
import logging
import os
import sys

from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)
from agent import create_agent
from agent_executor import KarleyAgentExecutor
from dotenv import load_dotenv
from google.adk.artifacts import InMemoryArtifactService
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService

# MOQT transport (replaces HTTP/uvicorn)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from moqt_transport import MOQTAgentServer, ensure_dev_certs

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set MOQT_RELAY_URL=moqt://localhost:20000 in .env to use relay mode.
_RELAY_URL = os.getenv("MOQT_RELAY_URL")


class MissingAPIKeyError(Exception):
    """Exception for missing API key."""

    pass


def _parse_moqt_url(url: str) -> tuple[str, int]:
    url = url.rstrip("/")
    for scheme in ("moqt://", "http://", "https://"):
        if url.startswith(scheme):
            url = url[len(scheme):]
            break
    host, _, port_str = url.rpartition(":")
    return (host or url), int(port_str) if port_str.isdigit() else 20000


def main():
    """Starts the agent server."""
    host = "localhost"
    try:
        # Check for API key only if Vertex AI is not configured
        if not os.getenv("GOOGLE_GENAI_USE_VERTEXAI") == "TRUE":
            if not os.getenv("GOOGLE_API_KEY"):
                raise MissingAPIKeyError(
                    "GOOGLE_API_KEY environment variable not set and GOOGLE_GENAI_USE_VERTEXAI is not TRUE."
                )

        capabilities = AgentCapabilities(streaming=True)
        skill = AgentSkill(
            id="check_schedule",
            name="Check Karley's Schedule",
            description="Checks Karley's availability for a pickleball game on a given date.",
            tags=["scheduling", "calendar"],
            examples=["Is Karley free to play pickleball tomorrow?"],
        )

        # In relay mode the AgentCard URL points at the relay so the host can
        # route messages through it; in direct mode it points at this agent's
        # own QUIC listener port.
        moqt_port = 20002
        card_url = _RELAY_URL if _RELAY_URL else f"moqt://{host}:{moqt_port}/"
        agent_card = AgentCard(
            name="Karley Agent",
            description="An agent that manages Karley's schedule for pickleball games.",
            url=card_url,
            version="1.0.0",
            defaultInputModes=["text/plain"],
            defaultOutputModes=["text/plain"],
            capabilities=capabilities,
            skills=[skill],
        )

        adk_agent = create_agent()
        runner = Runner(
            app_name=agent_card.name,
            agent=adk_agent,
            artifact_service=InMemoryArtifactService(),
            session_service=InMemorySessionService(),
            memory_service=InMemoryMemoryService(),
        )
        agent_executor = KarleyAgentExecutor(runner)

        request_handler = DefaultRequestHandler(
            agent_executor=agent_executor,
            task_store=InMemoryTaskStore(),
        )

        cert_file, key_file = ensure_dev_certs(
            cert_path=os.path.join(os.path.dirname(__file__), "..", "moqt_certs", "cert.pem"),
            key_path=os.path.join(os.path.dirname(__file__), "..", "moqt_certs", "key.pem"),
        )

        server = MOQTAgentServer(
            agent_card=agent_card,
            http_handler=request_handler,
            cert_file=cert_file,
            key_file=key_file,
        )

        if _RELAY_URL:
            relay_host, relay_port = _parse_moqt_url(_RELAY_URL)
            logger.info("Karley Agent: connecting to relay %s:%d", relay_host, relay_port)
            asyncio.run(server.serve_via_relay(relay_host, relay_port, agent_id="karley", ca_cert=cert_file))
        else:
            logger.info("Karley Agent: direct listen on %s:%d", host, moqt_port)
            asyncio.run(server.serve(host, moqt_port))

    except MissingAPIKeyError as e:
        logger.error(f"Error: {e}")
        exit(1)
    except Exception as e:
        logger.error(f"An error occurred during server startup: {e}")
        exit(1)


if __name__ == "__main__":
    main()
