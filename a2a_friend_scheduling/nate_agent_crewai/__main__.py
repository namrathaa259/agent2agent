"""This file serves as the main entry point for the application.

It initializes the A2A server, defines the agent's capabilities,
and starts the server to handle incoming requests.
"""

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
from agent import SchedulingAgent
from agent_executor import SchedulingAgentExecutor
from dotenv import load_dotenv

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


def _parse_moqt_url(url: str) -> tuple[str, int]:
    url = url.rstrip("/")
    for scheme in ("moqt://", "http://", "https://"):
        if url.startswith(scheme):
            url = url[len(scheme):]
            break
    host, _, port_str = url.rpartition(":")
    return (host or url), int(port_str) if port_str.isdigit() else 20000


def main():
    """Entry point for Nate's Scheduling Agent."""
    host = "localhost"
    try:
        if not os.getenv("GOOGLE_API_KEY"):
            raise MissingAPIKeyError("GOOGLE_API_KEY environment variable not set.")

        capabilities = AgentCapabilities(streaming=False)
        skill = AgentSkill(
            id="availability_checker",
            name="Availability Checker",
            description="Check my calendar to see when I'm available for a pickleball game.",
            tags=["schedule", "availability", "calendar"],
            examples=[
                "Are you free tomorrow?",
                "Can you play pickleball next Tuesday at 5pm?",
            ],
        )

        moqt_port = 20003
        card_url = _RELAY_URL if _RELAY_URL else f"moqt://{host}:{moqt_port}/"
        agent_card = AgentCard(
            name="Nate Agent",
            description="A friendly agent to help you schedule a pickleball game with Nate.",
            url=card_url,
            version="1.0.0",
            defaultInputModes=SchedulingAgent.SUPPORTED_CONTENT_TYPES,
            defaultOutputModes=SchedulingAgent.SUPPORTED_CONTENT_TYPES,
            capabilities=capabilities,
            skills=[skill],
        )

        request_handler = DefaultRequestHandler(
            agent_executor=SchedulingAgentExecutor(),
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
            logger.info("Nate Agent: connecting to relay %s:%d", relay_host, relay_port)
            asyncio.run(server.serve_via_relay(relay_host, relay_port, agent_id="nate", ca_cert=cert_file))
        else:
            logger.info("Nate Agent: direct listen on %s:%d", host, moqt_port)
            asyncio.run(server.serve(host, moqt_port))

    except MissingAPIKeyError as e:
        logger.error(f"Error: {e}")
        exit(1)
    except Exception as e:
        logger.error(f"An error occurred during server startup: {e}")
        exit(1)


if __name__ == "__main__":
    main()
