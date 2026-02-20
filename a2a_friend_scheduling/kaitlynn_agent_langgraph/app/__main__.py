import asyncio
import logging
import os
import sys

import httpx
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryPushNotifier, InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)
from app.agent import KaitlynAgent
from app.agent_executor import KaitlynAgentExecutor
from dotenv import load_dotenv

# MOQT transport (replaces HTTP/uvicorn)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
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
    """Starts Kaitlyn's Agent server."""
    host = "localhost"
    try:
        if not os.getenv("AZURE_OPENAI_API_KEY"):
            raise MissingAPIKeyError(
                "AZURE_OPENAI_API_KEY environment variable not set. "
                "Also ensure AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT_NAME are set."
            )

        capabilities = AgentCapabilities(streaming=True, pushNotifications=True)
        skill = AgentSkill(
            id="schedule_pickleball",
            name="Pickleball Scheduling Tool",
            description="Helps with finding Kaitlyn's availability for pickleball",
            tags=["scheduling", "pickleball"],
            examples=["Are you free to play pickleball on Saturday?"],
        )

        moqt_port = 20004
        card_url = _RELAY_URL if _RELAY_URL else f"moqt://{host}:{moqt_port}/"
        agent_card = AgentCard(
            name="Kaitlynn Agent",
            description="Helps with scheduling pickleball games",
            url=card_url,
            version="1.0.0",
            defaultInputModes=KaitlynAgent.SUPPORTED_CONTENT_TYPES,
            defaultOutputModes=KaitlynAgent.SUPPORTED_CONTENT_TYPES,
            capabilities=capabilities,
            skills=[skill],
        )

        httpx_client = httpx.AsyncClient()
        request_handler = DefaultRequestHandler(
            agent_executor=KaitlynAgentExecutor(),
            task_store=InMemoryTaskStore(),
            push_notifier=InMemoryPushNotifier(httpx_client),
        )

        cert_file, key_file = ensure_dev_certs(
            cert_path=os.path.join(os.path.dirname(__file__), "..", "..", "moqt_certs", "cert.pem"),
            key_path=os.path.join(os.path.dirname(__file__), "..", "..", "moqt_certs", "key.pem"),
        )

        server = MOQTAgentServer(
            agent_card=agent_card,
            http_handler=request_handler,
            cert_file=cert_file,
            key_file=key_file,
        )

        if _RELAY_URL:
            relay_host, relay_port = _parse_moqt_url(_RELAY_URL)
            logger.info("Kaitlynn Agent: connecting to relay %s:%d", relay_host, relay_port)
            asyncio.run(server.serve_via_relay(relay_host, relay_port, agent_id="kaitlynn", ca_cert=cert_file))
        else:
            logger.info("Kaitlynn Agent: direct listen on %s:%d", host, moqt_port)
            asyncio.run(server.serve(host, moqt_port))

    except MissingAPIKeyError as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred during server startup: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
