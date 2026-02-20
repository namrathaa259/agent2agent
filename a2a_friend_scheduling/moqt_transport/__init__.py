"""
moqt_transport -- MOQT (Media over QUIC Transport) layer for A2A agents.

Implements draft-a2a-moqt-transport-00 on top of draft-ietf-moq-transport-14.

Public API
    Server side (friend agents):
      MOQTAgentServer   -- replaces A2AStarletteApplication + uvicorn
                           supports both direct mode and relay-connected mode

    Client side (host agent):
      MOQTAgentClient   -- replaces A2AClient + httpx
      MOQTCardResolver  -- replaces A2ACardResolver

    Relay:
      MOQTRelay         -- lightweight MoQT relay (MoQ Lite)

    TLS (QUIC requires TLS 1.3):
      ensure_dev_certs  -- generate self-signed ECDSA P-256 cert for local dev
"""

from .certs import ensure_dev_certs
from .client import MOQTAgentClient, MOQTCardResolver
from .relay import MOQTRelay
from .server import MOQTAgentServer

__all__ = [
    "MOQTAgentServer",
    "MOQTAgentClient",
    "MOQTCardResolver",
    "MOQTRelay",
    "ensure_dev_certs",
]



