"""
MoQ Lite Relay -- CLI entry point.

Usage:
    python -m moqt_transport --host localhost --port 20000
    python -m moqt_transport.relay --host 0.0.0.0 --port 20000
"""

import argparse
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from moqt_transport.certs import ensure_dev_certs
from moqt_transport.relay import MOQTRelay


def main():
    parser = argparse.ArgumentParser(
        description="MoQ Lite Relay -- lightweight MOQT relay for A2A agents",
    )
    parser.add_argument("--host", default="localhost", help="Bind address (default: localhost)")
    parser.add_argument("--port", type=int, default=20000, help="Listen port (default: 20000)")
    parser.add_argument("--cert", default=None, help="TLS certificate file (PEM)")
    parser.add_argument("--key", default=None, help="TLS private key file (PEM)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.cert and args.key:
        cert_file, key_file = args.cert, args.key
    else:
        cert_dir = os.path.join(os.path.dirname(__file__), "..", "moqt_certs")
        cert_file, key_file = ensure_dev_certs(
            cert_path=os.path.join(cert_dir, "cert.pem"),
            key_path=os.path.join(cert_dir, "key.pem"),
        )

    relay = MOQTRelay(cert_file=cert_file, key_file=key_file)

    print(f"MoQ Lite Relay starting on {args.host}:{args.port}")
    print(f"  Agents connect via: moqt://{args.host}:{args.port}")
    print(f"  TLS cert: {cert_file}")
    print()

    try:
        asyncio.run(relay.serve(args.host, args.port))
    except KeyboardInterrupt:
        print("\nRelay stopped.")


if __name__ == "__main__":
    main()
