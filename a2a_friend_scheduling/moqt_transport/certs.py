"""
TLS Certificate generation for QUIC/MOQT transport.

⚠️  SECURITY REVIEW (codeguard-1-digital-certificates + codeguard-1-crypto-algorithms):
    Certificates generated here are SELF-SIGNED and intended ONLY for
    local development / testing.  NEVER deploy these to a public-facing service.

    Properties of generated certificates:
    - Algorithm : ECDSA with P-256 curve  (meets ≥ 256-bit EC key requirement)
    - Signature : SHA-256                  (SHA-2 family — compliant)
    - Issuer = Subject: self-signed        (acceptable for dev/internal only)
    - Validity: 90 days
    - TLS version enforced by QUIC: 1.3    (compliant)
"""

import ipaddress
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_dev_cert(cert_path: str, key_path: str, hostname: str = "localhost") -> None:
    """
    Generate a self-signed ECDSA P-256 / SHA-256 certificate for local QUIC use.

    Args:
        cert_path: Path to write the PEM certificate.
        key_path:  Path to write the PEM private key.
        hostname:  CN / SAN hostname (default: "localhost").

    ⚠️  This certificate is self-signed.  It MUST NOT be used in production.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required for certificate generation. "
            "Install it with: pip install cryptography"
        ) from exc

    # ECDSA P-256 — meets security guidelines (≥ 256-bit EC key)
    private_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "A2A MOQT Dev (LOCAL ONLY)"),
        ]
    )

    san_entries: list[x509.GeneralName] = [x509.DNSName(hostname)]
    if hostname == "localhost":
        san_entries.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
        san_entries.append(x509.IPAddress(ipaddress.IPv6Address("::1")))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        # SHA-256 signature — compliant with security guidelines (SHA-2 family)
        .sign(private_key, hashes.SHA256())
    )

    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
    Path(key_path).parent.mkdir(parents=True, exist_ok=True)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    logger.warning(
        "⚠️  Self-signed certificate written to %s — FOR LOCAL DEV ONLY. "
        "Do not use in production.",
        cert_path,
    )


def ensure_dev_certs(
    cert_path: str = "moqt_certs/cert.pem",
    key_path: str = "moqt_certs/key.pem",
    hostname: str = "localhost",
) -> tuple[str, str]:
    """
    Return (cert_path, key_path), generating the files if they don't exist yet.
    """
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        logger.info("Generating dev TLS certificate for QUIC/MOQT transport...")
        generate_dev_cert(cert_path, key_path, hostname)
    return cert_path, key_path



