"""Auto-install mitmproxy CA certificate for HTTPS interception."""

from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

MITMPROXY_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"


def _generate_cert_if_needed() -> None:
    """Run mitmdump briefly to generate the CA cert if it doesn't exist."""
    if MITMPROXY_CA.exists():
        return
    # Start and immediately stop mitmdump to trigger cert generation
    subprocess.run(
        ["mitmdump", "--set", "listen_port=0"],
        timeout=3, capture_output=True,
    )


def install_cert() -> list[str]:
    """Install the mitmproxy CA cert into the system trust store."""
    actions: list[str] = []

    _generate_cert_if_needed()
    if not MITMPROXY_CA.exists():
        return ["Error: could not generate mitmproxy CA certificate"]

    system = platform.system()

    if system == "Darwin":
        # macOS: add to system keychain
        subprocess.run([
            "sudo", "security", "add-trusted-cert", "-d",
            "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            str(MITMPROXY_CA),
        ], check=True)
        actions.append("Added CA cert to macOS System Keychain")

    elif system == "Linux":
        # Debian/Ubuntu
        ca_dir = Path("/usr/local/share/ca-certificates")
        if ca_dir.exists():
            dest = ca_dir / "mitmproxy-aigate.crt"
            subprocess.run(["sudo", "cp", str(MITMPROXY_CA), str(dest)], check=True)
            subprocess.run(["sudo", "update-ca-certificates"], check=True)
            actions.append("Added CA cert via update-ca-certificates")
        else:
            # RHEL/Fedora
            trust_dir = Path("/etc/pki/ca-trust/source/anchors")
            if trust_dir.exists():
                dest = trust_dir / "mitmproxy-aigate.pem"
                subprocess.run(["sudo", "cp", str(MITMPROXY_CA), str(dest)], check=True)
                subprocess.run(["sudo", "update-ca-trust"], check=True)
                actions.append("Added CA cert via update-ca-trust")
            else:
                return [f"Error: unsupported Linux distro. Manually install {MITMPROXY_CA}"]
    else:
        return [f"Error: unsupported OS ({system}). Manually install {MITMPROXY_CA}"]

    # Also set for Python requests/httpx (NODE_EXTRA_CA_CERTS for Node.js)
    actions.append(f"Cert location: {MITMPROXY_CA}")
    actions.append("You may also need: export REQUESTS_CA_BUNDLE=" + str(MITMPROXY_CA))
    actions.append("For Node.js: export NODE_EXTRA_CA_CERTS=" + str(MITMPROXY_CA))

    return actions


def is_cert_installed() -> bool:
    """Check if the mitmproxy CA cert exists."""
    return MITMPROXY_CA.exists()
