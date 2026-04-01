"""Auto-install mitmproxy CA certificate for HTTPS interception."""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path

MITMPROXY_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"


def _generate_cert_if_needed() -> None:
    """Run mitmdump briefly to generate the CA cert if it doesn't exist."""
    if MITMPROXY_CA.exists():
        return
    subprocess.run(
        ["mitmdump", "--set", "listen_port=0"],
        timeout=3, capture_output=True,
    )


def is_cert_installed() -> bool:
    """Check if the mitmproxy CA cert is trusted by the system."""
    if not MITMPROXY_CA.exists():
        return False

    system = platform.system()

    if system == "Darwin":
        result = subprocess.run(
            ["security", "find-certificate", "-a", "-c", "mitmproxy", "/Library/Keychains/System.keychain"],
            capture_output=True, text=True,
        )
        return "mitmproxy" in result.stdout

    elif system == "Linux":
        # Check if our cert is in the CA bundle
        ca_dest = Path("/usr/local/share/ca-certificates/mitmproxy-aigate.crt")
        if ca_dest.exists():
            return True
        ca_dest = Path("/etc/pki/ca-trust/source/anchors/mitmproxy-aigate.pem")
        if ca_dest.exists():
            return True

    return False


def install_cert() -> list[str]:
    """Install the mitmproxy CA cert into the system trust store."""
    actions: list[str] = []

    _generate_cert_if_needed()
    if not MITMPROXY_CA.exists():
        return ["Error: could not generate mitmproxy CA certificate"]

    system = platform.system()

    if system == "Darwin":
        subprocess.run([
            "sudo", "security", "add-trusted-cert", "-d",
            "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            str(MITMPROXY_CA),
        ], check=True)
        actions.append("Added CA cert to macOS System Keychain")

    elif system == "Linux":
        ca_dir = Path("/usr/local/share/ca-certificates")
        if ca_dir.exists():
            subprocess.run(["sudo", "cp", str(MITMPROXY_CA), str(ca_dir / "mitmproxy-aigate.crt")], check=True)
            subprocess.run(["sudo", "update-ca-certificates"], check=True)
            actions.append("Added CA cert via update-ca-certificates")
        else:
            trust_dir = Path("/etc/pki/ca-trust/source/anchors")
            if trust_dir.exists():
                subprocess.run(["sudo", "cp", str(MITMPROXY_CA), str(trust_dir / "mitmproxy-aigate.pem")], check=True)
                subprocess.run(["sudo", "update-ca-trust"], check=True)
                actions.append("Added CA cert via update-ca-trust")
            else:
                return [f"Error: unsupported Linux distro. Manually install {MITMPROXY_CA}"]
    else:
        return [f"Error: unsupported OS ({system}). Manually install {MITMPROXY_CA}"]

    actions.append(f"Cert location: {MITMPROXY_CA}")
    return actions
