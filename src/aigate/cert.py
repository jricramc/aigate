"""Auto-install mitmproxy CA certificate for HTTPS interception."""

from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

MITMPROXY_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

ENV_LINES = [
    '# aigate: trust mitmproxy CA for HTTPS interception',
    f'export NODE_EXTRA_CA_CERTS="{MITMPROXY_CA}"',
    f'export REQUESTS_CA_BUNDLE="{MITMPROXY_CA}"',
]

ENV_MARKER = "# aigate: trust mitmproxy CA"


def _generate_cert_if_needed() -> None:
    if MITMPROXY_CA.exists():
        return
    subprocess.run(
        ["mitmdump", "--set", "listen_port=0"],
        timeout=15, capture_output=True,
    )


def _shell_profile() -> Path:
    """Find the user's shell profile file."""
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return Path.home() / ".zshrc"
    return Path.home() / ".bashrc"


def _add_to_shell_profile() -> list[str]:
    """Add cert env vars to shell profile if not already there."""
    profile = _shell_profile()
    actions: list[str] = []

    if profile.exists():
        content = profile.read_text()
        if ENV_MARKER in content:
            actions.append(f"Shell env vars already in {profile.name}")
            return actions

    with open(profile, "a") as f:
        f.write("\n" + "\n".join(ENV_LINES) + "\n")

    actions.append(f"Added NODE_EXTRA_CA_CERTS to {profile.name}")
    actions.append(f"Added REQUESTS_CA_BUNDLE to {profile.name}")
    return actions


def is_cert_installed() -> bool:
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
        if Path("/usr/local/share/ca-certificates/mitmproxy-aigate.crt").exists():
            return True
        if Path("/etc/pki/ca-trust/source/anchors/mitmproxy-aigate.pem").exists():
            return True

    return False


def install_cert() -> list[str]:
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

    # Add env vars to shell profile for Node.js and Python
    actions.extend(_add_to_shell_profile())
    actions.append(f"Cert location: {MITMPROXY_CA}")
    actions.append("Run 'source ~/.bashrc' or open a new terminal for env vars to take effect")
    return actions
