"""Auto-install mitmproxy CA certificate for HTTPS interception."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

MITMPROXY_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
LINUX_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
ENV_MARKER = "# aigate: trust mitmproxy CA"


def _find_mitmdump() -> str:
    """Find mitmdump binary, even inside a virtualenv."""
    # Check if it's next to the current Python interpreter (same virtualenv)
    import sys
    venv_bin = Path(sys.executable).parent / "mitmdump"
    if venv_bin.exists():
        return str(venv_bin)
    # Fall back to PATH
    found = shutil.which("mitmdump")
    if found:
        return found
    raise FileNotFoundError("mitmdump not found. Is mitmproxy installed?")


def _generate_cert_if_needed() -> None:
    if MITMPROXY_CA.exists():
        return
    mitmdump = _find_mitmdump()
    subprocess.run(
        [mitmdump, "--set", "listen_port=0"],
        timeout=15, capture_output=True,
    )


def _shell_profile() -> Path:
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return Path.home() / ".zshrc"
    return Path.home() / ".bashrc"


def _add_to_shell_profile() -> list[str]:
    profile = _shell_profile()
    actions: list[str] = []

    if profile.exists():
        content = profile.read_text()
        if ENV_MARKER in content:
            actions.append(f"Shell env vars already in {profile.name}")
            return actions

    system = platform.system()
    lines = [ENV_MARKER]
    lines.append(f'export NODE_EXTRA_CA_CERTS="{MITMPROXY_CA}"')

    if system == "Linux" and Path(LINUX_CA_BUNDLE).exists():
        lines.append(f'export REQUESTS_CA_BUNDLE="{LINUX_CA_BUNDLE}"')
        lines.append(f'export SSL_CERT_FILE="{LINUX_CA_BUNDLE}"')
    elif system == "Darwin":
        lines.append(f'export SSL_CERT_FILE="{MITMPROXY_CA}"')

    with open(profile, "a") as f:
        f.write("\n" + "\n".join(lines) + "\n")

    actions.append(f"Added cert env vars to {profile.name}")
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
    """Install cert. Does NOT require sudo — handles elevation internally."""
    actions: list[str] = []

    _generate_cert_if_needed()
    if not MITMPROXY_CA.exists():
        return ["Error: could not generate mitmproxy CA certificate"]

    system = platform.system()
    is_root = os.geteuid() == 0

    if system == "Darwin":
        cmd = [
            "security", "add-trusted-cert", "-d",
            "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            str(MITMPROXY_CA),
        ]
        if not is_root:
            cmd = ["sudo"] + cmd
        subprocess.run(cmd, check=True)
        actions.append("Added CA cert to macOS System Keychain")

    elif system == "Linux":
        ca_dir = Path("/usr/local/share/ca-certificates")
        trust_dir = Path("/etc/pki/ca-trust/source/anchors")

        if ca_dir.exists():
            dest = str(ca_dir / "mitmproxy-aigate.crt")
            if is_root:
                shutil.copy2(str(MITMPROXY_CA), dest)
                subprocess.run(["update-ca-certificates"], check=True)
            else:
                subprocess.run(["sudo", "cp", str(MITMPROXY_CA), dest], check=True)
                subprocess.run(["sudo", "update-ca-certificates"], check=True)
            actions.append("Added CA cert via update-ca-certificates")
        elif trust_dir.exists():
            dest = str(trust_dir / "mitmproxy-aigate.pem")
            if is_root:
                shutil.copy2(str(MITMPROXY_CA), dest)
                subprocess.run(["update-ca-trust"], check=True)
            else:
                subprocess.run(["sudo", "cp", str(MITMPROXY_CA), dest], check=True)
                subprocess.run(["sudo", "update-ca-trust"], check=True)
            actions.append("Added CA cert via update-ca-trust")
        else:
            return [f"Error: unsupported Linux distro. Manually install {MITMPROXY_CA}"]
    else:
        return [f"Error: unsupported OS ({system}). Manually install {MITMPROXY_CA}"]

    actions.extend(_add_to_shell_profile())
    actions.append(f"Cert location: {MITMPROXY_CA}")
    actions.append("Run 'source ~/.bashrc' or open a new terminal for env vars to take effect")
    return actions
