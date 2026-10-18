"""Guardrails the live runner enforces before it ever touches a real target."""

from __future__ import annotations

import ipaddress
import socket


class UnauthorizedTargetError(RuntimeError):
    pass


def resolve_and_check(target: str, allow_public: bool = False) -> str:
    """Resolve `target` to an IP and refuse public addresses unless overridden."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = ipaddress.ip_address(socket.gethostbyname(target))

    if not allow_public and not (ip.is_private or ip.is_loopback):
        raise UnauthorizedTargetError(
            f"{target} ({ip}) is not a private/loopback address. This runner only "
            "targets isolated lab networks by default. Pass allow_public_target=True "
            "(--allow-public-target on the CLI) only if you are certain you have "
            "explicit written authorization to test this host."
        )
    return str(ip)


def require_confirmation(confirmed: bool, target: str) -> None:
    if not confirmed:
        raise UnauthorizedTargetError(
            f"Refusing to run a live exploit against {target} without explicit "
            "confirmation that you own or are authorized to test it. Pass "
            "--i-own-this-target on the CLI, or check the authorization box in the UI."
        )
