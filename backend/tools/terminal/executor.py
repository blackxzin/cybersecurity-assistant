"""Controlled command executor: the only gate between the AI and the shell.

Rules enforced here (independent of what the AI thinks it wants):
- denylist matches → always rejected (never executed);
- allowlist tools → executed directly (read-only);
- anything else → treated as needing confirmation (the API layer
  decides, based on safe_mode, whether to prompt the human);
- command is never run through a shell: argv list → subprocess, so
  no shell metacharacters, no injection;
- strict timeout;
- stdout captured, stderr captured, exit code returned;
- secret redaction applied to output before it is returned.
"""

import asyncio
from services.processes import communicate
from typing import Any

from security.sanitize import sanitize_text

# --- Denylist: hard blocks, regardless of mode. Prefixes win. ---
DENY_PREFIXES: tuple[str, ...] = (
    "rm",
    "dd",
    "mkfs",
    "format",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "init",
    "systemctl stop",
    "systemctl disable",
    "fdisk",
    "parted",
    ":(){",
    ">",
)
DENY_SUBSTRINGS: tuple[str, ...] = (
    "> /dev/sd",
    ">/dev/sd",
    "2>/dev/sd",
    ";",
    "&&",
    "||",
    "|",
    "`",
    "$(",
)

# --- Allowlist: read-only, safe to run without confirmation. ---
ALLOW_PREFIXES: tuple[str, ...] = (
    "ip addr",
    "ip -brief addr",
    "ip route",
    "ip link",
    "ss -t",
    "ss -u",
    "ss -tulnp",
    "systemctl --no-pager --plain list-units",
    "ps aux",
    "df -",
    "ls -l",
    "cat /proc/",
    "free -",
    "uname -",
    "hostname",
    "uptime",
)

TIMEOUT_SECONDS = 10
MAX_OUTPUT_CHARS = 4000


def _classify(argv: list[str]) -> str:
    """Return 'allow' | 'deny' | 'unknown'."""
    joined = " ".join(argv)
    lowered = joined.lower().strip()

    if not lowered:
        return "deny"

    # Denylist first — it always wins over allowlist.
    for prefix in DENY_PREFIXES:
        if lowered.startswith(prefix):
            return "deny"
    for sub in DENY_SUBSTRINGS:
        if sub in lowered:
            return "deny"

    for prefix in ALLOW_PREFIXES:
        if lowered.startswith(prefix):
            return "allow"
    return "unknown"


def classify_command(argv: list[str]) -> str:
    """Public wrapper for the Safety Layer / API to inspect a command."""
    return _classify(argv)


async def run_safe_command(argv: list[str]) -> tuple[str, str]:
    """Execute an allowlisted read-only command.

    Returns (stdout, stderr). Raises ValueError on any command that is
    not explicitly allowlisted — callers must never bypass this.
    """
    if not argv or _classify(argv) != "allow":
        raise ValueError(
            "Comando não permitido pelo Safety Layer (fora da allowlist)."
        )
    return await _run(argv)


async def _run(argv: list[str]) -> tuple[str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            out, err = await communicate(proc, TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Comando excedeu {TIMEOUT_SECONDS}s e foi encerrado."
            )
    except FileNotFoundError as exc:
        raise ValueError(f"Comando não encontrado: {exc}") from exc

    stdout = sanitize_text(out.decode(errors="replace"))
    stderr = sanitize_text(err.decode(errors="replace"))
    if len(stdout) > MAX_OUTPUT_CHARS:
        stdout = stdout[:MAX_OUTPUT_CHARS] + "\n...[truncado]"
    return stdout, stderr
