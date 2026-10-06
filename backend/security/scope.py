"""Authorized-scope gate: opt-in check that a tool's target (host/URL) was
declared in-scope before an offensive tool runs against it.

Off by default (empty scope = unrestricted, same behavior as before this
existed) — the user explicitly asked for "nada restrito" as the persona
default (see memory `cyber-persona-pentest`); this gate only activates once
the operator declares a scope for the current engagement. It protects
against fat-fingering a target, not against the AI refusing offensive work.

Scope entries can be:
  - a bare IP ("10.0.0.5")
  - a CIDR range ("10.0.0.0/24")
  - a domain, matched exact or as a subdomain suffix ("example.com" matches
    "example.com" and "api.example.com")
  - a "*.example.com" wildcard (same subdomain-suffix behavior, explicit form)
"""

import ipaddress
import re
from urllib.parse import urlsplit

from database import db as database
from database.context import project_id

def _scope_key():
    return _SETTING_KEY if project_id.get() == 1 else f"authorized_scope:{project_id.get()}"

_SETTING_KEY = "authorized_scope"
# A CIDR pattern is "<ip>/<prefix>" — an address followed by digits, nothing
# else. A domain typed as a full URL ("https://x.com/path") also contains a
# '/', so a bare "/" in pattern" check misfires on it: it falls into the CIDR
# branch, ipaddress.ip_network() raises on the scheme, and the scope check
# rejects an in-scope target. Only route actual CIDR shapes there.
_CIDR_RE = re.compile(r"^[0-9a-fA-F.:]+/\d{1,3}$")


def get_scope() -> list[str]:
    raw = database.get_setting(_scope_key())
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def set_scope(patterns: list[str]) -> list[str]:
    cleaned = [p.strip() for p in patterns if p.strip()]
    database.set_setting(_scope_key(), ",".join(cleaned))
    return cleaned


def extract_host(target: str) -> str:
    """Pulls the hostname out of a URL; returns the input unchanged if it's
    already a bare host (nmap/hydra pass a host directly, not a URL)."""
    target = target.strip()
    if "://" in target:
        return urlsplit(target).hostname or target
    # host[:port] form (no scheme) — strip a trailing port.
    return target.split(":")[0] if target.count(":") == 1 else target


def _matches_one(host: str, pattern: str) -> bool:
    pattern = pattern.strip()
    if not pattern:
        return False
    # CIDR or bare IP pattern — only meaningful if host is itself an IP.
    if _CIDR_RE.match(pattern) or _looks_like_ip(pattern):
        try:
            host_ip = ipaddress.ip_address(host)
            network = ipaddress.ip_network(pattern, strict=False)
            return host_ip in network
        except ValueError:
            return False
    # Domain pattern: accept a bare domain or a full URL (the panel takes
    # free text, and pasting "https://x.com/path" is a natural thing to do)
    # by normalizing it the same way a real target is normalized.
    pattern = extract_host(pattern)
    domain = pattern[2:] if pattern.startswith("*.") else pattern
    host_l, domain_l = host.lower(), domain.lower()
    return host_l == domain_l or host_l.endswith("." + domain_l)


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_authorized(target: str) -> bool:
    """True when no scope is configured (gate off) or target matches one
    of the configured patterns."""
    scope = get_scope()
    if not scope:
        return True
    host = extract_host(target)
    return any(_matches_one(host, pattern) for pattern in scope)


def check_target(target_arg: str | None, args: dict) -> str | None:
    """Returns an error message if 'args[target_arg]' is set and out of
    scope; None if there's nothing to check or it's authorized."""
    if not target_arg:
        return None
    raw = str(args.get(target_arg) or "").strip()
    if not raw:
        return None
    if is_authorized(raw):
        return None
    scope = get_scope()
    return (
        f"⛔ alvo fora do escopo autorizado: {raw!r}. "
        f"Escopo atual: {', '.join(scope)}. "
        "Adicione o alvo ao escopo (painel Configurações) antes de rodar essa ferramenta."
    )
