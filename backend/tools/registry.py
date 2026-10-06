"""Tool registry: central catalogue and executor for all tools."""

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable

ToolFn = Callable[[dict], Awaitable[str]]


@dataclass
class ToolSpec:
    name: str
    description: str
    fn: ToolFn
    risk: str = "info"  # info | moderate | dangerous
    requires_confirmation: bool = False
    # Arg keys the LLM must fill before this tool is called. Checked by the
    # orchestrator before confirmation/execution so a bad tool-selection
    # JSON turns into a clarifying question instead of a wasted confirm
    # round-trip or a tool call that fails on missing input.
    required_args: tuple[str, ...] = ()
    # Which arg key (if any) holds the network target (host/URL) this tool
    # acts on — used by security/scope.py to gate against the authorized
    # scope. None means the tool has no network target (e.g. cpf_osint).
    target_arg: str | None = None
    # Display-only grouping for the frontend (Segurança lista por categoria
    # em vez de lista plana) — não afeta execução/confirmação/escopo.
    category: str = "geral"


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, name: str, description: str, fn: ToolFn, **meta) -> None:
        self._tools[name] = ToolSpec(name, description, fn, **meta)

    def list(self) -> list[ToolSpec]:
        return sorted(self._tools.values(), key=lambda t: t.name)

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    async def run(self, name: str, args: dict) -> str:
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"Ferramenta desconhecida: {name}")
        from database.context import audit_enabled
        from database import db as database
        from services.tasks import current_task
        from security.sanitize import sanitize_text
        from security.scope import check_target
        from agents import _looks_like_tool_error
        work = current_task.get()
        if work:
            work.progress(f"Executando {name}")
        status, output = "ok", ""
        try:
            scope_error = check_target(tool.target_arg, args)
            if scope_error:
                status, output = "blocked", scope_error
                return output
            result = tool.fn(args)
            output = await result if asyncio.iscoroutine(result) else result
            output = sanitize_text(str(output))
            if _looks_like_tool_error(output):
                status = "error"
            return output
        except asyncio.CancelledError:
            status, output = "cancelled", "Execução cancelada pelo operador."
            raise
        except Exception as exc:
            status, output = "error", sanitize_text(str(exc))
            raise
        finally:
            if audit_enabled.get():
                # Store evidence before synthesis, including approved/cancelled calls.
                safe_args = {k: ("[REDACTED]" if any(s in k.lower() for s in
                             ("password", "token", "cookie", "secret", "api_key")) else v)
                             for k, v in args.items()}
                safe_args = {k: sanitize_text(v) if isinstance(v, str) else v for k, v in safe_args.items()}
                database.log_tool_call(name, safe_args, output, risk=tool.risk, status=status)



def read_only(name: str, description: str, fn: ToolFn):
    """Decorator shorthand to register a read-only tool."""

    def wrapper(registry: ToolRegistry) -> None:
        registry.register(name, description, fn, risk="info", requires_confirmation=False)

    return wrapper
