"""Aprovações humanas para ferramentas de risco moderado.

O Orquestrador registra a ação aqui, responde ao usuário pedindo a
decisão, e o endpoint da API (approve/deny) chama resolve() para
executar a ferramenta (ou negar) e produzir a resposta final.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Awaitable, Callable

from security.errors import describe_exception
from security.sanitize import sanitize_text
from security.scope import check_target
from database.context import project_id

if TYPE_CHECKING:
    from tools.registry import ToolRegistry

RunFn = Callable[[str, dict], Awaitable[str]]
_DEFAULT_TIMEOUT = 300  # 5 min p/ o humano decidir


@dataclass
class PendingAction:
    id: int
    tool: str
    args: dict
    prompt: str
    created_at: float
    status: str = "pending"  # pending | approved | denied | expired
    summary: str = ""
    project_id: int = 1
    future: asyncio.Future = field(default_factory=asyncio.Future, repr=False)


class ConfirmationStore:
    def __init__(self) -> None:
        self._pending: dict[int, PendingAction] = {}
        self._next_id: int = 1
        self._lock = asyncio.Lock()

    async def register(
        self, tool: str, args: dict, prompt: str, summary: str,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> PendingAction:
        async with self._lock:
            action = PendingAction(
                id=self._next_id, tool=tool, args=args, prompt=prompt,
                created_at=time.monotonic(), summary=summary, project_id=project_id.get(),
            )
            self._pending[self._next_id] = action
            self._next_id += 1
        asyncio.get_running_loop().create_task(self._expire(action, timeout))
        return action

    async def _expire(self, action: PendingAction, timeout: int) -> None:
        # Limpa o dict independente do status: ações aprovadas/negadas
        # também saem depois do timeout (a síntese acontece logo após resolve).
        await asyncio.sleep(timeout)
        if action.status == "pending":
            action.status = "expired"
        self._pending.pop(action.id, None)
        if not action.future.done():
            action.future.set_result(None)

    def get(self, action_id: int) -> PendingAction | None:
        action = self._pending.get(action_id)
        return action if action and action.project_id == project_id.get() else None

    async def resolve(
        self,
        action: PendingAction,
        approve: bool,
        registry: "ToolRegistry",
    ) -> str:
        """Executa (ou nega) a ação e devolve a resposta final p/ a UI."""
        if action.project_id != project_id.get():
            return "⛔ Ação pertence a outro projeto."
        if action.status != "pending":
            return "⚠️ Ação já não está pendente (provavelmente expirou)."
        action.status = "approved" if approve else "denied"

        if not approve:
            if not action.future.done():
                action.future.set_result(f"⛔ Ação {action.id} negada pelo usuário. "
                                         "Nada foi executado.")
            return "⛔ Negada pelo usuário. Nada foi executado."

        spec = registry.get(action.tool)
        scope_error = check_target(spec.target_arg if spec else None, action.args)
        if scope_error:
            if not action.future.done():
                action.future.set_result(scope_error)
            from security.logging import log_event
            log_event("warning", "scope", f"ação {action.id} bloqueada fora de escopo: {action.args}")
            return scope_error

        t0 = time.monotonic()
        try:
            result = sanitize_text(await registry.run(action.tool, action.args))
            dur = round(time.monotonic() - t0, 3)
            text = f"✅ Ação {action.id} aprovada.\n\n{result}"
        except asyncio.CancelledError:
            action.status = "cancelled"
            if not action.future.done():
                action.future.set_result("Execução cancelada pelo operador.")
            raise
        except Exception as exc:
            dur = round(time.monotonic() - t0, 3)
            text = f"⚠️ Ação {action.id} aprovada, mas a execução falhou: {describe_exception(exc)}"
        if not action.future.done():
            action.future.set_result(text)
        from security.logging import log_event, log_tool
        log_tool("tool_confirm", tool=action.tool, action_id=action.id,
                 status=action.status, duration=dur, args=str(action.args))
        log_event("info", "confirmation",
                  f"ação {action.id} {action.status} para {action.tool} "
                  f"(args: {action.args})")
        return text
