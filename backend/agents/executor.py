"""Plan Executor: runs multi-step plans, handles confirmations, collects results."""

import time
from typing import TYPE_CHECKING

from config.settings import settings
from security.errors import describe_exception
from security.logging import log_event, log_tool
from security.sanitize import sanitize_text
from security.scope import check_target

if TYPE_CHECKING:
    from tools.registry import ToolRegistry
    from tools.confirm import ConfirmationStore


class StepResult:
    def __init__(
        self,
        step_id: int,
        description: str,
        tool: str | None,
        status: str,
        output: str,
        pending_id: int | None = None,
    ) -> None:
        self.step_id = step_id
        self.description = description
        self.tool = tool
        self.status = status
        self.output = output
        self.pending_id = pending_id


class PlanExecutor:
    def __init__(self, registry: "ToolRegistry", store: "ConfirmationStore") -> None:
        self.registry = registry
        self.store = store

    async def execute(self, steps: list[dict], on_progress=None) -> tuple[list[StepResult], dict | None]:
        """Execute plan steps sequentially.

        Returns (results_so_far, pending_info_or_None).
        Stops at first step requiring confirmation and returns pending info.
        """
        results: list[StepResult] = []
        pending: dict | None = None

        for index, step in enumerate(steps, 1):
            if on_progress:
                await on_progress(f"Passo {index}/{len(steps)}: {step.get('description', '')}")
            step_id = step.get("id", 0)
            description = step.get("description", "")
            tool_name = step.get("tool")
            args = step.get("args", {}) or {}

            if not tool_name:
                results.append(StepResult(step_id, description, None, "skipped", ""))
                continue

            spec = self.registry.get(tool_name)
            if spec is None:
                results.append(StepResult(step_id, description, tool_name, "error",
                                          f"ferramenta '{tool_name}' não encontrada"))
                continue

            missing = [a for a in spec.required_args if not str(args.get(a) or "").strip()]
            if missing:
                results.append(StepResult(
                    step_id, description, tool_name, "missing_args",
                    f"args obrigatórios ausentes: {', '.join(missing)}"
                ))
                continue

            scope_error = check_target(spec.target_arg, args)
            if scope_error:
                log_event("warning", "scope", f"passo {step_id} ({tool_name}) bloqueado fora de escopo: {args}")
                results.append(StepResult(step_id, description, tool_name, "blocked", scope_error))
                continue

            if spec.requires_confirmation and settings.safe_mode != "advanced":
                action = await self.store.register(
                    tool_name, args,
                    f"plano passo {step_id}: {description}",
                    description,
                )
                pending = {
                    "id": action.id,
                    "tool": tool_name,
                    "summary": description,
                    "args": {k: v for k, v in args.items() if k != "password"},
                    "step_id": step_id,
                }
                log_event("warning", "executor", f"passo {step_id} requer confirmação: {tool_name}")
                break
            if spec.requires_confirmation:
                log_event("warning", "executor",
                          f"passo {step_id} ({tool_name}) executado sem confirmação "
                          f"(safe_mode=advanced): {args}")

            t0 = time.monotonic()
            try:
                output = sanitize_text(await self.registry.run(tool_name, args))
                dur = round(time.monotonic() - t0, 3)
                log_tool("tool", tool=tool_name, status="ok", duration=dur)
                from agents import _looks_like_tool_error
                status = "error" if _looks_like_tool_error(output) else "ok"
                results.append(StepResult(step_id, description, tool_name, status, output))
            except Exception as exc:
                dur = round(time.monotonic() - t0, 3)
                log_tool("tool", tool=tool_name, status="error", duration=dur,
                          error=describe_exception(exc))
                results.append(StepResult(
                    step_id, description, tool_name, "error",
                    f"erro: {describe_exception(exc)}"
                ))

        return results, pending
