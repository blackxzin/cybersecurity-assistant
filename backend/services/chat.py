"""Chat orchestration: turns user input into a streamed assistant answer.

Flow: sanitize → route through agents → (tools via Safety Layer) →
LLM synthesis → stream tokens to the client while persisting history.
"""

import asyncio

from ai.prompts import SYSTEM_PROMPT
from ai.providers.base import LLMProvider
from database import db as database
from security.logging import log_event
from security.sanitize import sanitize_text
from tools.confirm import ConfirmationStore
from tools.registry import ToolRegistry

from agents import Orchestrator


class ChatService:
    def __init__(self, provider: LLMProvider, registry: ToolRegistry,
                 store: ConfirmationStore | None = None,
                 research_provider: LLMProvider | None = None) -> None:
        self.provider = provider
        self.registry = registry
        self.store = store or ConfirmationStore()
        self.orchestrator = Orchestrator(provider, registry, self.store, research_provider)

    async def stream(self, user_message: str, on_delta=None,
                     on_progress=None) -> dict[str, object]:
        """Process one message and persist everything.

        Returns metadata plus the final assistant text. When `on_delta` is
        given (SSE), the orchestrator streams the growing answer to it live
        while the model generates; the returned dict still carries the final
        text for persistence.
        """
        clean = sanitize_text(user_message.strip())
        if not clean:
            raise ValueError("Mensagem vazia.")

        # History for context (kept out of the loop on first message).
        history = database.history(limit=8)

        try:
            result = await self.orchestrator.run(
                clean, history, on_delta=on_delta, on_progress=on_progress)
        except asyncio.CancelledError:
            database.save_messages([
                {"role": "user", "content": clean},
                {"role": "assistant", "content": "Execução cancelada pelo operador."},
            ])
            raise
        except (TimeoutError, RuntimeError) as exc:
            log_event("danger", "chat", f"erro não tratado: {exc}")
            raise

        final = sanitize_text(result)
        conversation_id = database.save_messages(
            [
                {"role": "user", "content": clean},
                {"role": "assistant", "content": final},
            ]
        )
        return {
            "conversation_id": conversation_id,
            "content": final,
            "tool_calls": self.orchestrator.last_tool_calls,
            "pending": self.orchestrator.last_pending,
        }
