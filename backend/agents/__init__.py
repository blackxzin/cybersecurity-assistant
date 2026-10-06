"""Agent registry: routes a request to the right specialist."""

import json
import re
import time
from typing import TYPE_CHECKING

from config.settings import settings
from database import db as database
from security.errors import describe_exception as _describe_exception
from security.logging import log_event, log_tool
from security.sanitize import sanitize_text

from security.scope import check_target
from .base import AgentContext
from .streaming import stream_or_complete
from tools.confirm import ConfirmationStore

if TYPE_CHECKING:
    from tools.registry import ToolRegistry
    from ai.providers.base import LLMProvider

_SYNTHESIS_INPUT_CHARS = 3000
_PLAN_CHARS = 600
_MEMORY_FACTS_INJECTED = 6

# Matches the plain-string error conventions every tool in backend/tools/*.py
# uses when it fails or rejects bad input ("erro: ...", "Uso: informe...",
# "host inválido: ..."). These carry no real data to explain — sending them
# to the "cite dados reais" synthesis prompt just invites the LLM to
# fabricate plausible-sounding facts to fill that section (observed live:
# a Burp MCP connection error came back with an invented Burp Suite version,
# Windows build and extension list). Skip synthesis entirely for these.
_TOOL_ERROR_RE = re.compile(r"^(erro:|uso:|\S+ inválid[oa]:)", re.IGNORECASE)
# tools/confirm.py::resolve() wraps a successful confirmed action as
# "✅ Ação {id} aprovada.\n\n{result}" — a tool-level error string still
# lands inside that wrapper (the action itself didn't raise, its own
# execution just returned an error message), so it has to be stripped
# before the error check above can see it.
_APPROVED_ACTION_PREFIX_RE = re.compile(r"^✅ Ação \d+ aprovada\.\n\n")


def _looks_like_tool_error(text: str) -> bool:
    text = _APPROVED_ACTION_PREFIX_RE.sub("", text.strip(), count=1)
    return bool(_TOOL_ERROR_RE.match(text.strip()))


def _memory_snippet() -> str:
    """Recent long-term facts (see tools/memory.py), formatted for a system
    prompt so the assistant references them without an explicit 'recall'."""
    facts = database.list_memory(limit=_MEMORY_FACTS_INJECTED)
    if not facts:
        return ""
    lines = "\n".join(f"- {f['content']}" for f in reversed(facts))
    return f"\n\nFatos que você já sabe sobre o usuário/ambiente:\n{lines}"


def _truncate_for_synthesis(text: str) -> str:
    """Caps tool output fed into a synthesis prompt. Full output is still
    kept for the audit trail (last_tool_calls/log_tool) — this only shields
    the LLM call from huge blobs (e.g. nmap NSE service fingerprints) that
    add no explanatory value but do add real timeout risk on slower models."""
    if len(text) <= _SYNTHESIS_INPUT_CHARS:
        return text
    return text[:_SYNTHESIS_INPUT_CHARS] + "\n...[truncado para a síntese]"


_KEYWORDS: list[tuple[str, str]] = [
    # "learning" goes first: its keywords are explicit teaching-intent verbs
    # ("explica", "o que é"...), not topic nouns — "explica firewall" or
    # "o que é nmap" must win over the security/network/system topic
    # buckets below, or every "explain a security concept" question (the
    # exact case Learning mode exists for) gets routed to tool execution
    # instead, since those buckets' keyword sets overlap heavily with
    # common security-learning topics.
    ("learning", r"\b(?:explica|aprend|ensinar|professor|conceito|tutorial|o que é|o que e)\b"),
    ("network", r"\b(?:rede|net|ip|interface|dns|route|conex|banda|ping|wifi)\b"),
    ("system", r"\b(?:cpu|ram|mem|disk|proces|servi|sistema|hardware|boot|kernel)\b"),
    ("security", r"\b(?:secur|vuln|scan|porta|log|alerta|firewall|nmap|backup|hardening|jwt|hash|token|base64|certificad|ssl|tls|header|cabecalho|cabeçalho|subdomín|subdomin)\b"),
]


def classify(prompt: str) -> str:
    """Route a request to an agent domain by keyword match."""
    lowered = prompt.lower()
    for agent, pattern in _KEYWORDS:
        if re.search(pattern, lowered):
            return agent
    return "network"


# Quais categorias de ferramenta cada bucket precisa ver na hora de DECIDIR.
# Filtrar a lista de ferramentas mandada ao modelo pelo bucket encurta o prompt
# (menos tokens pra avaliar no CPU = decisão mais rápida). "memória" entra em
# todos (recall/remember são transversais). É só otimização do 1º chute: a
# validação aceita QUALQUER ferramenta registrada, e o retry usa a lista
# completa — então nunca exclui a ferramenta certa de forma definitiva.
_BUCKET_CATEGORIES: dict[str, set[str]] = {
    "network": {"rede", "diagnóstico", "osint", "ofensivo", "web"},
    "system": {"sistema", "diagnóstico"},
    "security": {"ofensivo", "exploração", "burp", "engenharia-reversa",
                 "osint", "rede", "diagnóstico", "web", "cripto"},
}


class Orchestrator:
    """Coordinates agent selection, tool execution and final LLM synthesis."""

    def __init__(
        self, provider: "LLMProvider", registry: "ToolRegistry", store: ConfirmationStore,
        research_provider: "LLMProvider | None" = None,
    ) -> None:
        self.provider = provider
        # DeepHat (provider) decide e executa ferramentas. research_provider é
        # opcional (settings.research_provider) — um 2° modelo só pra
        # pesquisa/planejamento (Planner/Validator); sem ele, cai no mesmo
        # provider de sempre (comportamento idêntico a antes desse recurso).
        self.research_provider = research_provider or provider
        self.registry = registry
        self.store = store
        self.last_tool_calls: list[dict] = []
        # Presente quando a resposta contém uma ação aguardando aprovação.
        self.last_pending: dict | None = None
        # Callback opcional (SSE) que recebe o texto acumulado da resposta
        # final enquanto o modelo gera. None = comportamento não-streaming.
        self._on_delta = None
        # Callback opcional (SSE) pra status curtos ("🔧 executando X…")
        # durante as fases lentas ANTES da síntese (decidir/rodar ferramenta),
        # pra o chat não ficar parado no "⏳ Analisando…".
        self._on_progress = None

    async def run(self, prompt: str, history: list[dict[str, str]],
                  on_delta=None, on_progress=None) -> str:
        self.last_tool_calls = []
        self.last_pending = None
        self._on_delta = on_delta
        self._on_progress = on_progress
        from agents.planner import is_complex_task
        if is_complex_task(prompt):
            result = await self._run_pipeline(prompt, history)
            if result is not None:
                return result
        agent_name = classify(prompt)
        return await self._run_agent(agent_name, prompt, history)

    async def _progress(self, message: str) -> None:
        """Emite um status curto pro cliente (no-op se não houver callback)."""
        if self._on_progress is None:
            return
        try:
            await self._on_progress(message)
        except Exception:
            pass

    async def _run_pipeline(self, prompt: str, history: list[dict[str, str]]) -> str | None:
        """Planner → Executor → Validator pipeline for complex tasks.

        Returns None if planner fails to generate a plan (fall back to single-tool mode).
        """
        from agents.planner import TaskPlanner
        from agents.executor import PlanExecutor
        from agents.validator import ResultValidator

        await self._progress("🧭 montando plano…")
        planner = TaskPlanner(self.research_provider, self.registry)
        steps = await planner.plan(prompt)
        if not steps:
            return None

        await self._progress(f"⚙️ executando plano de {len(steps)} passo(s)…")
        executor = PlanExecutor(self.registry, self.store)
        results, pending = await executor.execute(steps, on_progress=self._on_progress)

        for r in results:
            if r.tool and r.output:
                self.last_tool_calls.append({
                    "tool": r.tool,
                    "status": r.status,
                    "result": r.output[:500],
                })

        if pending:
            self.last_pending = pending
            completed_text = self._format_partial_results(results)
            return (
                f"{completed_text}"
                f"\n\n⚠️ Passo {pending['step_id']} requer autorização: "
                f"**{pending['tool']}** — {pending['summary']}. "
                "Aprovar ou negar no painel."
            )

        if not results:
            return None

        validator = ResultValidator(self.research_provider)
        validation = await validator.validate(prompt, results)

        return await self._synthesize_plan(prompt, results, validation)

    def _format_partial_results(self, results: list) -> str:
        parts: list[str] = []
        for r in results:
            if r.status == "ok" and r.output:
                parts.append(f"**Passo {r.step_id}** ({r.tool}): concluído")
        if not parts:
            return ""
        return "\n".join(parts)

    async def _synthesize_plan(self, prompt: str, results: list, validation: object) -> str:
        ok_results = [(r.tool, r.output) for r in results if r.status == "ok" and r.output]
        if not ok_results:
            return "Nenhum resultado obtido nos passos executados."

        results_block = "\n\n".join(
            f"[{tool}]\n{out[:_PLAN_CHARS]}"
            for tool, out in ok_results
        )
        gaps_note = (
            f"\nLacunas detectadas: {', '.join(validation.gaps)}"
            if hasattr(validation, "gaps") and validation.gaps else ""
        )
        messages = [
            {"role": "system", "content": (
                "Você é o Cyber, assistente de segurança. "
                "Explique em português os resultados de um plano multi-passo executado. "
                "Cite dados reais. Estruture: sumário, achados por ferramenta, conclusão. "
                "Nunca invente dados."
            )},
            {"role": "user", "content": (
                f"Pedido original: {prompt}\n\n"
                f"Validação: {validation.summary}; status={validation.status}.\n"
                f"Resultados coletados:\n{results_block}{gaps_note}"
            )},
        ]
        try:
            verdict = "Objetivo confirmado por evidência." if validation.success else "Resultado inconclusivo."
            answer = await stream_or_complete(self.provider, messages, self._on_delta)
            return f"{verdict}\n{validation.summary}{gaps_note}\n\n{answer}"
        except Exception as exc:
            return f"Resultado inconclusivo. {validation.summary}{gaps_note}\n{results_block}\n\n(síntese indisponível: {_describe_exception(exc)})"

    async def _run_agent(self, agent: str, prompt: str, history: list[dict[str, str]]) -> str:
        from agents.system_agent import SystemAgent

        if agent == "system":
            ctx = AgentContext(prompt=prompt, history=history)
            answer = await SystemAgent(self.provider, self.registry).run(ctx, self._on_delta)
        elif agent == "learning":
            from agents.learning_agent import LearningAgent
            ctx = AgentContext(prompt=prompt, history=history)
            answer = await LearningAgent(self.provider).run(ctx, self._on_delta)
        else:
            answer = await self._run_with_tools(prompt, history, agent)
        return answer

    def _tool_block(self, bucket: str | None, full: bool = False) -> str:
        """Lista de ferramentas pro prompt de decisão. Sem `full`, filtra pelas
        categorias do bucket (prompt menor, decisão mais rápida no CPU)."""
        tools = self.registry.list()
        if not full and bucket in _BUCKET_CATEGORIES:
            cats = _BUCKET_CATEGORIES[bucket] | {"memória"}
            subset = [t for t in tools if t.category in cats]
            if subset:
                tools = subset
        return "\n".join(f"- {t.name}: {t.description}" for t in tools)

    def _decide_prompt(self, tool_block: str, include_memory: bool = True) -> str:
        return (
            "You decide which tool answers the user. Tools:\n"
            f"{tool_block}\n"
            "Reply ONLY with a JSON object: {\"tool\": \"<name>\", \"args\": {…}} "
            "filling in the required args from the user's request. "
            "Use {\"tool\": null} if no tool is needed."
            f"{_memory_snippet() if include_memory else ''}"
        )

    async def _run_with_tools(self, prompt: str, history: list[dict[str, str]],
                              bucket: str | None = None) -> str:
        """Classic loop: LLM decides tool → confirm if risky → execute → explain."""
        tool_names = [t.name for t in self.registry.list()]
        await self._progress("🔎 escolhendo ferramenta…")
        # 1º chute com a lista filtrada pelo bucket (mais rápido).
        decide_prompt = self._decide_prompt(self._tool_block(bucket))
        decision = await self._decide_tool(decide_prompt, prompt)
        chosen, args, well_formed = self._extract_tool(decision)

        needs_retry = (chosen and chosen not in tool_names) or not well_formed
        if needs_retry:
            reason = (
                f"citou a ferramenta '{chosen}', que não existe" if chosen
                else "não veio em JSON válido"
            )
            log_event("warning", "orchestrator", f"decisão do LLM {reason}; tentando de novo")
            # Retry com a lista COMPLETA — se a ferramenta certa tiver ficado de
            # fora do filtro, ela aparece agora.
            full_prompt = self._decide_prompt(self._tool_block(bucket, full=True))
            retry_prompt = (
                f"{full_prompt}\n\nSua resposta anterior {reason}. "
                "Responda de novo com APENAS o JSON, sem texto extra, "
                "escolhendo um nome EXATO da lista acima, ou {\"tool\": null}."
            )
            decision = await self._decide_tool(retry_prompt, prompt)
            chosen, args, well_formed = self._extract_tool(decision)

        if not (chosen and chosen in tool_names):
            if not well_formed or (chosen and chosen not in tool_names):
                log_event("warning", "orchestrator",
                          f"tool-selection falhou após retry (decisão: {decision[:200]!r})")
            return await self._synthesize_no_tool(prompt, history)

        spec = self.registry.get(chosen)
        missing = [a for a in spec.required_args if not str(args.get(a) or "").strip()]
        if missing:
            log_event("info", "orchestrator",
                      f"{chosen}: faltam args {missing} — pedindo esclarecimento")
            joined = ", ".join(missing)
            return (
                f"Pra usar **{chosen}** preciso que você informe: {joined}. "
                "Pode reescrever o pedido com esse dado?"
            )

        scope_error = check_target(spec.target_arg, args)
        if scope_error:
            log_event("warning", "scope", f"{chosen} bloqueado fora de escopo: {args}")
            return scope_error

        if spec.requires_confirmation and settings.safe_mode != "advanced":
            return await self._request_confirmation(prompt, history, chosen, args)
        if spec.requires_confirmation:
            log_event("warning", "orchestrator",
                      f"{chosen} executado sem confirmação (safe_mode=advanced): {args}")
        await self._progress(f"🔧 executando `{chosen}`…")
        return await self._run_chosen(prompt, history, chosen, args)

    async def _decide_tool(self, system_prompt: str, user_prompt: str) -> str:
        decide = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        decision = (await self.provider.complete(decide, json_mode=True)).strip()
        log_event("info", "orchestrator", f"decisão LLM: {decision[:200]!r}")
        return decision

    async def _request_confirmation(
        self, prompt: str, history: list[dict[str, str]], tool: str, args: dict
    ) -> str:
        summary = await self._summarize_action(tool, args)
        action = await self.store.register(tool, args, prompt, summary)
        self.last_pending = {
            "id": action.id,
            "tool": tool,
            "summary": summary,
            "args": {k: v for k, v in args.items() if k != "password"},
        }
        log_event("warning", "confirmation",
                  f"ação {action.id} requer confirmação: {tool} {args}")
        return (
            f"⚠️ Preciso da sua autorização para executar: **{tool}** — {summary}. "
            f"Aprovar ou negar no painel."
        )

    async def _summarize_action(self, tool: str, args: dict) -> str:
        """Pedido curto em pt-BR da ação que será executada."""
        # Mostra os args não sigilosos (sem passwords/tokens).
        visible = {k: v for k, v in args.items() if k != "password"}
        messages = [
            {"role": "system", "content": (
                "Descreva EM UMA FRASE curta (máx 15 palavras), em português "
                "simples, a ação que a ferramenta fará, citando o alvo. "
                "Ex: 'Escaneia portas e serviços do host 10.0.0.5 com nmap'."
            )},
            {"role": "user", "content": f"Ferramenta: {tool}. Argumentos: {visible}"},
        ]
        try:
            text = (await self.provider.complete(messages, max_tokens=30)).strip()
            return re.sub(r"[\r\n]+", " ", text)[:160]
        except Exception:
            return f"{tool} com {visible}"

    async def _run_chosen(
        self, prompt: str, history: list[dict[str, str]], chosen: str, args: dict
    ) -> str:
        t0 = time.monotonic()
        try:
            result = sanitize_text(await self.registry.run(chosen, args))
        except Exception as exc:  # tool itself failed → explain the error
            dur = round(time.monotonic() - t0, 3)
            self.last_tool_calls.append({"tool": chosen, "status": "error"})
            log_tool("tool", tool=chosen, status="error", duration=dur, error=_describe_exception(exc))
            log_event("warning", "tool", f"{chosen}: {_describe_exception(exc)}")
            return f"⚠️ Não consegui consultar {chosen}: {_describe_exception(exc)}"

        dur = round(time.monotonic() - t0, 3)
        if _looks_like_tool_error(result):
            # Tool ran but rejected the input or hit its own failure (e.g. a
            # dependency it talks to is unreachable) — no real data to
            # synthesize, and asking the LLM to explain it invites invented
            # detail. Return it verbatim, same as an exception from the tool.
            self.last_tool_calls.append({"tool": chosen, "status": "error", "result": result[:500]})
            log_tool("tool", tool=chosen, status="error", duration=dur, result=result)
            return f"⚠️ {result}"
        ctx = AgentContext(prompt=prompt, history=history)
        ctx.tool_calls.append({"tool": chosen, "result": result})
        self.last_tool_calls.append({"tool": chosen, "status": "ok", "result": result[:500]})
        log_tool("tool", tool=chosen, status="ok", duration=dur, result=result)
        # Tool succeeded — a synthesis failure past this point must not
        # swallow the real result (LLM timeout ≠ tool failure).
        try:
            return await self._synthesize(ctx, chosen, result)
        except Exception as exc:
            return f"{result}\n\n(síntese indisponível: {_describe_exception(exc)})"

    async def synthesize_approved(self, action_id: int) -> str:
        """LLM interpreta o resultado de uma ação aprovada."""
        from tools.confirm import PendingAction
        action = self.store.get(action_id)
        if not isinstance(action, PendingAction) or action.status != "approved":
            return "⚠️ Ação não encontrada ou não aprovada."
        try:
            text = action.future.result()
        except Exception:
            return "⚠️ Resultado da ação não disponível."
        if text.startswith(("⚠️", "⛔")) or _looks_like_tool_error(text):
            return text
        messages = [
            {"role": "system", "content": (
                "Explique em português simples o resultado de uma ferramenta "
                "de auditoria. Cite dados reais. Estruture: o que a ferramenta "
                "encontrou, o que isso significa, e uma sugestão. NUNCA invente "
                "dados ausentes."
            )},
            {"role": "user", "content": f"Ação aprovada: {action.tool} {action.args}\n\nResultado:\n{_truncate_for_synthesis(text)}"},
        ]
        try:
            return (await self.provider.complete(messages)).strip()
        except Exception as exc:
            return f"{text}\n\n(síntese indisponível: {_describe_exception(exc)})"

    def _extract_tool(self, decision: str) -> tuple[str | None, dict, bool]:
        """Returns (tool, args, well_formed). well_formed=False means the
        model's output could not be parsed as JSON at all (garbled, not a
        deliberate {"tool": null}) — the caller uses this to decide whether
        a retry is worth it."""
        if not decision:
            return None, {}, False
        # If the model wrapped the JSON in a code fence, unwrap it.
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", decision)
        if match:
            decision = match.group(1)
        try:
            data = json.loads(decision)
        except json.JSONDecodeError:
            match = re.search(r'"tool"\s*:\s*"?([a-z_]+)"?', decision)
            return (match.group(1) if match else None), {}, bool(match)
        tool = data.get("tool")
        if not isinstance(tool, str) or not tool:
            return None, {}, True
        args = data.get("args")
        if isinstance(args, dict):
            args = {str(k): (str(v) if v is not None else "") for k, v in args.items()}
        else:
            args = {}
        return tool, args, True

    async def _synthesize(self, ctx: AgentContext, tool: str, result: str) -> str:
        messages = [
            {"role": "system", "content": (
                "You analyze the REAL tool output and explain it in simple "
                "Portuguese (pt-BR). Use the actual data from the result — "
                "cite real interface names, IPs and values. NEVER invent or "
                "make up data that is not present in the tool output. "
                "Structure: breve explicação, dados reais, o que significam, "
                "sugestão. If the user asked a question, answer it directly "
                "using the real data."
            )},
            {"role": "user", "content": f"Pergunta: {ctx.prompt}\n\nResultado real da ferramenta {tool}:\n{_truncate_for_synthesis(result)}"},
        ]
        return await stream_or_complete(self.provider, messages, self._on_delta)

    async def _synthesize_no_tool(self, prompt: str, history: list[dict[str, str]]) -> str:
        messages = [
            {"role": "system", "content": (
                "Você é o Cyber, pentester profissional e administrador Linux. "
                "Responda em português claro, direto, sem disclaimers. Seja didático."
                f"{_memory_snippet()}"
            )},
            *history[-6:],
            {"role": "user", "content": prompt},
        ]
        return await stream_or_complete(self.provider, messages, self._on_delta)
