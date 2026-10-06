"""FastAPI application: internal REST + SSE streaming API.

All routes bind to 127.0.0.1 by default — the UI is served from the
same process. CORS is locked to that same origin: a wildcard here
would let any web page the user visits in a browser drive this API
(DNS-rebinding / drive-by localhost attack), even though the backend
itself only listens on loopback.
"""

import asyncio
import contextlib
import hmac
import json
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from ai.providers import (
    available_providers,
    build_provider,
    build_research_provider,
    get_research_provider_override,
    set_research_provider_override,
)
from config.settings import FRONTEND_DIR, settings
from database import db as database
from security.errors import describe_exception
from security.logging import log_event
from security.safety import Risk, classify_action
from security import scope as scope_module
from services.chat import ChatService
from services.report import generate_pentest_report
from services import watcher
from services.tasks import manager, current_task
from database.context import project_id, audit_enabled
from api.projects import router as projects_router
from tools.confirm import ConfirmationStore
from tools.terminal import executor
from tools import build_registry
from tools.system import cpu_percent, disk_percent, mem_percent

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_watcher_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _watcher_task
    database.init_db()
    if settings.watcher_enabled:
        _watcher_task = asyncio.create_task(watcher.run_forever())
    yield
    if _watcher_task:
        _watcher_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _watcher_task
    for work in list(manager.works.values()):
        if work.finished is None:
            await manager.cancel(work)
    await _provider.aclose()


app = FastAPI(title="Cybersecurity AI", version="0.1.0", lifespan=lifespan)

app.include_router(projects_router)

_ALLOWED_ORIGINS = {f"http://127.0.0.1:{settings.port}", f"http://localhost:{settings.port}"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(_ALLOWED_ORIGINS),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _enforce_same_origin(request: Request, call_next):
    """CORS alone doesn't stop a "simple" cross-origin POST from firing
    (it only blocks the response being read). Any page open in the user's
    browser could otherwise silently approve/deny pending actions or run
    the terminal endpoint. Require Origin (or Sec-Fetch-Site) to prove the
    request came from our own UI for every state-changing call.

    Verified: requests from overlay/ (Electron main-process `fetch`, i.e.
    Node/undici) carry neither header — only browser-context requests do —
    so this guard passes them through while still blocking a page open in
    the user's browser (curl-tested: no headers -> 200, foreign Origin or
    cross-site Sec-Fetch-Site -> 403)."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        sec_fetch_site = request.headers.get("sec-fetch-site")
        same_site = sec_fetch_site in ("same-origin", "none")
        if origin is not None and origin not in _ALLOWED_ORIGINS and not same_site:
            return JSONResponse(status_code=403, content={"detail": "cross-origin request refused"})
        if origin is None and sec_fetch_site not in (None, "same-origin", "none"):
            return JSONResponse(status_code=403, content={"detail": "cross-origin request refused"})
    return await call_next(request)


@app.middleware("http")
async def _project_context(request: Request, call_next):
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    raw = request.headers.get("x-project-id", "1")
    try:
        value = int(raw)
    except ValueError:
        return JSONResponse(status_code=422, content={"detail": "Projeto inválido."})
    with database.db() as conn:
        exists = conn.execute("SELECT id FROM projects WHERE id=?", (value,)).fetchone() if 0 < value < 2**63 else None
    if not exists:
        return JSONResponse(status_code=404, content={"detail": "Projeto não encontrado."})
    token = project_id.set(value)
    audit = audit_enabled.set(request.url.path in ("/api/chat", "/api/terminal") or request.url.path.startswith("/api/actions/"))
    try:
        return await call_next(request)
    finally:
        project_id.reset(token)
        audit_enabled.reset(audit)


# Rotas /api/* que devem responder mesmo sem token — health check e a
# própria UI não podem depender de um segredo pra sinalizar "estou vivo".
_PUBLIC_API_PATHS = {"/api/health"}
_RATE_WINDOW_SECONDS = 60
# Bounded LRU: caps memory even if the server is reachable beyond loopback
# and sees requests from many/rotating client addresses (each address gets
# a permanent dict entry otherwise — a slow memory-exhaustion path).
_MAX_RATE_BUCKETS = 10_000
_rate_buckets: "OrderedDict[str, deque]" = OrderedDict()
_rate_lock = asyncio.Lock()


@app.middleware("http")
async def _enforce_api_token(request: Request, call_next):
    """Optional shared-secret gate (API_TOKEN). Off by default — this app
    is meant for single-user localhost use — but becomes load-bearing the
    moment HOST is changed away from 127.0.0.1."""
    path = request.url.path
    if settings.api_token and path.startswith("/api/") and path not in _PUBLIC_API_PATHS:
        got = request.headers.get("x-api-token") or ""
        # Constant-time compare: a plain != leaks how many leading
        # characters of a guessed token are correct, and this check only
        # matters once the app is reachable beyond loopback.
        if not hmac.compare_digest(got, settings.api_token):
            return JSONResponse(status_code=401, content={"detail": "token inválido ou ausente"})
    return await call_next(request)


@app.middleware("http")
async def _enforce_rate_limit(request: Request, call_next):
    """Sliding-window rate limit per client address, in-memory (single
    process, no extra dependency) — caps how hard any one client can hit
    the LLM/tool endpoints, including a misbehaving local client."""
    path = request.url.path
    if path.startswith("/api/"):
        client_id = request.client.host if request.client else "unknown"
        now = time.monotonic()
        async with _rate_lock:
            bucket = _rate_buckets.get(client_id)
            if bucket is None:
                bucket = deque()
                _rate_buckets[client_id] = bucket
                if len(_rate_buckets) > _MAX_RATE_BUCKETS:
                    _rate_buckets.popitem(last=False)  # evict oldest-seen client
            else:
                _rate_buckets.move_to_end(client_id)
            while bucket and now - bucket[0] > _RATE_WINDOW_SECONDS:
                bucket.popleft()
            if len(bucket) >= settings.rate_limit_per_minute:
                return JSONResponse(status_code=429, content={"detail": "muitas requisições, aguarde um pouco"})
            bucket.append(now)
    return await call_next(request)


_provider = build_provider()
_research_provider = build_research_provider()
_registry = build_registry()
_store = ConfirmationStore()
_chat = ChatService(_provider, _registry, _store, _research_provider)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR / "static"), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


# --- Health ---
@app.get("/api/health")
async def health() -> dict:
    # override salvo via UI (POST /api/provider/research) tem prioridade
    # sobre o .env — health precisa refletir o que tá REALMENTE ativo, não
    # só o valor estático do .env (senão a UI mostra "não configurado"
    # mesmo com um override aplicado e funcionando).
    override = get_research_provider_override()
    research_provider = override["provider"] if override else (settings.research_provider or None)
    research_model = (override.get("model") if override else settings.research_model) or None
    return {
        "status": "ok",
        "provider": settings.ai_provider,
        "model": settings.ai_model,
        "research_provider": research_provider,
        "research_model": research_model,
        "safe_mode": settings.safe_mode,
        "tools": [t.name for t in _registry.list()],
        "authorized_scope": scope_module.get_scope(),
    }


# --- Chat (SSE stream) ---
@app.post("/api/chat")
async def chat(body: dict):
    message = (body.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Mensagem vazia.")

    if body.get("task_id"):
        import uuid
        try:
            body["task_id"] = str(uuid.UUID(str(body["task_id"])))
        except ValueError:
            raise HTTPException(422, "Identificador de tarefa inválido.")
        if body["task_id"] in manager.works:
            raise HTTPException(409, "Identificador de tarefa já utilizado.")

    async def event_stream():
        # Producer/consumer: the orchestrator streams the growing answer into
        # a queue via on_delta while the model generates; the consumer forwards
        # each snapshot as an SSE event so the browser repaints live instead of
        # waiting for the whole completion (a single answer can take ~1min on a
        # local CPU model). An immediate progress ping fills the gap before the
        # first token (tool selection + tool run happen before any synthesis).
        queue: asyncio.Queue = asyncio.Queue()
        done = object()

        async def on_delta(text_so_far: str) -> None:
            await queue.put({"content": text_so_far})

        async def on_progress(status: str) -> None:
            # status curto das fases lentas antes da síntese (decidir/rodar
            # ferramenta), separado dos tokens da resposta final.
            work = current_task.get()
            if work:
                work.progress(status)
            await queue.put({"progress": status})

        async def producer() -> None:
            try:
                service = ChatService(_provider, _registry, _store, _research_provider)
                result = await service.stream(message, on_delta=on_delta,
                                            on_progress=on_progress)
                final = {"content": result["content"]}
                if result.get("pending"):
                    final["pending"] = result["pending"]
                    work = current_task.get()
                    if work:
                        work.status = "awaiting_approval"
                        work.progress("Aguardando aprovação do operador.")
                await queue.put(final)
            except asyncio.CancelledError:
                await queue.put({"content": "Execução cancelada pelo operador.", "cancelled": True})
                raise
            except Exception as exc:
                msg = describe_exception(exc)
                log_event("danger", "chat_error", msg)
                await queue.put({"error": msg})
                work = current_task.get()
                if work:
                    work.status = "error"
            finally:
                await queue.put(done)

        work = manager.start(producer, body.get("task_id"))
        task = work.task
        task.add_done_callback(lambda _: queue.put_nowait(done))
        yield f"data: {json.dumps({'content': '⏳ Analisando…', 'task_id': work.id}, ensure_ascii=False)}\n\n"
        try:
            while True:
                item = await queue.get()
                if item is done:
                    break
                if "error" in item:
                    yield f"event: error\ndata: {json.dumps(item, ensure_ascii=False)}\n\n"
                    continue
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
            yield "event: done\ndata: {}\n\n"
        finally:
            if not task.done():
                await manager.cancel(work)
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --- Tools ---
@app.get("/api/tools")
async def list_tools() -> dict:
    return {"tools": [
        {"name": t.name, "description": t.description, "risk": t.risk, "category": t.category}
        for t in _registry.list()
    ]}


# --- Controlled terminal ---
@app.post("/api/terminal")
async def terminal(body: dict):
    """Run a command ONLY if it is on the read-only allowlist.

    deny → blocked outright; unknown → requires human confirmation
    (UI receives status=confirm). A raw shell is never used.
    """
    cmd = (body.get("command") or "").strip()
    if not cmd:
        raise HTTPException(status_code=400, detail="comando vazio")
    argv = cmd.split()
    verdict = executor.classify_command(argv)
    if verdict == "deny":
        database.insert_security_event("warning", "terminal", f"Comando bloqueado: {cmd}")
        log_event("warning", "terminal", f"bloqueado: {cmd}")
        return {"status": "denied", "output": ""}
    if verdict == "unknown":
        database.insert_security_event("warning", "terminal", f"Comando requer confirmação: {cmd}")
        log_event("warning", "terminal", f"requer confirmação: {cmd}")
        return {"status": "confirm", "output": ""}
    # allow → execute
    try:
        out, err = await executor.run_safe_command(argv)
    except Exception as exc:
        return {"status": "error", "output": f"erro: {exc}"}
    database.insert_security_event("info", "terminal", f"Comando executado: {cmd}")
    log_event("info", "terminal", f"executado: {cmd}")
    return {"status": "ok", "output": out}


# --- Aprovação humana de ações (nmap, captura, OSINT...) ---
@app.post("/api/actions/{action_id}/approve")
async def approve_action(action_id: int, task_id: str | None = None) -> dict:
    action = _store.get(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Ação não encontrada.")
    if action.status != "pending":
        raise HTTPException(409, "Ação já resolvida ou em execução.")
    async def execute():
        text = await _store.resolve(action, True, _registry)
        if action.status == "approved":
            service = ChatService(_provider, _registry, _store, _research_provider)
            text = await service.orchestrator.synthesize_approved(action_id)
        database.save_messages([{"role": "assistant", "content": text}])
        return {"status": action.status, "content": text}
    try:
        work = manager.start(execute, task_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    try:
        return await asyncio.shield(work.task)
    except asyncio.CancelledError:
        await manager.cancel(work)
        database.save_messages([{"role": "assistant", "content": "Execução cancelada pelo operador."}])
        return {"status": "cancelled", "content": "Execução cancelada pelo operador."}



@app.post("/api/actions/{action_id}/deny")
async def deny_action(action_id: int) -> dict:
    action = _store.get(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Ação não encontrada.")
    text = await _store.resolve(action, False, _registry)
    return {"status": action.status, "content": text}


# --- Safety Layer introspection ---
@app.post("/api/safety/classify")
async def classify(body: dict) -> dict:
    action = (body.get("action") or "").strip()
    if not action:
        raise HTTPException(status_code=400, detail="action vazio")
    risk_name = body.get("risk", "info")
    try:
        risk = Risk(risk_name)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"risk inválido: {risk_name}")
    decision = classify_action(action, risk)
    # Command-level detail via the executor classifier.
    from tools.terminal.executor import classify_command
    command_verdict = "unknown"
    if action.startswith("command:"):
        command_verdict = classify_command(action.split(":", 1)[1].strip().split())
    return {"decision": decision.value, "command": command_verdict, "risk": risk.value}


# --- Config do research provider (2° modelo opcional — openrouter/anthropic/etc) ---
@app.get("/api/provider/research")
async def get_research_provider_config() -> dict:
    override = get_research_provider_override()
    if override:
        return {
            "source": "ui",
            "provider": override["provider"],
            "base_url": override.get("base_url", ""),
            "model": override.get("model", ""),
            "api_key_set": bool(override.get("api_key")),
            "available_providers": available_providers(),
        }
    return {
        "source": "env" if settings.research_provider else "none",
        "provider": settings.research_provider or None,
        "base_url": settings.research_base_url,
        "model": settings.research_model,
        "api_key_set": bool(settings.research_api_key),
        "available_providers": available_providers(),
    }


@app.post("/api/provider/research")
async def set_research_provider_config(body: dict) -> dict:
    provider = str(body.get("provider") or "").strip()
    if provider and provider.lower() not in available_providers():
        raise HTTPException(status_code=400, detail=f"provider desconhecido: {provider!r}")
    base_url = str(body.get("base_url") or "").strip()
    model = str(body.get("model") or "").strip()
    api_key = body.get("api_key")
    api_key = str(api_key).strip() if isinstance(api_key, str) and api_key.strip() else None
    set_research_provider_override(provider, base_url, model, api_key)

    global _research_provider
    old_provider = _research_provider
    _research_provider = build_research_provider()
    _chat.orchestrator.research_provider = _research_provider
    with contextlib.suppress(Exception):
        await old_provider.aclose()

    log_event("info", "provider",
             f"research provider config atualizado: {provider or '(removido, volta pro .env)'}")
    return await get_research_provider_config()


# --- Escopo autorizado (gate opt-in antes de rodar ferramenta ofensiva) ---
@app.get("/api/scope")
async def get_scope() -> dict:
    return {"scope": scope_module.get_scope()}


@app.post("/api/scope")
async def set_scope(body: dict) -> dict:
    patterns = body.get("scope")
    if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
        raise HTTPException(status_code=400, detail="'scope' precisa ser uma lista de strings")
    saved = scope_module.set_scope(patterns)
    log_event("info", "scope", f"escopo autorizado atualizado: {saved}")
    return {"scope": saved}


# --- History ---
@app.get("/api/history")
async def history(limit: int = 12) -> dict:
    return {"messages": database.history(limit=limit)}


# --- System summary (Dashboard) ---
@app.get("/api/system")
async def system_summary() -> dict:
    try:
        mem = await _registry.run("memory_info", {})
        disk = await _registry.run("disk_info", {})
        return {
            "memory": mem,
            "disk": disk,
            "cpu_percent": cpu_percent(),
            "mem_percent": mem_percent(),
            "disk_percent": disk_percent(),
            "alerts": database.get_alert_counts(),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# --- Security events & alerts ---
@app.get("/api/security/events")
async def security_events() -> dict:
    with database.db() as conn:
        rows = conn.execute(
            "SELECT id, level, category, description, created_at FROM security_events WHERE project_id=? ORDER BY id DESC LIMIT 20", (project_id.get(),)
        ).fetchall()
    return {"events": [dict(r) for r in rows]}


@app.get("/api/alerts")
async def alerts() -> dict:
    with database.db() as conn:
        rows = conn.execute(
            "SELECT id, severity, title, description, acknowledged, created_at FROM alerts WHERE project_id=? ORDER BY id DESC LIMIT 20", (project_id.get(),)
        ).fetchall()
    return {"alerts": [dict(r) for r in rows]}


@app.post("/api/alerts/ack")
async def ack_alert(body: dict) -> dict:
    alert_id = body.get("id")
    if not alert_id:
        raise HTTPException(status_code=400, detail="id vazio")
    with database.db() as conn:
        conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=? AND project_id=?", (alert_id, project_id.get()))
    return {"ok": True}


# --- Relatório de pentest (Markdown, achados + alertas) ---
@app.get("/api/report")
async def pentest_report() -> Response:
    report = generate_pentest_report()
    filename = f"pentest-report-{time.strftime('%Y%m%d-%H%M%S')}.md"
    return Response(
        content=report,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --- Memória longa (fatos guardados via a tool 'remember') ---
@app.get("/api/memory")
async def list_memory() -> dict:
    return {"facts": database.list_memory(limit=50)}


@app.post("/api/memory")
async def add_memory(body: dict) -> dict:
    """Guarda um fato direto pela UI, sem passar pelo chat/LLM.

    Reusa tool_remember (não duplica sanitização/limite de tamanho aqui).
    """
    content = (body.get("content") or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="content vazio")
    from tools.memory import tool_remember
    message = await tool_remember({"content": content})
    return {"ok": True, "message": message}


@app.delete("/api/memory/{memory_id}")
async def forget_memory(memory_id: int) -> dict:
    ok = database.delete_memory(memory_id)
    if not ok:
        raise HTTPException(status_code=404, detail="fato não encontrado")
    return {"ok": True}


# --- Progresso do modo Learning ---
@app.get("/api/learning/progress")
async def learning_progress() -> dict:
    return {"progress": database.learning_progress()}


# --- Áudio: STT (whisper local) e TTS (espeak-ng) ---
@app.post("/api/audio/transcribe")
async def transcribe(file: UploadFile):
    """Recebe áudio (WAV) e devolve a transcrição em pt-BR."""
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="áudio vazio")
    try:
        from services.audio import transcribe_audio
        text = await transcribe_audio(data)
    except Exception as exc:
        log_event("danger", "stt_error", str(exc))
        raise HTTPException(status_code=500, detail=f"STT falhou: {exc}")
    return {"text": text}


@app.post("/api/audio/speak")
async def speak(body: dict):
    """Gera WAV pt-br a partir do texto (TTS via espeak-ng)."""
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="texto vazio")
    try:
        from services.audio import speak_to_wav
        wav = await speak_to_wav(text)
    except Exception as exc:
        log_event("danger", "tts_error", str(exc))
        raise HTTPException(status_code=500, detail=f"TTS falhou: {exc}")
    # Edge-TTS devolve MP3; espeak-ng devolve WAV. Sniff no header pra escolher.
    is_mp3 = wav[:3] == b"ID3" or (len(wav) > 1 and wav[0] == 0xFF and 0xE0 <= wav[1] <= 0xFF)
    media = "audio/mpeg" if is_mp3 else "audio/wav"
    return Response(content=wav, media_type=media)


# --- Visão: a personagem "vê" a tela e descreve ---
@app.post("/api/vision")
async def vision(body: dict):
    """Captura o desktop (grim) e pede descrição ao modelo de visão (NVIDIA)."""
    prompt = (body.get("prompt") or "").strip() or (
        "Descreva de forma curta e útil o que está visível na tela. "
        "Seja específico sobre janelas, texto e estado. Responda em português."
    )
    try:
        from ai.providers import build_vision_provider
        from services.screen import capture_screen
        b64 = await capture_screen()
    except Exception as exc:
        log_event("danger", "vision_capture", str(exc))
        raise HTTPException(status_code=500, detail=f"captura falhou: {exc}")

    provider = build_vision_provider()
    messages = [{
        "role": "user",
        "content": [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}},
        ],
    }]
    try:
        text = await provider.complete(messages, max_tokens=400)
    except Exception as exc:
        log_event("danger", "vision_error", str(exc))
        raise HTTPException(status_code=500, detail=f"visão falhou: {exc}")
    finally:
        await provider.aclose()
    return {"text": text}
