"""In-process task tracking. Cancellation completes only after cleanup."""
import asyncio
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from database.context import project_id

current_task = ContextVar("current_task", default=None)

@dataclass
class Work:
    id: str
    project_id: int
    started: float = field(default_factory=time.monotonic)
    status: str = "running"
    stage: str = "Analisando…"
    events: list = field(default_factory=list)
    task: asyncio.Task | None = None
    finished: float | None = None

    def progress(self, text):
        self.stage = text
        self.events.append({"stage": text, "elapsed": round(time.monotonic() - self.started, 1)})
        self.events = self.events[-100:]

    def as_dict(self):
        return {"id": self.id, "status": self.status, "stage": self.stage,
                "elapsed": round((self.finished or time.monotonic()) - self.started, 1),
                "events": self.events}

class TaskManager:
    def __init__(self):
        self.works = {}

    def start(self, fn, task_id=None):
        task_id = str(uuid.UUID(task_id)) if task_id else str(uuid.uuid4())
        if task_id in self.works:
            raise ValueError("Identificador de tarefa já utilizado.")
        for key, value in list(self.works.items()):
            if len(self.works) < 200:
                break
            if value.finished is not None:
                del self.works[key]
        if len(self.works) >= 200:
            raise ValueError("Muitas tarefas em andamento.")
        work = Work(task_id, project_id.get())
        self.works[task_id] = work

        async def run():
            token = current_task.set(work)
            try:
                result = await fn()
                if work.status == "running":
                    work.status = "completed"
                    work.progress("Concluída.")
                return result
            except asyncio.CancelledError:
                work.status = "cancelled"
                work.stage = "Cancelada; processos encerrados."
                raise
            except Exception:
                work.status = "error"
                work.stage = "Falha na execução."
                raise
            finally:
                work.finished = time.monotonic()
                current_task.reset(token)

        work.task = asyncio.create_task(run())
        return work

    def get(self, task_id):
        work = self.works.get(task_id)
        return work if work and work.project_id == project_id.get() else None

    async def cancel(self, work):
        if work.finished is None and work.status != "cancelling":
            work.status = "cancelling"
            work.task.cancel()
        try:
            await asyncio.shield(work.task)
        except (asyncio.CancelledError, Exception):
            pass
        if work.finished is None and work.task.done():
            work.status = "cancelled"
            work.stage = "Cancelada; processos encerrados."
            work.finished = time.monotonic()
        return work.as_dict()

manager = TaskManager()
