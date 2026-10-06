"""Request-local project identity, inherited by asyncio child tasks."""
from contextvars import ContextVar
from contextlib import contextmanager

project_id = ContextVar("project_id", default=1)
audit_enabled = ContextVar("audit_enabled", default=False)

@contextmanager
def project_context(value: int):
    token = project_id.set(value)
    try:
        yield
    finally:
        project_id.reset(token)
