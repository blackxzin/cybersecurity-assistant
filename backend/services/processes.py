"""Reap subprocesses and their process group on timeout or cancellation."""
import asyncio
import contextlib
import os
import signal

async def stop_process(proc):
    with contextlib.suppress(ProcessLookupError):
        if isinstance(getattr(proc, "pid", None), int):
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    await proc.communicate()

async def communicate(proc, timeout):
    try:
        return await asyncio.wait_for(proc.communicate(), timeout)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        await asyncio.shield(stop_process(proc))
        raise
