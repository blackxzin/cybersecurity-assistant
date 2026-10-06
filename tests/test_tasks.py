"""Real process cancellation and task lifecycle tests; no external targets."""
import asyncio
import os
import sys
import pytest
from database.context import project_context
from services.tasks import TaskManager, current_task
from services.processes import communicate

async def test_cancellation_kills_real_process_and_waits_for_reaping(tmp_path):
    ready = asyncio.Event()
    proc = None
    async def run():
        nonlocal proc
        proc = await asyncio.create_subprocess_exec(sys.executable, '-c', 'import time; time.sleep(60)',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
        ready.set()
        await communicate(proc, 90)
    manager = TaskManager(); work = manager.start(run)
    await ready.wait()
    result = await manager.cancel(work)
    assert result['status'] == 'cancelled'
    assert proc.returncode is not None
    with pytest.raises(ProcessLookupError): os.kill(proc.pid, 0)
    assert (await manager.cancel(work))['status'] == 'cancelled'

async def test_timeout_kills_real_process():
    proc = await asyncio.create_subprocess_exec(sys.executable, '-c', 'import time; time.sleep(60)',
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
    with pytest.raises(TimeoutError): await communicate(proc, .02)
    assert proc.returncode is not None

async def test_task_lifecycle_and_project_ownership():
    manager = TaskManager()
    async def run():
        current_task.get().progress('Passo 1/2')
        return 'done'
    work = manager.start(run)
    assert await work.task == 'done'
    assert work.status == 'completed'
    assert work.as_dict()['events'][0]['stage'] == 'Passo 1/2'
    with project_context(2): assert manager.get(work.id) is None
    assert manager.get(work.id) is work
    with pytest.raises(ValueError): manager.start(run, work.id)
    with pytest.raises(ValueError): manager.start(run, 'bad-id')

async def test_task_cancel_before_first_turn_and_failure():
    manager = TaskManager()
    async def run(): await asyncio.sleep(60)
    work = manager.start(run)
    assert (await manager.cancel(work))['status'] == 'cancelled'
    async def fail(): raise RuntimeError('failed')
    work = manager.start(fail)
    with pytest.raises(RuntimeError): await work.task
    assert work.status == 'error'

async def test_nonzero_subprocess_exit_is_an_error_even_with_stdout():
    from tools.pentest import _run
    out = await _run([sys.executable, '-c', 'print("partial evidence"); raise SystemExit(2)'])
    assert out.startswith('erro:') and 'partial evidence' in out and 'código 2' in out
