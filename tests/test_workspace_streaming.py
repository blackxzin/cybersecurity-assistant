import asyncio
import json
import uuid
import pytest
import httpx
from database import db
from config.settings import settings
from tools.registry import ToolRegistry
from tools.confirm import ConfirmationStore

@pytest.fixture
def api(tmp_path, monkeypatch):
    from api import main
    monkeypatch.setattr(db, 'DB_PATH', tmp_path / 'test.db')
    monkeypatch.setattr(db, 'LOG_DIR', tmp_path / 'logs')
    monkeypatch.setattr(db, 'DATA_DIR', tmp_path)
    db.init_db()
    main._rate_buckets.clear()
    from services.tasks import TaskManager
    monkeypatch.setattr(main, 'manager', TaskManager())
    import api.projects
    monkeypatch.setattr(api.projects, 'manager', main.manager)
    monkeypatch.setattr(main, '_store', ConfirmationStore())
    monkeypatch.setattr(settings, 'safe_mode', 'assisted')
    return main

class Provider:
    async def complete(self, messages, **extra):
        if extra.get('json_mode'):
            return json.dumps({'tool':'probe', 'args':{'host':'127.0.0.1'}})
        return 'Resposta da ferramenta.'
    async def stream_chat(self, messages, **extra):
        yield 'Resposta da ferramenta.'

async def test_chat_stream_persists_evidence_and_progress_in_selected_project(api, monkeypatch):
    registry = ToolRegistry()
    async def probe(args): return 'Porta local identificada.'
    registry.register('probe', 'probe', probe, category='rede', target_arg='host')
    monkeypatch.setattr(api, '_registry', registry)
    monkeypatch.setattr(api, '_provider', Provider())
    project = db.insert('projects', name='B', created_at=db._now())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
        headers={'X-Project-ID':str(project)}
        task_id = str(uuid.uuid4())
        r = await client.post('/api/chat', json={'message':'teste rede', 'task_id':task_id}, headers=headers)
        assert r.status_code == 200
        assert 'event: done' in r.text and 'Resposta da ferramenta.' in r.text and 'progress' in r.text
        assert (await client.get('/api/history')).json()['messages'] == []
        calls = (await client.get('/api/executions', headers=headers)).json()['executions']
        assert len(calls) == 1
        assert (await client.get(f'/api/tasks/{task_id}', headers=headers)).json()['status'] == 'completed'
        assert (await client.get(f'/api/tasks/{task_id}')).status_code == 404
        assert (await client.post('/api/chat', json={'message':'x','task_id':'bad'})).status_code == 422
        assert (await client.post('/api/chat', json={'message':'x','task_id':task_id})).status_code == 409

async def test_cancel_running_chat_records_cancelled_evidence(api, monkeypatch):
    started = asyncio.Event(); cleaned = asyncio.Event()
    async def probe(args):
        started.set()
        try: await asyncio.sleep(60)
        finally: cleaned.set()
    registry = ToolRegistry(); registry.register('probe', 'probe', probe, category='rede')
    monkeypatch.setattr(api, '_registry', registry); monkeypatch.setattr(api, '_provider', Provider())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
        task_id = str(uuid.uuid4())
        response = asyncio.create_task(client.post('/api/chat', json={'message':'teste rede', 'task_id':task_id}))
        await asyncio.wait_for(started.wait(), 3)
        r = await client.post(f'/api/tasks/{task_id}/cancel')
        assert r.json()['status'] == 'cancelled' and cleaned.is_set()
        body = await asyncio.wait_for(response, 3)
        assert 'cancelada' in body.text
        assert (await client.get('/api/executions')).json()['executions'][0]['status'] == 'cancelled'
        assert (await client.post('/api/tasks/missing/cancel')).status_code == 404

async def test_approved_task_can_be_cancelled_and_is_audited(api, monkeypatch):
    started = asyncio.Event()
    async def probe(args): started.set(); await asyncio.sleep(60)
    registry = ToolRegistry(); registry.register('probe', 'probe', probe, category='rede', requires_confirmation=True)
    monkeypatch.setattr(api, '_registry', registry); monkeypatch.setattr(api, '_provider', Provider())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
        response = await client.post('/api/chat', json={'message':'teste rede'})
        events = [json.loads(line[5:]) for line in response.text.splitlines() if line.startswith('data:')]
        action = next(e['pending'] for e in events if 'pending' in e)
        task_id = str(uuid.uuid4())
        approval = asyncio.create_task(client.post(f'/api/actions/{action["id"]}/approve?task_id={task_id}'))
        await asyncio.wait_for(started.wait(), 3)
        assert (await client.post(f'/api/tasks/{task_id}/cancel')).json()['status'] == 'cancelled'
        assert (await approval).json()['status'] == 'cancelled'
        calls = (await client.get('/api/executions')).json()['executions']
        assert len(calls) == 1 and calls[0]['status'] == 'cancelled'

async def test_approved_success_is_in_history_and_evidence(api, monkeypatch):
    async def probe(args): return 'Evidência aprovada.'
    registry = ToolRegistry(); registry.register('probe', 'probe', probe)
    monkeypatch.setattr(api, '_registry', registry); monkeypatch.setattr(api, '_provider', Provider())
    action = await api._store.register('probe', {}, 'prompt', 'resumo')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
        r = await client.post(f'/api/actions/{action.id}/approve')
        assert r.json()['status'] == 'approved'
        assert len((await client.get('/api/history')).json()['messages']) == 1
        assert len((await client.get('/api/executions')).json()['executions']) == 1
