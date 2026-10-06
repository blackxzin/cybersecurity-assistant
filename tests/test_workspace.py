"""Regression coverage for project boundaries and evidence-based review."""
import asyncio
import json
import sqlite3
from contextlib import closing

import pytest
from fastapi.testclient import TestClient
from config.settings import settings
from database import db
from database.context import project_context, audit_enabled
from security.scope import get_scope, set_scope
from services.report import generate_pentest_report
from tools.registry import ToolRegistry

@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(db, 'DB_PATH', tmp_path / 'workspace.db')
    monkeypatch.setattr(db, 'LOG_DIR', tmp_path / 'logs')
    monkeypatch.setattr(db, 'DATA_DIR', tmp_path)
    db.init_db()
    return tmp_path

@pytest.fixture
def client(isolated, monkeypatch):
    monkeypatch.setattr(settings, 'watcher_enabled', False)
    from api import main
    main._rate_buckets.clear()
    with TestClient(main.app) as client:
        yield client

def new_project():
    return db.insert('projects', name='Projeto B', created_at=db._now())

def test_migration_preserves_legacy_rows_and_is_idempotent(tmp_path, monkeypatch):
    path = tmp_path / 'old.db'
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript(db.SCHEMA)
        conn.execute("INSERT INTO tool_calls(tool,result,created_at) VALUES('nmap_scan','legacy','old')")
        conn.commit()
    monkeypatch.setattr(db, 'DB_PATH', path)
    db.init_db(); db.init_db()
    with db.db() as conn:
        row = conn.execute('SELECT result, project_id FROM tool_calls').fetchone()
        assert tuple(row) == ('legacy', 1)
        assert conn.execute('SELECT COUNT(*) FROM projects').fetchone()[0] == 1

def test_project_context_isolates_history_scope_memory_snapshots_and_report(isolated):
    project = new_project()
    db.save_messages([{'role': 'user', 'content': 'Segredo do projeto A'}])
    mem = db.insert_memory('fato A')
    db.log_tool_call('nmap_scan', {}, 'evidência A')
    db.insert_alert('high', 'alerta A', 'descrição')
    db.save_snapshot('nmap', 'localhost', 'A')
    set_scope(['example.com'])
    with project_context(project):
        assert db.history() == []
        assert db.recent_conversation_id() is None
        assert db.list_memory() == []
        assert not db.delete_memory(mem)
        assert db.get_snapshot('nmap', 'localhost') is None
        assert get_scope() == []
        assert db.get_alert_counts() == {}
        report = generate_pentest_report()
        assert 'evidência A' not in report and 'alerta A' not in report
        db.save_messages([{'role': 'user', 'content': 'B'}])
        assert db.recent_conversation_id() is not None
        db.insert_memory('B', 'network')
        assert db.list_memory('network')[0]['content'] == 'B'
        db.save_snapshot('nmap', 'localhost', 'B')
        assert db.get_snapshot('nmap', 'localhost') == 'B'
        set_scope(['localhost'])
    assert db.get_snapshot('nmap', 'localhost') == 'A'
    assert get_scope() == ['example.com']
    assert len(db.history()) == 1

async def test_concurrent_project_contexts_do_not_leak(isolated):
    project = new_project()
    async def turn(pid, text):
        with project_context(pid):
            await asyncio.sleep(0)
            db.save_messages([{'role': 'user', 'content': text}])
            await asyncio.sleep(0)
            return db.history()[0]['content']
    assert await asyncio.gather(turn(1, 'A'), turn(project, 'B')) == ['A', 'B']

@pytest.mark.parametrize('header,status', [('x',422), ('-1',404), ('999',404), (str(2**80),404)])
def test_api_rejects_invalid_project(client, header, status):
    assert client.get('/api/history', headers={'X-Project-ID':header}).status_code == status

def test_project_api(client):
    assert client.post('/api/projects', json={'name':' '}).status_code == 422
    r = client.post('/api/projects', json={'name':'Teste'})
    assert r.status_code == 201
    pid = r.json()['id']
    assert len(client.get('/api/projects').json()['projects']) == 2
    headers = {'X-Project-ID': str(pid)}
    assert client.post('/api/scope', headers=headers, json={'scope':['127.0.0.1']}).status_code == 200
    assert client.get('/api/scope').json()['scope'] == []
    assert client.get('/api/scope', headers=headers).json()['scope'] == ['127.0.0.1']

def finding_body(call):
    return dict(tool_call_id=call, title='Header ausente', severity='low', evidence='CSP: ausente',
                impact='Defesa adicional ausente', remediation='Definir uma política adequada', review_status='pending')

def test_finding_workflow_and_report_exclude_other_projects(client):
    call = db.log_tool_call('http_headers', {'url':'http://127.0.0.1'}, 'HTTP 200\nCSP: ausente\n' + 'x'*9000)
    body = finding_body(call)
    r = client.post('/api/findings', json=body)
    assert r.status_code == 201
    fid = r.json()['id']
    body['review_status'] = 'confirmed'
    assert client.put(f'/api/findings/{fid}', json=body).status_code == 200
    assert client.get('/api/findings').json()['findings'][0]['review_status'] == 'confirmed'
    report = client.get('/api/report').text
    assert 'Header ausente' in report and 'confirmed' in report and 'CSP: ausente' in report
    assert len(client.get(f'/api/executions/{call}').json()['result']) > 9000
    assert client.get('/api/executions').json()['executions'][0]['id'] == call
    other = {'X-Project-ID': str(new_project())}
    assert client.get('/api/findings', headers=other).json()['findings'] == []
    assert client.get('/api/executions', headers=other).json()['executions'] == []
    assert client.get(f'/api/executions/{call}', headers=other).status_code == 404
    assert client.post('/api/findings', headers=other, json=body).status_code == 404
    assert client.put(f'/api/findings/{fid}', headers=other, json=body).status_code == 404
    assert 'Header ausente' not in client.get('/api/report', headers=other).text
    assert client.put('/api/findings/9999', json=body).status_code == 404

@pytest.mark.parametrize('changes', [dict(evidence='inventada'), dict(evidence=' '), dict(title=' '), dict(severity='banana'), dict(review_status='confirmed', impact=''), dict(review_status='confirmed', remediation='')])
def test_finding_rejects_fabricated_evidence_or_incomplete_confirmation(client, changes):
    call = db.log_tool_call('http_headers', {}, 'CSP: ausente')
    body = finding_body(call); body.update(changes)
    assert client.post('/api/findings', json=body).status_code == 422

def test_failed_execution_cannot_be_confirmed(client):
    call = db.log_tool_call('http_headers', {}, 'CSP: ausente', status='error')
    body = finding_body(call); body['review_status'] = 'confirmed'
    assert client.post('/api/findings', json=body).status_code == 422

async def test_registry_persists_full_evidence_error_cancel_and_redacts_arguments(isolated):
    registry = ToolRegistry()
    async def ok(args): return 'evidence\n' + 'x' * 9000
    async def fail(args): raise RuntimeError('falha real')
    async def cancelled(args): raise asyncio.CancelledError()
    async def error_text(args): return 'erro: timeout'
    for name, fn in [('ok',ok), ('fail',fail), ('cancelled',cancelled), ('error_text',error_text)]:
        registry.register(name, name, fn)
    token = audit_enabled.set(True)
    try:
        await registry.run('ok', {'password':'private', 'host':'127.0.0.1'})
        with pytest.raises(RuntimeError): await registry.run('fail', {})
        with pytest.raises(asyncio.CancelledError): await registry.run('cancelled', {})
        await registry.run('error_text', {})
    finally:
        audit_enabled.reset(token)
    with db.db() as conn:
        rows = conn.execute('SELECT * FROM tool_calls ORDER BY id').fetchall()
    assert len(rows) == 4
    assert len(rows[0]['result']) > 9000
    assert 'private' not in rows[0]['args']
    assert json.loads(rows[0]['args'])['host'] == '127.0.0.1'
    assert [r['status'] for r in rows] == ['ok','error','cancelled','error']

async def test_pending_action_remembers_project_and_rechecks_scope(isolated):
    from tools.confirm import ConfirmationStore
    store = ConfirmationStore(); registry = ToolRegistry()
    called = []
    async def tool(args): called.append(args); return 'ok'
    registry.register('scan', 'scan', tool, target_arg='host')
    action = await store.register('scan', {'host':'127.0.0.1'}, 'p', 's', timeout=1)
    with project_context(new_project()):
        assert store.get(action.id) is None
        assert 'outro projeto' in await store.resolve(action, True, registry)
    set_scope(['example.com'])
    assert 'fora do escopo' in await store.resolve(action, True, registry)
    assert not called
