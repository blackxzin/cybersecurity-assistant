"""Project workspace and evidence review API."""
from typing import Literal
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from database import db as database
from database.context import project_id
from security.sanitize import sanitize_text
from services.tasks import manager

router = APIRouter(prefix="/api")

class ProjectInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)

class FindingInput(BaseModel):
    tool_call_id: int
    title: str = Field(min_length=1, max_length=200)
    severity: Literal['info', 'low', 'medium', 'high', 'critical'] = 'info'
    evidence: str = Field(min_length=1, max_length=20000)
    impact: str = Field(default='', max_length=5000)
    remediation: str = Field(default='', max_length=5000)
    review_status: Literal['pending', 'confirmed', 'rejected', 'resolved'] = 'pending'

@router.get('/projects')
async def projects():
    with database.db() as conn:
        return {'projects': [dict(r) for r in conn.execute('SELECT * FROM projects ORDER BY id')]}

@router.post('/projects', status_code=201)
async def create_project(body: ProjectInput):
    name = sanitize_text(body.name.strip())
    if not name:
        raise HTTPException(422, 'Nome vazio.')
    return {'id': database.insert('projects', name=name, created_at=database._now()), 'name': name}

@router.get('/executions')
async def executions():
    with database.db() as conn:
        rows = conn.execute('SELECT id, tool, args, status, risk, created_at FROM tool_calls WHERE project_id=? ORDER BY id DESC LIMIT 200', (project_id.get(),))
        return {'executions': [dict(r) for r in rows]}

@router.get('/executions/{call_id}')
async def evidence(call_id: int):
    with database.db() as conn:
        row = conn.execute('SELECT * FROM tool_calls WHERE id=? AND project_id=?', (call_id, project_id.get())).fetchone()
    if not row:
        raise HTTPException(404, 'Execução não encontrada neste projeto.')
    return dict(row)

@router.get('/findings')
async def findings():
    with database.db() as conn:
        return {'findings': [dict(r) for r in conn.execute('SELECT * FROM findings WHERE project_id=? ORDER BY id DESC', (project_id.get(),))]}

async def validate_finding(body):
    call = await evidence(body.tool_call_id)
    values = body.model_dump()
    for key in ('title', 'evidence', 'impact', 'remediation'):
        values[key] = sanitize_text(values[key].strip())
    if not values['title'] or not values['evidence']:
        raise HTTPException(422, 'Título e evidência são obrigatórios.')
    if values['evidence'] not in call['result']:
        raise HTTPException(422, 'A evidência deve ser um trecho literal da saída registrada.')
    if body.review_status == 'confirmed' and (call['status'] != 'ok' or not values['impact'] or not values['remediation']):
        raise HTTPException(422, 'Confirmação exige execução bem-sucedida, impacto e correção preenchidos.')
    return values

@router.post('/findings', status_code=201)
async def create_finding(body: FindingInput):
    values = await validate_finding(body)
    now = database._now()
    return {'id': database.insert('findings', project_id=project_id.get(), **values, created_at=now, updated_at=now)}

@router.put('/findings/{finding_id}')
async def update_finding(finding_id: int, body: FindingInput):
    values = await validate_finding(body)
    with database.db() as conn:
        cur = conn.execute('UPDATE findings SET tool_call_id=?, title=?, severity=?, evidence=?, impact=?, remediation=?, review_status=?, updated_at=? WHERE id=? AND project_id=?',
                           (values['tool_call_id'], values['title'], values['severity'], values['evidence'], values['impact'], values['remediation'], values['review_status'], database._now(), finding_id, project_id.get()))
        if not cur.rowcount:
            raise HTTPException(404, 'Achado não encontrado neste projeto.')
    return {'id': finding_id}

@router.get('/tasks/{task_id}')
async def task_status(task_id: str):
    work = manager.get(task_id)
    if not work:
        raise HTTPException(404, 'Tarefa não encontrada neste projeto.')
    return work.as_dict()

@router.post('/tasks/{task_id}/cancel')
async def cancel_task(task_id: str):
    work = manager.get(task_id)
    if not work:
        raise HTTPException(404, 'Tarefa não encontrada neste projeto.')
    return await manager.cancel(work)
