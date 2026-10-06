/* Project-scoped requests, evidence review and cancellable task progress. */
let activeProject = localStorage.getItem('cyber-project') || '1';
let chatBusy = false, workspaceReady = false, activeTask = null, taskTimer = null;
const statusLabel = status => ({running:'em andamento', completed:'concluída', cancelled:'cancelada', cancelling:'cancelando', error:'falhou', awaiting_approval:'aguardando aprovação', ok:'executada', blocked:'bloqueada'}[status] || status);
const el = id => document.getElementById(id);
async function apiFetch(url, options = {}) {
  const project = activeProject;
  const headers = new Headers(options.headers || {});
  if (url.startsWith('/api/')) headers.set('X-Project-ID', activeProject);
  const response = await fetch(url, { ...options, headers });
  if (url.startsWith('/api/') && project !== activeProject) throw new Error('Projeto alterado; resposta anterior descartada.');
  return response;
}
async function apiJSON(url, options) {
  const response = await apiFetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Dados inválidos. Confira os campos.');
  return data;
}
function setChatBusy(value) {
  chatBusy = value;
  el('project-select').disabled = value;
  el('project-form').querySelector('button').disabled = value;
  el('chat-form').querySelector('[type=submit]').disabled = value;
  el('btn-clear').disabled = value;
}
async function loadProjects() {
  try {
    // Listing projects must remain possible if a saved selection was removed.
    const response = await fetch('/api/projects');
    if (!response.ok) throw new Error('Falha ao carregar projetos.');
    const { projects } = await response.json();
    if (!projects.some(p => String(p.id) === activeProject)) activeProject = '1';
    el('project-select').replaceChildren(...projects.map(p => new Option(p.name, p.id)));
    el('project-select').value = activeProject;
    el('project-select').disabled = chatBusy;
    localStorage.setItem('cyber-project', activeProject);
    workspaceReady = true;
  } catch (error) { toast(error.message); }
}
async function loadProjectHistory() {
  if (!workspaceReady) return;
  const { messages } = await apiJSON('/api/history?limit=100');
  el('messages').querySelectorAll('.msg').forEach(m => m.remove());
  el('chat-empty').classList.toggle('hidden', !!messages.length);
  messages.forEach(m => addMsg(m.role === 'user' ? 'user' : 'ai', m.content));
}
async function switchProject(id) {
  activeProject = String(id);
  localStorage.setItem('cyber-project', activeProject);
  await loadProjects();
  await loadProjectHistory();
  el('finding-form').reset();
  el('finding-id').value = '';
  el('task-progress').textContent = 'Pronto para iniciar.';
  el('task-events').replaceChildren();
  loadScope(); loadFindings(); loadMemory(); loadLogs(); loadDashboard();
}
el('project-select').addEventListener('change', e => switchProject(e.target.value).catch(error => toast(error.message)));
el('project-form').addEventListener('submit', async e => {
  e.preventDefault();
  if (chatBusy) return;
  try {
    const project = await apiJSON('/api/projects', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name: el('project-name').value}) });
    el('project-name').value = '';
    await switchProject(project.id);
  } catch (error) { toast(error.message); }
});
async function refreshTask() {
  const id = activeTask;
  if (!id) return;
  try {
    const work = await apiJSON(`/api/tasks/${id}`);
    if (activeTask !== id) return;
    el('task-progress').textContent = `${work.stage} · ${work.elapsed}s · ${statusLabel(work.status)}`;
    el('task-events').replaceChildren(...work.events.map(event => {
      const li = document.createElement('li'); li.textContent = `${event.elapsed}s — ${event.stage}`; return li;
    }));
    el('task-cancel').disabled = work.status !== 'running';
  } catch { /* Request may not have reached the server yet. */ }
}
function startTaskUI() {
  clearInterval(taskTimer);
  activeTask = crypto.randomUUID();
  el('task-progress').textContent = 'Iniciando…';
  el('task-events').replaceChildren();
  el('task-cancel').disabled = true;
  taskTimer = setInterval(refreshTask, 2000);
  return activeTask;
}
async function stopTaskUI() {
  clearInterval(taskTimer);
  await refreshTask();
  activeTask = null;
  el('task-cancel').disabled = true;
}
el('task-cancel').addEventListener('click', async () => {
  if (!activeTask) return;
  el('task-cancel').disabled = true;
  try {
    const work = await apiJSON(`/api/tasks/${activeTask}/cancel`, {method: 'POST'});
    el('task-progress').textContent = `${work.stage} · ${work.elapsed}s`;
  } catch (error) { toast(error.message); el('task-cancel').disabled = false; }
});
async function downloadText(text, filename, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], {type}));
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
el('report-link').addEventListener('click', async e => {
  e.preventDefault();
  try {
    const r = await apiFetch('/api/report');
    if (!r.ok) throw new Error('Falha ao gerar relatório.');
    await downloadText(await r.text(), `projeto-${activeProject}-relatorio.md`, 'text/markdown');
  } catch (error) { toast(error.message); }
});
let findingRows = [];
async function loadFindings() {
  try {
    const project = activeProject;
    const [calls, findings] = await Promise.all([apiJSON('/api/executions'), apiJSON('/api/findings')]);
    if (project !== activeProject) return;
    findingRows = findings.findings;
    const selected = el('finding-execution').value;
    el('finding-execution').replaceChildren(new Option('Selecione uma execução', ''), ...calls.executions.map(c => new Option(`#${c.id} ${c.tool} · ${statusLabel(c.status)} · ${c.created_at}`, c.id)));
    if (calls.executions.some(c => String(c.id) === selected)) el('finding-execution').value = selected;
    el('findings-list').replaceChildren(...findingRows.map(f => {
      const card = document.createElement('div'); card.className = 'tool';
      const title = document.createElement('strong'); title.textContent = `#${f.id} ${f.title} · ${f.severity} · ${f.review_status}`;
      const detail = document.createElement('p'); detail.textContent = f.impact || 'Impacto ainda não avaliado.';
      const button = document.createElement('button'); button.className = 'btn'; button.textContent = 'Revisar';
      button.addEventListener('click', () => editFinding(f)); card.append(title, detail, button); return card;
    }));
    if (!findingRows.length) el('findings-list').textContent = 'Nenhum achado registrado neste projeto.';
  } catch (error) { toast(error.message); }
}
function editFinding(f) {
  el('finding-id').value = f.id;
  if (![...el('finding-execution').options].some(o => o.value === String(f.tool_call_id))) {
    el('finding-execution').add(new Option(`Execução #${f.tool_call_id}`, f.tool_call_id));
  }
  el('finding-execution').value = f.tool_call_id;
  for (const field of ['title', 'severity', 'evidence', 'impact', 'remediation']) el('finding-' + field).value = f[field];
  el('finding-review').value = f.review_status;
  el('finding-title').focus();
}
el('finding-execution').addEventListener('change', async () => {
  if (!el('finding-execution').value) return;
  try {
    const c = await apiJSON(`/api/executions/${el('finding-execution').value}`);
    el('finding-id').value = '';
    el('finding-title').value = `Observação de ${c.tool}`;
    el('finding-evidence').value = c.result.slice(0, 20000);
    el('finding-severity').value = 'info';
    el('finding-review').value = 'pending';
    el('finding-impact').value = ''; el('finding-remediation').value = '';
  } catch (error) { toast(error.message); }
});
el('evidence-download').addEventListener('click', async () => {
  if (!el('finding-execution').value) return;
  try {
    const c = await apiJSON(`/api/executions/${el('finding-execution').value}`);
    await downloadText(c.result, `projeto-${activeProject}-execucao-${c.id}.txt`);
  } catch (error) { toast(error.message); }
});
el('finding-form').addEventListener('submit', async e => {
  e.preventDefault();
  const body = {tool_call_id: Number(el('finding-execution').value), review_status: el('finding-review').value};
  for (const field of ['title', 'severity', 'evidence', 'impact', 'remediation']) body[field] = el('finding-' + field).value;
  const id = el('finding-id').value;
  try {
    await apiJSON('/api/findings' + (id ? '/' + id : ''), {method: id ? 'PUT' : 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
    toast('Achado salvo.'); el('finding-form').reset(); el('finding-id').value = ''; await loadFindings();
  } catch (error) { toast(error.message); }
});
el('finding-new').addEventListener('click', () => { el('finding-form').reset(); el('finding-id').value = ''; });
el('refresh-findings').addEventListener('click', loadFindings);
