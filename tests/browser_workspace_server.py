"""Isolated backend for browser checks; never uses the operator database/LLM."""
import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from config.settings import settings
from database import db
from tools.registry import ToolRegistry

sandbox = tempfile.TemporaryDirectory(prefix='cyber-browser-')
db.DB_PATH = Path(sandbox.name) / 'test.db'
db.DATA_DIR = Path(sandbox.name)
db.LOG_DIR = Path(sandbox.name) / 'logs'
settings.watcher_enabled = False
settings.port = 8768
settings.api_token = ''
settings.safe_mode = 'assisted'
db.init_db()
db.log_tool_call('http_headers', {'url':'http://127.0.0.1'}, 'HTTP 200\nServer: VulnLab/1.0\nCSP: ausente')

from api import main
class Provider:
    async def complete(self, messages, **kwargs):
        if kwargs.get('json_mode'):
            return '{"tool":"slow_probe","args":{}}'
        return 'Leitura de teste local.'
    async def stream_chat(self, messages, **kwargs):
        yield 'Leitura de teste local.'
    async def aclose(self): pass

async def slow_probe(args):
    from tools.pentest import _run
    return await _run([sys.executable, '-c', 'import time; time.sleep(60)'])
registry = ToolRegistry()
async def info(args): return 'Teste isolado'
registry.register('memory_info', 'memória', info)
registry.register('disk_info', 'disco', info)
registry.register('slow_probe', 'Leitura de teste local', slow_probe, category='rede', requires_confirmation=True)
main._provider = Provider()
main._research_provider = main._provider
main._registry = registry
if __name__ == '__main__':
    import uvicorn
    try: uvicorn.run(main.app, host='127.0.0.1', port=settings.port)
    finally: sandbox.cleanup()
