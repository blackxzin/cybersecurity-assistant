"""Testes de tools/reporting.py (export_report). Escreve num tmp_path
isolado; DB isolado pra gerar o relatório vazio sem tocar o real."""

from pathlib import Path

import pytest

from database import db
from tools import reporting
from tools.reporting import _safe_slug, tool_export_report


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    monkeypatch.setattr(reporting.settings, "reports_dir", str(tmp_path / "reports"))


@pytest.mark.parametrize("raw,expected_prefix", [
    ("../etc/passwd", "etc-passwd"),
    ("meu relatório!", "meu-relat"),
    ("", "relatorio"),
])
def test_safe_slug(raw, expected_prefix):
    assert _safe_slug(raw).startswith(expected_prefix) or _safe_slug(raw) == "relatorio"


@pytest.mark.asyncio
async def test_export_markdown(tmp_path):
    out = await tool_export_report({"format": "md", "name": "teste"})
    assert "Relatório exportado" in out
    files = list((tmp_path / "reports" / "project-1").glob("*.md"))
    assert len(files) == 1
    assert files[0].read_text().startswith("# Relatório de Pentest")


@pytest.mark.asyncio
async def test_export_html(tmp_path):
    out = await tool_export_report({"format": "html", "name": "teste"})
    files = list((tmp_path / "reports" / "project-1").glob("*.html"))
    assert len(files) == 1
    assert "<!doctype html>" in files[0].read_text()


@pytest.mark.asyncio
async def test_export_bad_format():
    out = await tool_export_report({"format": "docx"})
    assert "formato inválido" in out.lower()


def test_no_path_traversal_in_name():
    assert "/" not in _safe_slug("../../evil")
    assert ".." not in _safe_slug("../../evil")


@pytest.mark.asyncio
async def test_export_pdf(tmp_path):
    out = await tool_export_report({"format": "pdf", "name": "teste"})
    if "fpdf2" in out:  # ambiente sem fpdf2 — aviso claro, não crash
        assert "erro" in out.lower()
        return
    files = list((tmp_path / "reports" / "project-1").glob("*.pdf"))
    assert len(files) == 1
    assert files[0].read_bytes().startswith(b"%PDF")
