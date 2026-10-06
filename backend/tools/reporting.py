"""Exporta o relatório de pentest pra arquivo (Markdown ou HTML standalone).

Reusa `services.report.generate_pentest_report()` (que compila tool_calls +
alerts do audit trail). Escreve num diretório de relatórios do projeto e
devolve o caminho. risk=info, sem confirmação — grava arquivo local, não
toca alvo. PDF exigiria dependência extra (reportlab/weasyprint) que o
projeto não tem; HTML standalone abre no navegador e imprime pra PDF.
"""

import html
import re

from datetime import datetime, timezone
from pathlib import Path

from config.settings import settings
from database.context import project_id
from services.report import generate_pentest_report

try:
    from fpdf import FPDF
except ImportError:  # fpdf2 opcional — sem ele, 'pdf' cai num aviso claro
    FPDF = None

_FORMATS = ("md", "html", "pdf")


def _safe_slug(name: str) -> str:
    """Nome de arquivo seguro (sem path traversal, sem espaço)."""
    slug = re.sub(r"[^A-Za-z0-9_.-]", "-", name.strip())
    slug = slug.strip("-.") or "relatorio"
    return slug[:60]


def _markdown_to_html(md: str) -> str:
    """Wrapper HTML mínimo (sem lib de markdown): mantém o markdown legível
    dentro de <pre> monoespaçado, pronto pra abrir e imprimir em PDF."""
    body = html.escape(md)
    return (
        "<!doctype html><html lang=pt-BR><head><meta charset=utf-8>"
        "<title>Relatório de Pentest</title>"
        "<style>body{font:14px/1.5 system-ui,sans-serif;max-width:60rem;"
        "margin:2rem auto;padding:0 1rem;color:#1a1a1a}"
        "pre{white-space:pre-wrap;word-wrap:break-word}</style></head>"
        f"<body><pre>{body}</pre></body></html>"
    )


def _markdown_to_pdf(md: str, path: Path) -> None:
    """Renderiza o markdown como PDF simples (texto monoespaçado). Precisa
    do fpdf2 (pip install fpdf2) — o chamador checa FPDF antes."""
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Courier", size=9)
    # fpdf2 core usa latin-1; troca o que não couber pra não estourar.
    for line in md.splitlines() or [""]:
        safe = line.encode("latin-1", "replace").decode("latin-1")
        pdf.multi_cell(0, 4, safe or " ", wrapmode="CHAR",
                       new_x="LMARGIN", new_y="NEXT")
    pdf.output(str(path))


async def tool_export_report(args: dict) -> str:
    """Gera o relatório de pentest e grava em arquivo (md padrão, html ou pdf)."""
    fmt = str(args.get("format") or "md").strip().lower()
    if fmt not in _FORMATS:
        return f"formato inválido: {fmt!r}. Use 'md' ou 'html'."
    md = generate_pentest_report()
    out_dir = Path(settings.reports_dir) / f"project-{project_id.get()}"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = _safe_slug(str(args.get("name") or f"pentest-{stamp}"))
    path = out_dir / f"{base}.{fmt}"
    if fmt == "pdf":
        if FPDF is None:
            return ("erro: exportar PDF precisa do fpdf2 (pip install fpdf2). "
                    "Use format='html' e imprima pra PDF no navegador enquanto isso.")
        _markdown_to_pdf(md, path)
    else:
        content = md if fmt == "md" else _markdown_to_html(md)
        path.write_text(content, encoding="utf-8")
    hint = {
        "md": "Use format='html' ou 'pdf' pra versão imprimível.",
        "html": "Abra o .html no navegador e imprima pra PDF se precisar.",
        "pdf": "PDF pronto pra entregar.",
    }[fmt]
    return f"Relatório exportado: {path}\n({len(md.splitlines())} linhas, formato {fmt}). " + hint


def register(registry) -> None:
    registry.register(
        "export_report",
        "Gera e grava o relatório de pentest em arquivo (informe 'format' "
        "'md', 'html' ou 'pdf', e 'name' opcional). Compila as ações de "
        "auditoria e alertas registrados.",
        tool_export_report,
        risk="info", requires_confirmation=False,
        required_args=(), target_arg=None, category="relatório",
    )
