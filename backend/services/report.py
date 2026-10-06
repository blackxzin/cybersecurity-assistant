"""Pentest report generator: compiles recent audit actions (tool_calls) and
alerts into a single Markdown report — a hand-off/archive artifact per
engagement, built from the same audit trail already persisted by
ChatService.stream() (see backend/services/chat.py)."""

from datetime import datetime, timezone

from database import db as database
from database.context import project_id

# Ferramentas relevantes pra um relatório de pentest — exclui leituras de
# sistema (memory_info, disk_info...) que não são "achados" de engagement.
PENTEST_TOOLS = (
    "nmap_scan", "sqlmap_scan", "hydra_bruteforce", "gobuster_scan",
    "nikto_scan", "packet_capture", "cpf_osint",
    "nuclei_scan", "ffuf_scan", "wafw00f_scan",
    "smb_enum", "enum4linux_scan", "subfinder_scan", "shodan_host",
    "msf_module", "searchsploit_lookup",
    "burp_search_history", "burp_find_vulnerabilities", "burp_proxy_history",
    "http_headers", "tls_inspect", "dns_lookup", "recon_pipeline", "web_recon_chain",
)

_SNIPPET_LINES = 20


def generate_pentest_report(limit: int = 200) -> str:
    """Builds the report as a Markdown string, most recent action last
    within each tool's section (chronological reading order)."""
    placeholders = ",".join("?" * len(PENTEST_TOOLS))
    with database.db() as conn:
        rows = conn.execute(
            f"SELECT tool, result, status, created_at FROM tool_calls "  # nosec B608
            f"WHERE tool IN ({placeholders}) AND project_id=? ORDER BY id DESC LIMIT ?",
            (*PENTEST_TOOLS, project_id.get(), limit),
        ).fetchall()
        alerts = conn.execute(
            "SELECT severity, title, description, created_at FROM alerts WHERE project_id=? ORDER BY id DESC LIMIT 50", (project_id.get(),)
        ).fetchall()
        project = conn.execute("SELECT name FROM projects WHERE id=?", (project_id.get(),)).fetchone()
        findings = conn.execute("SELECT * FROM findings WHERE project_id=? ORDER BY id", (project_id.get(),)).fetchall()
    calls = list(reversed(rows))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = ["# Relatório de Pentest", "", f"Gerado em {now}.", "", "## Sumário"]
    lines.append(f"- Projeto: {project['name']} (#{project_id.get()})")
    lines.append(f"- {len(findings)} achado(s) em revisão/registro")
    lines.append(f"- {len(calls)} ação(ões) de auditoria registrada(s)")
    lines.append(f"- {len(alerts)} alerta(s) no histórico")
    lines.append("")

    lines.extend(["## Achados revisáveis", "", "Execução bem-sucedida não confirma vulnerabilidade. O estado abaixo é a revisão do operador.", ""])
    for finding in findings:
        lines.extend([
            f"### #{finding['id']} — {finding['title']}",
            f"- Gravidade: {finding['severity']}",
            f"- Revisão: {finding['review_status']}",
            f"- Execução de origem: #{finding['tool_call_id']}",
            f"- Impacto: {finding['impact'] or 'A avaliar'}",
            f"- Correção sugerida: {finding['remediation'] or 'A definir'}",
            "", "Evidência:", "",
            *["> " + line for line in finding['evidence'].splitlines()], "",
        ])
    if not calls:
        lines.append("Nenhuma ação de pentest registrada ainda.")
    else:
        by_tool: dict[str, list] = {}
        for row in calls:
            by_tool.setdefault(row["tool"], []).append(row)
        lines.append("## Histórico de execuções por ferramenta")
        for tool in sorted(by_tool):
            tool_rows = by_tool[tool]
            lines.append(f"### {tool} ({len(tool_rows)} execução(ões))")
            for row in tool_rows:
                mark = "✅" if row["status"] == "ok" else "⚠️"
                lines.append(f"- {mark} {row['created_at']}")
                snippet = (row["result"] or "").strip()
                if snippet:
                    body_lines = snippet.splitlines()[:_SNIPPET_LINES]
                    lines.append("  ```")
                    lines.extend(f"  {line}" for line in body_lines)
                    if len(snippet.splitlines()) > _SNIPPET_LINES:
                        lines.append("  ...[truncado]")
                    lines.append("  ```")
            lines.append("")

    if alerts:
        lines.append("## Alertas")
        for a in alerts:
            lines.append(
                f"- **[{a['severity'].upper()}]** {a['title']} — {a['description']} ({a['created_at']})"
            )
        lines.append("")

    return "\n".join(lines)
