"""Ferramentas de engenharia reversa (binário/malware/firmware): tipo de
arquivo, strings, símbolos, cabeçalho ELF, disassembly, análise
automática (radare2, se instalado) e triagem por regra YARA.

Diferente de tools/pentest.py, estas não tocam nenhum alvo remoto — só
inspecionam um arquivo local que o operador aponta (amostra de malware,
binário baixado, firmware extraído). Por isso não exigem confirmação
humana: mesma categoria de risco das ferramentas de leitura de sistema.

Tudo aqui é análise ESTÁTICA — lê/parseia bytes do arquivo, nunca executa
a amostra (inclusive YARA: casamento de padrão, não detonação)."""

import asyncio
from services.processes import communicate

from pathlib import Path

from security.sanitize import sanitize_text

TIMEOUT_SECONDS = 60
MAX_OUTPUT_CHARS = 8000
_MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB — evita travar objdump/strings num arquivo gigante


async def _run(argv: list[str], timeout: int = TIMEOUT_SECONDS) -> str:
    """Executa subprocess sem shell; devolve stdout sanitizado (ou erro)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        return f"erro: ferramenta não encontrada ({exc.filename})"
    try:
        out, err = await communicate(proc, timeout)
    except asyncio.TimeoutError:
        return f"erro: comando excedeu {timeout}s e foi encerrado."
    stdout = sanitize_text(out.decode(errors="replace"))
    stderr = sanitize_text(err.decode(errors="replace"))
    if type(proc.returncode) is int and proc.returncode != 0:
        return f"erro: comando terminou com código {proc.returncode}.\n{stdout[:MAX_OUTPUT_CHARS]}\n{stderr[:400]}"
    if not stdout and stderr:
        return f"erro: {stderr.strip()[:400]}"
    if len(stdout) > MAX_OUTPUT_CHARS:
        stdout = stdout[:MAX_OUTPUT_CHARS] + "\n...[truncado]"
    return stdout


def _validate_path(raw: str) -> tuple[Path | None, str | None]:
    """Valida caminho de arquivo local. Devolve (Path, None) ou (None, erro)."""
    raw = raw.strip()
    if not raw:
        return None, "Uso: informe 'path' (caminho do arquivo — binário, firmware, amostra...)."
    path = Path(raw).expanduser()
    if not path.is_file():
        return None, f"arquivo não encontrado: {raw!r}"
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"erro ao ler {raw!r}: {exc}"
    if size > _MAX_FILE_SIZE:
        return None, f"arquivo grande demais ({size} bytes; limite {_MAX_FILE_SIZE})."
    return path, None


async def tool_re_file_info(args: dict) -> str:
    """Identifica tipo de arquivo (formato, arquitetura, se é ELF/PE/Mach-O...)."""
    path, err = _validate_path(str(args.get("path") or ""))
    if err:
        return err
    out = await _run(["file", "-b", str(path)])
    return out or f"file {path}: sem saída."


def _clamp_min_len(value) -> int:
    try:
        return max(4, min(int(value), 32))
    except (TypeError, ValueError):
        return 6


async def tool_re_strings(args: dict) -> str:
    """Extrai strings imprimíveis do arquivo ('min_len' opcional, 'filter' opcional
    pra restringir às linhas que contêm um termo — útil pra achar URL, chave, mensagem)."""
    path, err = _validate_path(str(args.get("path") or ""))
    if err:
        return err
    min_len = _clamp_min_len(args.get("min_len", 6))
    out = await _run(["strings", "-n", str(min_len), str(path)])
    if out.startswith("erro"):
        return out
    term = str(args.get("filter") or "").strip().lower()
    if term:
        matched = [line for line in out.splitlines() if term in line.lower()]
        return "\n".join(matched) or f"(nenhuma string casando com {term!r})"
    return out or "(nenhuma string encontrada)"


async def tool_re_symbols(args: dict) -> str:
    """Lista símbolos do binário (tabela completa via nm; se estiver strip —
    'no symbols' — cai pra readelf, que ainda lê a tabela dinâmica)."""
    path, err = _validate_path(str(args.get("path") or ""))
    if err:
        return err
    out = await _run(["nm", "-C", str(path)], timeout=30)
    if out.startswith("erro") or "no symbols" in out.lower():
        fallback = await _run(["readelf", "-sW", str(path)], timeout=30)
        return fallback or out
    return out


async def tool_re_headers(args: dict) -> str:
    """Cabeçalho ELF + seções (arquitetura, entrypoint, seções, flags)."""
    path, err = _validate_path(str(args.get("path") or ""))
    if err:
        return err
    out = await _run(["readelf", "-hS", str(path)], timeout=30)
    return out or f"readelf {path}: sem saída."


async def tool_re_disasm(args: dict) -> str:
    """Disassembly (objdump, sintaxe Intel). 'symbol' opcional restringe a uma função."""
    path, err = _validate_path(str(args.get("path") or ""))
    if err:
        return err
    argv = ["objdump", "-d", "-M", "intel", "--no-show-raw-insn"]
    symbol = str(args.get("symbol") or "").strip()
    if symbol:
        argv.append(f"--disassemble={symbol}")
    argv.append(str(path))
    out = await _run(argv, timeout=60)
    return out or f"objdump {path}: sem saída."


async def tool_re_analyze(args: dict) -> str:
    """Análise automática com radare2 (aaa) + lista de funções detectadas (afl).
    Requer radare2 instalado (AUR/`pacman -S radare2` no Arch)."""
    path, err = _validate_path(str(args.get("path") or ""))
    if err:
        return err
    out = await _run(["r2", "-q", "-c", "aaa;afl", str(path)], timeout=90)
    return out or f"r2 {path}: sem saída."


# Locais comuns de um ruleset YARA "index" (arquivo raiz que puxa o resto
# via 'include') — pacote yara-rules do AUR ou clone manual do repositório
# github.com/Yara-Rules/rules costumam cair num desses.
_YARA_RULES_DEFAULTS = (
    "/usr/share/yara-rules/index.yar",
    "/usr/share/yara/index.yar",
    "/opt/yara-rules/index.yar",
    str(Path.home() / "yara-rules" / "index.yar"),
)


async def tool_re_yara_scan(args: dict) -> str:
    """Casa regras YARA contra o arquivo (triagem de malware por padrão/
    assinatura — nunca executa a amostra). 'rules' opcional: caminho de um
    arquivo .yar/.yara (pode usar 'include' pra puxar mais regras); sem
    isso, tenta um ruleset padrão do sistema. Requer yara instalado
    (AUR/`pacman -S yara` no Arch)."""
    path, err = _validate_path(str(args.get("path") or ""))
    if err:
        return err
    rules = str(args.get("rules") or "").strip()
    if not rules:
        rules = next((r for r in _YARA_RULES_DEFAULTS if Path(r).is_file()), "")
    if not rules:
        return ("Uso: informe 'rules' (caminho de um arquivo .yar/.yara) — nenhum "
                "ruleset padrão encontrado no sistema.")
    if not Path(rules).is_file():
        return f"arquivo de regras não encontrado: {rules!r}"
    out = await _run(["yara", "-s", "-w", rules, str(path)], timeout=60)
    if out.startswith("erro"):
        return out
    return out or f"YARA: nenhuma regra casou com {path.name}."


def register(registry) -> None:
    for name, desc, fn in (
        ("re_file_info", "Identifica tipo/arquitetura de um arquivo local (informe 'path').", tool_re_file_info),
        ("re_strings", "Extrai strings imprimíveis de um arquivo local (informe 'path'; 'min_len' e 'filter' opcionais).", tool_re_strings),
        ("re_symbols", "Lista símbolos (funções, variáveis) de um binário local (informe 'path').", tool_re_symbols),
        ("re_headers", "Mostra cabeçalho ELF + seções de um binário local (informe 'path').", tool_re_headers),
        ("re_disasm", "Disassembly (objdump, Intel) de um binário local (informe 'path'; 'symbol' opcional).", tool_re_disasm),
        ("re_analyze", "Análise automática radare2 (funções detectadas) de um binário local (informe 'path'; requer radare2 instalado).", tool_re_analyze),
        ("re_yara_scan", "Triagem de malware por regra YARA num arquivo local (informe 'path'; 'rules' opcional, requer yara instalado).", tool_re_yara_scan),
    ):
        # Leitura local de arquivo apontado pelo operador — não toca alvo remoto,
        # mesma categoria de risco das tools de leitura de sistema: sem confirmação.
        registry.register(name, desc, fn, risk="info", requires_confirmation=False,
                          category="engenharia-reversa")
