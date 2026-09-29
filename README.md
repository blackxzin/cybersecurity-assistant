# 🛡 Cybersecurity AI

> **⚠️ Em desenvolvimento ativo** — código muda a cada sessão. Fluxos principais funcionam (chat, ferramentas, voz), mas não é estável para uso em produção.

Assistente pessoal de **pentest/red-team** para Linux, com IA local (Ollama),
agentes especializados, ferramentas ofensivas **com confirmação humana**,
terminal controlado, dashboard e uma **personagem animada** como interface visual.

<p align="center">
  <a href="https://blackxzin.github.io/cybersecurity-assistant/"><strong>▶ Ver demo ao vivo →</strong></a>
</p>

<p align="center">
  <img alt="status" src="https://img.shields.io/badge/status-em%20desenvolvimento-orange?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.14-3776ab?style=flat-square&logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white">
  <img alt="IA local" src="https://img.shields.io/badge/IA-local%20(Ollama)-000000?style=flat-square&logo=ollama&logoColor=white">
  <img alt="Ferramentas" src="https://img.shields.io/badge/ferramentas-53-2E5BFF?style=flat-square">
  <img alt="Testes" src="https://img.shields.io/badge/testes-487%20passing-0B7A48?style=flat-square">
</p>

> A **demo** é interativa: um terminal que roda o Cyber com saídas de recon **reais**
> (capturadas contra `example.com` e `scanme.nmap.org`), mostra o gate de confirmação
> nas ferramentas ofensivas e lista o arsenal completo. É uma página estática única
> (`docs/index.html`) — nada executa de verdade no navegador.

---

## O que faz hoje

- **Chat com IA local** (Ollama, `DeepHat-V1-7B`, fine-tune de segurança) com streaming SSE.
- **Agentes especializados** (system / network / security / learning) que decidem qual ferramenta usar e explicam o resultado em português.
- **Ferramentas de auditoria ativa** que **exigem aprovação humana** antes de executar:
  - `nmap_scan` — escaneia portas/serviços de um host (`nmap -sT -sV`, não precisa de root);
  - `sqlmap_scan` — testa injeção SQL numa URL (`sqlmap --batch`);
  - `hydra_bruteforce` — testa credenciais contra um serviço (ssh/ftp/http/mysql/...), para no primeiro par válido (porta customizada opcional via `port`);
  - `gobuster_scan` — enumera diretórios/arquivos de uma URL;
  - `nikto_scan` — varre vulnerabilidades web conhecidas numa URL;
  - `nuclei_scan` — scanner de vulnerabilidades por **template** (nuclei/ProjectDiscovery): roda milhares de checagens de CVE/misconfig/exposure numa URL, com rate-limit e filtro de `severity` (padrão medium+) e `tags` opcionais (ex: `cve,exposure`); saída ordenada por gravidade;
  - `ffuf_scan` — fuzzing rápido de diretórios/arquivos/parâmetros (alternativa ao gobuster, bem mais veloz): aceita o marcador `FUZZ` na URL (anexa no fim se faltar), `wordlist` e `match_codes` opcionais;
  - `wafw00f_scan` — detecta qual WAF/firewall de aplicação está na frente de uma URL (Cloudflare, Akamai, etc.), útil antes de escolher técnica de evasão;
  - `web_recon_chain` — recon web encadeado numa URL (fingerprint de headers **+** `nuclei`) numa tacada só, na ordem certa;
  - `recon_pipeline` — pipeline completo num **host**: `nmap` → detecta serviços web abertos → `http_headers` + `nuclei` em cada um, numa tacada só (fluxo clássico descobrir→provar→escanear);
  - `smb_enum` — lista shares SMB de um host via `smbclient` (sessão nula por padrão; `username`/`password` opcionais);
  - `enum4linux_scan` — enumeração SMB/Samba completa (usuários, shares, políticas) via `enum4linux`;
  - `msf_module` — roda um módulo do **Metasploit** contra um alvo (`module`, `rhosts`, `options` opcionais) de forma não-interativa (`msfconsole -q -x`), com módulo/opções validados contra injeção;
  - `searchsploit_lookup` — busca exploit conhecido offline (exploit-db local) por serviço/versão
    (`pacman -S exploitdb` no Arch); **não pede confirmação** (busca local, não toca o alvo) e
    roda automático depois de todo `nmap_scan` — cada serviço com versão detectada vira uma
    busca, resultado anexado direto na resposta do scan (fecha o ciclo achar→explorar);
  - `packet_capture` — captura tráfego (`dumpcap`) e resume com `tshark`;
  - `cpf_osint` — mapeia contas associadas a um CPF (usa o [cpfFinder](https://github.com/p1ngul1n0/cpfFinder));
  - `email_osint` — descobre em quais sites um email está cadastrado (via [holehe](https://github.com/megadose/holehe));
  - `username_osint` — busca um username em centenas de redes sociais/plataformas (via [sherlock](https://github.com/sherlock-project/sherlock));
  - `burp_proxy_history` / `burp_send_request` — lê histórico do proxy e reenvia requisições via a ponte com o Burp Suite.
- **OSINT passivo** (sem confirmação — só consulta serviço público, nunca toca o alvo):
  - `domain_whois` — WHOIS de domínio (registrante, datas, nameservers), via `python-whois`;
  - `subdomain_enum` — enumera subdomínios por certificate transparency ([crt.sh](https://crt.sh),
    às vezes instável/rate-limited — falha vira mensagem de erro clara, não trava o chat).
  - `subfinder_scan` — enumera subdomínios via [subfinder](https://github.com/projectdiscovery/subfinder) (dezenas de fontes públicas, mais completo que só crt.sh); passivo, não toca o alvo;
  - `shodan_host` — consulta o [Shodan](https://shodan.io) sobre um IP (portas, serviços, CVEs já indexados) sem tocar o alvo; precisa de `SHODAN_API_KEY` no `.env`.
- **Recon web** (sem binário externo — httpx/ssl já são dependências, então roda em qualquer
  máquina; risco `info`):
  - `http_headers` — um GET no alvo e laudo de banners de tecnologia/versão, headers de
    segurança faltando (HSTS/CSP/X-Frame/nosniff/Referrer/Permissions) e flags de cookie
    (Secure/HttpOnly/SameSite);
  - `tls_inspect` — abre handshake TLS e lê o certificado (issuer/validade/SANs/fingerprint
    SHA256) + protocolo/cipher negociados, sinalizando expirado/self-signed/verificação falha;
  - `dns_lookup` — resolve A/AAAA/MX/TXT/NS/CNAME/SOA via DNS-over-HTTPS (não fala direto com a
    infra do alvo).
- **Cripto offline** (puro Python, nunca toca rede/binário; risco `info`):
  - `jwt_decode` — decodifica header/payload de um JWT sem verificar assinatura e aponta falhas
    (`alg=none`, HS/RS key-confusion, `exp` vencido);
  - `hash_identify` — identifica o tipo de um hash por formato/comprimento e sugere o modo do
    `hashcat` (`-m`);
  - `encode_decode` — base64/hex/url/rot13 encode e decode.
- **Engenharia reversa** de binário/malware/firmware local (sem confirmação — arquivo local
  apontado pelo operador, não toca alvo remoto): `re_file_info` (tipo/arquitetura via `file`),
  `re_strings` (strings impressas, com filtro), `re_symbols` (`nm`, cai pra `readelf` se strip),
  `re_headers` (cabeçalho ELF + seções), `re_disasm` (disassembly Intel via `objdump`, função
  específica opcional), `re_analyze` (análise automática + funções via radare2, se instalado —
  `pacman -S radare2` no Arch), `re_yara_scan` (triagem de malware por regra YARA — casamento de
  padrão/assinatura, nunca executa a amostra; requer `pacman -S yara`, repo oficial `extra`; sem
  `rules` explícito tenta um índice padrão do sistema, ex: `/usr/share/yara-rules/index.yar`).
- **Ferramentas de leitura** (sem confirmação): interfaces, rotas, DNS, portas locais, serviços systemd, conectividade, logs de segurança, CPU/RAM/disco/processos.
- **Voz**: botão de mic na UI web e PTT no overlay desktop (`Ctrl+Shift+M`) — transcrição local (faster-whisper) e fala local (espeak-ng).
- **Overlay desktop**: personagem animada em janela transparente (Electron + Hyprland), estados
  listening/thinking/talking/alert — sincronizados tanto com a voz quanto com alertas reais do
  watcher (porta nova, disco cheio, diff de scan): a personagem reage sozinha, sem precisar
  interagir por voz.
- **Logging e auditoria**: tudo sanitizado e registrado em `logs/security.log` + SQLite.
- **Watcher em segundo plano** (a cada `WATCHER_INTERVAL_SECONDS`, padrão 5min):
  - diff de portas locais escutando (`ss -tulnp`) — porta nova = alerta;
  - diff de portas abertas entre scans `nmap_scan` do mesmo host — porta nova = alerta + aviso na resposta do chat;
  - disco acima de `DISK_ALERT_PERCENT`% = alerta (sem repetir enquanto continuar acima);
  - purga automática de resultados `cpf_osint` com mais de `OSINT_RETENTION_DAYS` dias (LGPD);
  - alerta grave dispara notificação desktop (`notify-send`).
- **Dashboard** com CPU/memória/disco em tempo real (antes fixo em "—").
- **Providers de IA**: `ollama` (padrão), `nvidia` (visão), `openai`/`lmstudio`/`openrouter` (API OpenAI-compatible — `openrouter` dá acesso a várias IAs de vários fabricantes com uma chave só), `anthropic` (Claude, API nativa).
- **Research provider (opcional)**: liga um 2° modelo só pra pesquisa/planejamento — o
  Planner (monta o plano de pentest) e o Validator (avalia o resultado / o que falta)
  passam a usar ele em vez do DeepHat. O DeepHat (`AI_PROVIDER`) continua sendo quem decide
  e executa as ferramentas de verdade. Configurável de duas formas: `RESEARCH_PROVIDER`/
  `RESEARCH_BASE_URL`/`RESEARCH_MODEL`/`RESEARCH_API_KEY` no `.env`, **ou** direto pela UI
  (aba "⚙️ Configurações" → "Research provider" — provider/host/modelo/chave, `GET/POST
  /api/provider/research`) sem precisar reiniciar o servidor; a config da UI tem prioridade
  sobre o `.env` quando as duas existem. Vazio (padrão) = um modelo só pra tudo, como sempre foi.
- **Memória longa**: ferramentas `remember`/`recall` guardam fatos em SQLite entre sessões
  (`GET/POST /api/memory`, `DELETE /api/memory/{id}`); os fatos mais recentes são injetados
  automaticamente no contexto do chat, sem precisar pedir explicitamente. Tem aba própria
  na UI ("🧠 Memória") pra ver, adicionar e esquecer fatos manualmente.
- **Modo Learning**: perguntas de "explica X" caem num agente que estrutura a resposta em
  Conceito/Exemplo prático/Cuidado/Pergunta pra fixar e registra o progresso por conceito
  em SQLite (`GET /api/learning/progress`, também visível na aba "🧠 Memória") —
  reperguntar o mesmo conceito muda o tom da explicação.
- **Hardening de API**: `API_TOKEN` opcional (header `X-API-Token`, desativado por padrão —
  só relevante se o servidor sair de 127.0.0.1) e rate limit por IP em toda rota `/api/*`
  (`RATE_LIMIT_PER_MINUTE`, padrão 120/min).
- **Escopo autorizado (opt-in)**: painel "⚙️ Configurações" (`GET/POST /api/scope`) declara
  os alvos autorizados do engagement (IP, CIDR ou domínio). Vazio (padrão) = sem restrição,
  mesmo comportamento de sempre. Assim que um escopo é definido, `nmap_scan`/`sqlmap_scan`/
  `hydra_bruteforce`/`gobuster_scan`/`nikto_scan` recusam alvo fora dele — antes mesmo de
  pedir confirmação humana, e re-checado de novo no momento da aprovação (o escopo pode
  ter mudado entre pedir e aprovar).
- **Relatório de pentest**: botão "📄 Baixar relatório" na aba "🛡 Segurança" (`GET /api/report`) — e a ferramenta `export_report` grava o relatório em arquivo (`md`, `html` imprimível ou **`pdf`** via fpdf2) em `reports/`
  compila as últimas execuções de ferramentas ofensivas + alertas do watcher num Markdown
  pronto pra arquivar/entregar.

---

## Arquitetura (resumo)

```
backend/
├── api/          FastAPI: /api/chat (SSE), /api/system, /api/terminal, /api/tools,
│                 /api/actions/{id}/approve|deny, /api/audio/*, /api/vision,
│                 /api/scope (GET/POST), /api/report…
├── ai/
│   └── providers/  interface LLMProvider (ollama hoje; openai/anthropic/lmstudio depois)
├── agents/       Orchestrator + especialistas (system, network, security, learning)
├── tools/        ferramentas de leitura (system, network, diagnostics)
│   │             + pentest (nmap_scan, packet_capture, cpf_osint) — exigem confirmação
│   ├── confirm.py   fila de aprovações humanas (pending → approved/denied/expired)
│   ├── terminal/    executor controlado (allowlist/denylist, sem shell)
├── security/     Safety Layer (classificação) + sanitização de segredos + logging
├── services/     ChatService (orquestração), audio (STT/TTS), screen (visão)
└── database/     SQLite (stdlib), esquema pronto p/ migrar a PostgreSQL
frontend/         HTML/CSS/JS puro servido pelo backend (sem build)
overlay/          personagem animada (Electron) — integração com o chat por voz
```

### Fluxo de uma mensagem

```
input → sanitize → Orchestrator (classifica intenção)
     → decide ferramenta (+ args via JSON heurístico)
     → se a ferramenta é de risco moderado → PEDE CONFIRMAÇÃO humana
          ├─ aprovar → executa → LLM explica o resultado real
          └─ negar   → nada roda (tudo fica registrado)
     → se é leitura segura → executa → LLM explica
     → stream SSE p/ o chat (com campo "pending" quando há ação a aprovar)
     → persistência SQLite
```

### Confirmação humana — o princípio mais importante

Nenhuma ferramenta de auditoria ativa roda sem o seu OK:

1. Você pede algo como *"escaneie 10.0.0.5"*;
2. a IA decide a ferramenta e abre um **modal Aprovar/Negar** na UI;
3. **Aprovar** → executa e a IA interpreta o resultado · **Negar** → nada executa;
4. a ação expira em 5 minutos se ninguém decidir.

O Safety Layer ainda aplica em paralelo:
- **denylist** (rm, dd, mkfs, shutdown…) → sempre bloqueados (protege a própria máquina, não é sobre ofensiva);
- ferramentas ofensivas (nmap, sqlmap, hydra, gobuster, nikto, masscan, metasploit, hashcat, john…) não são bloqueadas por nome — passam por confirmação humana como qualquer outra ação de risco moderado;
- **nunca** usa shell (argv direto) → sem injeção;
- timeout rígido, saída redigida (sem segredos), tudo registrado.

`SAFE_MODE`: `safe` (somente leitura) | `assisted` (leitura + confirmação, **padrão**) |
`advanced` (**pentest automático** — ferramentas que normalmente parariam pra aprovação
humana, incluindo dentro de um plano multi-passo do Planner, rodam direto, sem clicar
Aprovar em cada uma. Fica registrado em log de qualquer forma. Use só se você mesmo é o
único operando essa instância, contra alvo próprio/autorizado).

---

## Instalação

Pré-requisitos: **Python 3.12+**, **Ollama** (`ollama pull hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q5_K_M`),
e (opcional, para captura) estar no grupo `wireshark`.

```bash
./install.sh     # venv + deps + verifica modelo + DB
./start.sh       # sobe o servidor → http://127.0.0.1:8000
./run.sh         # servidor + personagem no desktop (overlay)
./overlay.sh     # só a personagem + backend (voz PTT)
```

Configuração: copie `.env.example` para `.env` e ajuste.

### Extra — cpf_osint

O `cpf_osint` usa o [cpfFinder](https://github.com/p1ngul1n0/cpfFinder), esperado por
padrão em `~/cpfFinder` (script `cpfinder.py` + `data.json`; ajustável via
`CPF_FINDER_DIR` no `.env`). Se você for usar essa ferramenta, clone-o:

```bash
git clone https://github.com/p1ngul1n0/cpfFinder ~/cpfFinder
```

### Extra — Burp Suite (burp_proxy_history, burp_send_request)

A ponte fala com a extensão oficial **MCP Server** da PortSwigger via
[Model Context Protocol](https://modelcontextprotocol.io):

1. No Burp: **Extensions → BApp Store** → busque **"MCP Server"** → **Install**
   (ou baixe manualmente em
   [portswigger.net/bappstore](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
   e carregue via **Extensions → Add**).
2. Na aba **MCP** que aparece no Burp, marque **Enabled** (padrão:
   `127.0.0.1:9876`, ajustável via `BURP_MCP_URL` no `.env` se você mudar a porta).

A extensão mostra seu próprio dialog **Allow/Deny** no Burp para cada
requisição enviada e cada leitura de histórico — além da confirmação já
pedida pelo cyber-assitente, é uma segunda camada de aprovação.

> A antiga ponte Java própria (`burp-extension/cyber-bridge.jar`) foi
> descontinuada em favor do MCP Server oficial — o código fica em
> `burp-extension/` só de referência. Veja `burp-extension/README.md`.

### Extra — overlay desktop

```bash
cd overlay && npm install   # instala o Electron (uma vez)
./run.sh                    # ou ./overlay.sh
```

Atalhos do overlay: `Ctrl+Shift+M` = voz PTT · `Ctrl+Shift+V` = ela olha a tela ·
`Ctrl+Shift+X` = fechar.

---

## Testes

```bash
./.venv/bin/pip install -r requirements-dev.txt
./.venv/bin/python -m pytest              # validação de entrada + fluxo de confirmação
./.venv/bin/python tests/test_safety.py   # self-check do Safety Layer + Executor
./.venv/bin/python -m pytest --cov=backend --cov-report=term-missing  # cobertura
./.venv/bin/python -m pytest -m integration tests/test_*_integration.py  # binário real (opt-in)
```

Cobrem: allowlist, denylist, comandos desconhecidos, execução bloqueada,
sanitização de segredos, ferramentas confirmáveis (registro, risco,
validação de CPF/host/interface contra flag-injection), e o fluxo de
aprovação humana (`ConfirmationStore`: registrar, aprovar, negar, expirar).
CI roda a suíte + gate de cobertura mínima (80%, `--cov-fail-under=80`) a
cada push/PR (`.github/workflows/tests.yml`). `services/audio.py`,
`services/screen.py` e `backend/run.py` ficam abaixo da média (hardware
real — mic/TTS, captura de tela — e script de entrypoint, sem lógica pra
testar isoladamente); o resto do código fica bem acima dos 80%.

---

## Lab de treino (alvo local autorizado)

`lab/` traz uma app **deliberadamente vulnerável** (SQLi, XSS refletido, auth
fraca, rotas enumeráveis, banner de versão) que sobe **só em `127.0.0.1`** —
alvo real e legal pra exercitar `nmap`/`sqlmap`/`gobuster`/`nikto`/`hydra` e
fechar o ciclo achar→explorar→reportar sem tocar em terceiros. Só usa a
stdlib do Python (não instala nada). Detalhes e exemplos em [`lab/README.md`](lab/README.md).

```bash
./lab/run_lab.sh                 # sobe em http://127.0.0.1:8666
gobuster dir -u http://127.0.0.1:8666 -w lab/wordlist.txt
sqlmap -u "http://127.0.0.1:8666/login?user=admin&pass=x" --batch
```

O `127.0.0.1` já está no escopo autorizado, então dá pra pedir direto no chat:
*"faz um nmap no 127.0.0.1 porta 8666 e depois enumera diretórios"*.

---

## Roadmap

- **Fase 1** ✅ chat + ferramentas de leitura + Safety Layer + UI
- **Fase 2** ✅ logging estruturado + ferramentas de diagnóstico + voz PTT + **confirmação humana real** (nmap/captura/OSINT)
- **Fase 3** ✅ agentes completos (Planner/Executor/Validator) — pipeline pra pedidos complexos multi-passo
- **Fase 4** ✅ overlay sincronizado — estados ligados à voz **e** aos alertas reais do watcher (a personagem reage sozinha a porta nova/disco cheio/diff de scan, não só a interação por voz)
- **Fase 5** ✅ dashboard ao vivo (CPU/mem/disco reais) + watcher de alertas (portas/disco/diff de scan) + **modo Learning** (estruturado, com progresso por conceito, com aba própria na UI)
- **Fase 6** ✅ providers openai/lmstudio/anthropic + **memória longa** (`remember`/`recall`, injetada automaticamente no contexto, com aba própria na UI)
- **Fase 7** — integração ghunt: **bloqueada em decisão do usuário** (requer venv próprio com
  Python 3.13 por causa do `pillow<11` sem wheel pra 3.14, e `ghunt login` é um OAuth
  interativo no navegador do usuário contra a própria conta Google — não é algo que dá
  pra automatizar/decidir por ele). Sem isso resolvido manualmente, a integração fica pendente.
- **Hardening** ✅ `API_TOKEN` opcional + rate limit por IP em `/api/*`
- **Streaming real** ✅ o chat agora emite os tokens da resposta ao vivo (SSE) +
  eventos de progresso ("🔎 escolhendo ferramenta…" / "🔧 executando `X`…" /
  "🧭 montando plano…") nas fases lentas antes da síntese — antes o backend
  juntava a resposta inteira e só pintava no fim (tela em branco ~1min no CPU)
- **Fix de roteamento** ✅ pedidos de leitura simples (ex: "lista minhas
  interfaces") não caem mais por engano no pipeline caro de 3 chamadas ao LLM
- **Decisão de ferramenta mais rápida** ✅ o prompt de decisão manda só as
  ferramentas do domínio do pedido (filtro por bucket do `classify()`), com
  fallback pra lista completa no retry — prompt menor = decisão mais rápida no CPU
- **Lab de treino** ✅ `lab/` — app vulnerável local (SQLi, XSS, command
  injection, path traversal, IDOR, SSRF, auth fraca + 2º alvo) pra exercitar as
  ferramentas ofensivas end-to-end (ver seção acima)
- **Instalador de ferramentas** ✅ `./install-tools.sh` detecta e instala o que
  falta (nmap/sqlmap/gobuster/nikto/hydra/radare2/yara/exploitdb via pacman,
  holehe/sherlock via pipx); mensagem de erro das tools aponta pra ele

---

## Segurança

Este é um projeto de **pentest pessoal/lab**: scan, brute-force, exploração e OSINT
só devem ser usados contra **sistemas próprios ou autorizados** (engagement, CTF,
lab). O design assume que um humano aprova cada ação sensível antes do disparo —
nada de varredura em massa automática.

`cpf_osint` retorna dado pessoal (LGPD): os resultados ficam só em `data/` e
`logs/` (ambos fora do git, ver `.gitignore`) — apague esses diretórios
periodicamente se não precisar reter o histórico de consultas.
