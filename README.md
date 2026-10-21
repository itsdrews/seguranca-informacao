# Segurança e Criptografia de Comunicação em Chat
## Algoritmo Blowfish + ECDH + HMAC

Sistema de chat com criptografia ponta-a-ponta (E2E). Cada usuário tem um par de
chaves **ECDH P-256**; a troca de chaves gera um segredo compartilhado, do qual o
**HKDF-SHA256** deriva uma chave para o **Blowfish-CBC** (cifra) e outra para o
**HMAC-SHA256** (autenticação/integridade). As mensagens trafegam cifradas via
WebSocket, com fila **Redis** para destinatários offline e **SQLite** para as
chaves públicas depositadas.

O projeto tem dois clientes que falam com o mesmo backend:

- **CLI** (`vorcar.io/app/cli_chat.py`) — cliente de terminal em Python.
- **Frontend** (`frontend/`) — aplicação web em React + Vite.

---

## Pré-requisitos

| Ferramenta | Para quê | Verificar |
|-----------|----------|-----------|
| [uv](https://docs.astral.sh/uv/) | Ambiente/dependências Python | `uv --version` |
| [Docker](https://docs.docker.com/) | Rodar o Redis | `docker --version` |
| [Node.js](https://nodejs.org/) 18+ | Rodar o frontend | `node --version` |

---

## Tutorial de execução

### Passo 1 — Instalar o uv (se ainda não tiver)

```bash
pip install uv
```

### Passo 2 — Subir o Redis via Docker

A fila de mensagens offline usa o Redis na porta padrão `6379`:

```bash
docker run -d --name redis -p 6379:6379 redis
```

Se o container já existir de uma execução anterior, basta reiniciá-lo:

```bash
docker start redis
```

> O servidor **não sobe** sem o Redis: há uma verificação de conexão no startup
> (`vorcar.io/app/main.py`) que aborta com erro se a porta 6379 não responder.

### Passo 3 — Instalar as dependências do backend

```bash
cd vorcar.io
uv sync
```

### Passo 4 — Subir o servidor (API + WebSocket)

A partir de `vorcar.io/app`:

```bash
cd app
uv run uvicorn main:app --reload
```

O servidor sobe em `http://localhost:8000`. Confira em `http://localhost:8000/`
(deve responder `{"status": "API operando com SQLite e Redis"}`) ou abra a
documentação interativa em `http://localhost:8000/docs`.

### Passo 5a — Usar o cliente CLI

Em **outro terminal**, a partir de `vorcar.io/app`, suba um cliente por usuário:

```bash
uv run cli_chat.py alice
```

```bash
uv run cli_chat.py bob
```

Ao iniciar, o cliente deposita a chave pública no servidor e mostra os comandos:

```
/keys                  - Lista usuários e chaves do servidor
/chat <user1> <user2>  - Inicia chat com um ou mais destinatários (1:N)
/status                - Exibe destinatários e sessões ativas
/ajuda                 - Exibe a ajuda
/sair                  - Encerra o chat
```

Fluxo típico: no terminal da Alice, `/chat bob` e comece a digitar. As chaves
privadas ficam em `alice_private.pem` / `bob_private.pem` (não versionados).

### Passo 5b — Usar o frontend web

Em **outro terminal**, a partir de `frontend/`:

```bash
cd frontend
npm install
npm run dev
```

Abra `http://localhost:5173`. O frontend consome a API em `127.0.0.1:8000` (CORS
já liberado para `localhost:5173` em `main.py`) e implementa o mesmo pipeline de
cripto do CLI (ECDH + HKDF + Blowfish + HMAC via Web Crypto API), de modo que
clientes web e CLI conversam entre si.

### Resumo (ordem de inicialização)

```
1. docker start redis          (ou o docker run do passo 2)
2. cd vorcar.io/app && uv run uvicorn main:app --reload
3a. uv run cli_chat.py alice   (e bob em outro terminal)
3b. cd frontend && npm run dev
```

---

## Demonstrações de ataque (relatório)

Três demonstrações de segurança foram planejadas para o relatório, cada uma
explorando uma camada diferente do sistema:

1. **Man-in-the-Middle na troca de chaves** — explora a ausência de autenticação
   no depósito/consulta de chaves públicas.

O guia de implementação (conceito, pontos do código, esqueleto da lógica e o que
capturar) está em **[docs/DEMONSTRACOES_DE_ATAQUE.md](docs/DEMONSTRACOES_DE_ATAQUE.md)**.

---

## Estrutura do projeto

```
seguranca-informacao/
├── vorcar.io/                 # Backend (FastAPI + uv)
│   └── app/
│       ├── main.py            # App FastAPI, CORS, lifespan (checa Redis)
│       ├── cli_chat.py        # Cliente de terminal
│       ├── database.py        # SQLite (chaves públicas)
│       ├── redis_client.py    # Fila de mensagens offline
│       ├── crypto/            # blowfish, ecdh, hmac, kdf
│       └── routers/           # keys, messages, websockets
├── frontend/                  # Frontend React + Vite
│   └── src/
│       ├── crypto/            # mesmo pipeline em TypeScript (Web Crypto)
│       ├── services/          # api.ts, websocket.ts
│       └── ...
└── docs/
    └── DEMONSTRACOES_DE_ATAQUE.md
```
