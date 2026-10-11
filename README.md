# Segurança e Criptografia de Comunicação em Chat
# Algoritmo Blowfish + ECDH 

### 1. Instalando gerenciador de ambiente UV
```bash
pip install uv

```
### 2. Navegue até o projeto
```bash
cd \vorcar.io\app
```
### 3. Sincronize as dependências UV
```bash
uv sync
```

### 4. Baixe a imagem redis pelo Docker CLI e rode na porta padrão

```bash
docker run -d --name redis -p 6379:6379 redis

```
### 5. Subir servidor de aplicação
```bash
uv run uvicorn main:app 
```
### 6. Subir client (Alice -> Bob)
```bash
uv run cli_chat.py alice bob
```
### 7. Subir client (Bob -> Alice)

```bash
uv run cli_chat.py bob alice
```
#### Observe a interação do chat via websocket, a troca de chaves e distribuição pelo terminal do servidor.