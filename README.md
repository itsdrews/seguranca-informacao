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
uv run cli_chat.py alice

```
Alice deposita chave e uma lista de comandos aparece disponível.
```bash
/keys  # Retorna lista de 'usuários' chaves públicas disponíveis no servidor
/chat <destinatario1> <destinatario2> # Permite uma troca de mensagens 1:N 

```
### Próximo passo: implementar room para que as mensagens não sejam disparadas uma a uma para cada interlocutor
