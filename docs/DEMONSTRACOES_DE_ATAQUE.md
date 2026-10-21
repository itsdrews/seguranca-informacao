# Guia de Implementação — Demonstrações de Ataque

> Documento de apoio ao relatório da disciplina de Segurança da Informação.
> Descreve **como construir** três demonstrações de ataque contra o próprio
> sistema de chat (Blowfish + ECDH + HMAC). Os scripts não estão prontos aqui —
> este guia dá o conceito, os pontos exatos do código onde cada ataque se
> encaixa, o esqueleto da lógica e o que capturar para o relatório.

## Sumário

1. [Entendendo o alvo](#0-entendendo-o-alvo)
2. [Ataque 1 — Man-in-the-Middle na troca de chaves](#ataque-1--man-in-the-middle-na-troca-de-chaves)

---

## 0. Entendendo o alvo

Antes de atacar, vale fixar como o pipeline funciona hoje, porque cada ataque
explora uma camada diferente dele.

Fluxo de uma mensagem de `alice` para `bob` (vale para o CLI e para o frontend):

```
1. Cada usuário gera um par ECDH P-256 (identidade de longo prazo).
   - Python: ECC.generate(curve="p256")  -> cli_chat.py:37 (_load_or_create_identity_key)
   - Web:    crypto.subtle.generateKey    -> frontend/src/crypto/ecdh.ts

2. Cada usuário DEPOSITA a chave pública no servidor, SEM autenticação:
   POST /keys/{user_id}  -> vorcar.io/app/routers/keys_router.py:28

3. Para falar com bob, alice BUSCA a chave pública de bob:
   GET /keys/{bob}       -> keys_router.py:70
   - cliente: fetch_peer_key() em cli_chat.py:67

4. ECDH(priv_alice, pub_bob) = segredo compartilhado
   -> init_session_for() em cli_chat.py:77

5. HKDF-SHA256(segredo) -> (cipher_key 16B, mac_key 16B)
   -> crypto/kdf.py (KeyDerivator.derive)

6. Blowfish-CBC(cipher_key) cifra {text, timestamp}; gera (iv, ciphertext)
   -> crypto/blowfish.py (BlowfishCipher.encrypt)

7. HMAC-SHA256(mac_key) sobre (iv + ciphertext) -> tag
   -> crypto/hmac.py (MessageAuthenticator.sign)

8. Pacote base64({iv, ciphertext, tag}) vai pelo WebSocket.
   -> encrypt_for() em cli_chat.py:93 / decrypt_from() em cli_chat.py:116
```

---

## Ataque 1 — Man-in-the-Middle na troca de chaves

### Objetivo da demonstração

Provar, com código rodando de verdade, que Sauron consegue se intercalar entre
Gandalf e Elrond, **ler** todas as mensagens em claro e **repassá-las** sem que
nenhum dos dois perceba — tudo porque o servidor não autentica a chave pública.
É o gancho perfeito para a seção de "trabalhos futuros" (autenticar a pré-chave).

### Por que funciona

Em `GET /keys/{user_id}` (`keys_router.py:70`) o servidor devolve a chave que
estiver no banco, sem nenhuma assinatura ou prova de posse. E em
`POST /keys/{user_id}` (`keys_router.py:28`) qualquer um grava qualquer chave sob
qualquer nome. Gandalf confia cegamente na chave que recebe (`fetch_peer_key`,
`cli_chat.py:67`). Se Sauron conseguir que Gandalf receba **a chave dela** no
lugar da de Elrond, o ECDH de Gandalf fecha um segredo com Sauron, não com Elrond.

O núcleo do ataque é a **dupla sessão** de Sauron:

```
Gandalf  --ECDH-->  Sauron  --ECDH-->  Elrond
         (chave M)           (chave M)

- Gandalf pensa que a chave pública "de Elrond" é a de Sauron.
- Elrond pensa que a chave pública "de Gandalf" é a de Sauron.
- Sauron mantém DUAS sessões:
    S1 = HKDF(ECDH(priv_M, pub_Gandalf))   <- fala com Gandalf
    S2 = HKDF(ECDH(priv_M, pub_Elrond))    <- fala com Elrond
- Mensagem chega cifrada com S1 -> Sauron decifra, lê,
  recifra com S2 -> repassa. Ninguém nota.
```

### Duas formas de montar (escolha uma, ou mostre as duas)

**Forma A — Envenenamento de diretório (mais simples, recomendada para começar).**
Explora diretamente a falta de autenticação no `POST`. Sauron simplesmente
sobrescreve a chave de Elrond no servidor pela dela **antes** de Gandalf buscar.

Esqueleto da lógica (não é o script final, é o roteiro):

```
# "sauron" tem o próprio par ECDH (priv_M, pub_M).
1. Sauron gera/pega seu par ECDH (igual ao cliente faz em cli_chat.py:37).
2. Sauron faz POST /keys/elrond com pub_M  (sobrescreve a chave real de Elrond).
   -> usa o MESMO endpoint que o cliente legítimo usa em deposit_public_key(), cli_chat.py:48
3. Agora Gandalf faz /chat elrond: fetch_peer_key("elrond") devolve pub_M.
   Gandalf deriva S1 = HKDF(ECDH(priv_Gandalf, pub_M)).  <- igual S1 de Sauron.
4. Gandalf envia a mensagem cifrada com S1.
5. Sauron (conectada ao WS como "elrond", ou lendo a fila) decifra com S1.
```

Limitação honesta da Forma A: para repassar a Elrond **sem ele notar**, Sauron
precisaria também ter feito Elrond receber `pub_M` no lugar de `pub_Gandalf`. Então,
para o repasse transparente, Sauron sobrescreve **as duas** chaves (`elrond` e
`gandalf`) por `pub_M`. Deixe isso explícito no relatório.

**Forma B — Proxy HTTP interceptador (mais fiel ao "man-in-the-middle" clássico).**
Sauron sobe um pequeno servidor que fica **entre** o cliente e o backend real.
Gandalf aponta para o proxy (trocando `HTTP_URL` em `cli_chat.py:15`, ou via
`hosts`/porta). O proxy repassa tudo para o backend verdadeiro, **exceto** o
`GET /keys/elrond`, cuja resposta ele reescreve trocando `public_key` por `pub_M`.

Esqueleto:

```
Proxy (FastAPI ou http.server) escutando em :9000, backend real em :8000.

- Qualquer rota != GET /keys/elrond  -> encaminha para :8000 e devolve igual.
- GET /keys/elrond                   -> busca no backend, mas ANTES de devolver
                                        substitui o campo public_key por base64(pub_M_DER).
- (opcional) intercepta o tráfego WS para fazer o repasse decifra->recifra.
```

A Forma B é visualmente mais convincente ("o servidor estava intacto, a chave
foi trocada no caminho"), mas dá mais trabalho por causa do WebSocket. Sugestão:
**use a Forma A para o relatório** e cite a Forma B como variação.

### Peças de código que você vai reutilizar

Tudo já existe no projeto — Sauron é basicamente um `ChatClient` com superpoderes:

- Gerar par e exportar DER/base64: ver `deposit_public_key()` em `cli_chat.py:48`.
- Derivar sessão a partir de uma chave peer: `init_session_for()` em `cli_chat.py:77`
  (é aqui que mora o `ECDH + HKDF`).
- Decifrar/recifrar: `decrypt_from()` e `encrypt_for()`, `cli_chat.py:116` e `:93`.

Para as duas sessões de Sauron, basta manter dois dicionários de sessão (ou
instanciar a derivação duas vezes com `KeyDerivator.derive`).

### O que capturar para o relatório

1. Print do segredo/`cipher_key` que **Gandalf** derivou e do que **Sauron**
   derivou lado a lado — devem ser **idênticos** (prova que a sessão é com Sauron).
2. A mensagem em claro aparecendo no terminal de Sauron.
3. (Se fizer o repasse) a mesma mensagem chegando normalmente em Elrond, com a
   tag HMAC válida — mostrando que o HMAC **não protege** contra MITM, porque
   Sauron tem a `mac_key` legítima de cada trecho.
4. Conclusão: o HMAC garante integridade **dado** um segredo compartilhado
   autêntico; ele não resolve a ausência de autenticação da chave. Daí a melhoria
   futura: assinar a pré-chave (ex.: identidade assinada, TOFU, ou certificado).

---

```

Como os scripts importam `from crypto.blowfish import ...`, rode-os **a partir de
`vorcar.io/app/`** (que é onde o `crypto/` é visível), usando o ambiente `uv`:

```bash
cd vorcar.io/app
```
Para o **MITM (Forma A)**, você precisa do servidor e do Redis no ar (ver o
tutorial de execução no `README.md`), porque o ataque conversa com os endpoints
`/keys`. O `bitflip` e o `bruteforce` são autocontidos e rodam offline.

> Lembrete: `*.pem`, `*.db` e `*.png` estão no `.gitignore`. Se o gráfico do
> ataque 3 for exportado como `.png`, ele não será versionado — exporte também o
> `.csv` ou mova o `.png` para fora do ignore se quiser commitá-lo.
