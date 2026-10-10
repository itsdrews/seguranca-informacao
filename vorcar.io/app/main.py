from database import Base, engine
from fastapi import FastAPI
from routers.keys_router import router as keys_router
from routers.messages_router import router as messages_router
from contextlib import asynccontextmanager
from redis_client import check_redis_connection

@asynccontextmanager
async def lifespan(app: FastAPI):
  # Evento de Inicialização (Startup)
  print("🔍 Verificando conexão com o Redis...")
  if not check_redis_connection():
    raise RuntimeError(
        "❌ [ERRO CRÍTICO] Não foi possível conectar ao Redis na porta 6379."
        " Certifique-se de que o container Docker está em execução!"
    )
  print("✅ Conexão com Redis estabelecida com sucesso!")

  # Cria tabelas no SQLite se necessário
  Base.metadata.create_all(bind=engine)

  yield  # Aplicação pronta para receber requisições

  # Evento de Encerramento (Shutdown)
  print("🛑 Encerrando aplicação...")


app = FastAPI(
    title="Chaves Persistentes & Fila de Mensagens Redis", lifespan=lifespan
)

app.include_router(keys_router)
app.include_router(messages_router)


@app.get("/")
def root():
  return {"status": "API operando com SQLite e Redis"}