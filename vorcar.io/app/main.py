
from contextlib import asynccontextmanager

from database import Base, engine
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis_client import check_redis_connection
from routers.keys_router import router as keys_router
from routers.messages_router import router as messages_router
from routers.websockets_router import router as websockets_router


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

    yield

    # Evento de Encerramento (Shutdown)
    print("🛑 Encerrando aplicação...")


app = FastAPI(
    title="Chaves Persistentes & Fila de Mensagens Redis - Chat E2E",
    lifespan=lifespan
)

# Permite requisições HTTP do frontend React
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Registra as rotas do backend
app.include_router(keys_router)
app.include_router(messages_router)
app.include_router(websockets_router)


@app.get("/")
def root():
    return {"status": "API operando com SQLite e Redis"}
