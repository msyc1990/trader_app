from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from app.database import create_db_and_tables
from app.routers import ui

app = FastAPI(title="Ciemna Komnata - Sniper HUD Professional")

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

app.include_router(ui.router)

@app.get("/")
async def root():
    return RedirectResponse(url="/auth/logowanie")