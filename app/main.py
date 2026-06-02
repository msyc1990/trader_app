from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.database import create_db_and_tables
from app.routers import ui

app = FastAPI(title="Ciemna Komnata - Sniper HUD Professional")

# Funkcja uruchamiana przy starcie serwera
@app.on_event("startup")
def on_startup():
    # Automatycznie tworzy plik bazy danych i tabele na podstawie modeli, jeśli nie istnieją
    create_db_and_tables()

# Podłączenie routera autoryzacji, który stworzyliśmy w poprzednim kroku
app.include_router(ui.router)

# Domyślne przekierowanie ze strony głównej na ekran logowania
from fastapi.responses import RedirectResponse
@app.get("/")
async def root():
    return RedirectResponse(url="/auth/logowanie")