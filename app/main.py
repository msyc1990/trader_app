import httpx
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select
from app.database import create_db_and_tables, engine
from app.routers import ui
from app.models import TokenRynkowy

app = FastAPI(title="Ciemna Komnata - Sniper HUD Professional")

async def pobierz_tokeny_z_binance() -> list[dict]:
    """Pobiera listę tokenów z Binance API."""
    url = "https://api.binance.com/api/v3/exchangeInfo"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # Filtrowanie: tylko tokeny USDT, TRADING, spot allowed
            tokeny = []
            for symbol_data in data.get("symbols", []):
                if (symbol_data.get("quoteAsset") == "USDT" and
                    symbol_data.get("status") == "TRADING" and
                    symbol_data.get("isSpotTradingAllowed") is True):
                    tokeny.append({
                        "symbol": symbol_data.get("baseAsset"),
                        "nazwa_pary": symbol_data.get("symbol")
                    })
            return tokeny
    except Exception as e:
        print(f"[BŁĄD] Nie udało się pobrać tokenów z Binance: {e}")
        return []

async def zsynchronizuj_tokeny_binance():
    """Synchronizuje tokeny z Binance i zapisuje do bazy danych."""
    tokeny = await pobierz_tokeny_z_binance()
    
    if not tokeny:
        print("[INFO] Brak tokenów do synchronizacji.")
        return
    
    # Otwarcie sesji i sprawdzenie, czy tabela jest pusta
    with Session(engine) as session:
        istniejace_tokeny = session.exec(select(TokenRynkowy)).first()
        
        if not istniejace_tokeny:
            print(f"[INFO] Synchronizacja {len(tokeny)} tokenów z Binance...")
            for token_data in tokeny:
                token = TokenRynkowy(
                    symbol=token_data["symbol"],
                    nazwa_pary=token_data["nazwa_pary"]
                )
                session.add(token)
            
            try:
                session.commit()
                print(f"[SUKCES] Zapisano {len(tokeny)} tokenów do bazy danych.")
            except Exception as e:
                print(f"[BŁĄD] Nie udało się zapisać tokenów do bazy: {e}")
                session.rollback()
        else:
            print("[INFO] Tokeny już istnieją w bazie. Pomijam synchronizację.")

@app.on_event("startup")
async def on_startup():
    create_db_and_tables()
    await zsynchronizuj_tokeny_binance()

app.include_router(ui.router)

@app.get("/")
async def root():
    return RedirectResponse(url="/auth/logowanie")