from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel

class Uzytkownik(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True)  # Unikalna nazwa użytkownika
    password_hash: str                  # Zaszyfrowane hasło
    kapital: float                      # Wymagane pole, definiowane przy rejestracji
    poziom: int = Field(default=1)
    status_snajpera: str = Field(default="CZUWANIE")  # CZUWANIE, POLOWANIE, BLOKADA
    blokada_do: Optional[datetime] = Field(default=None)
    licznik_prob: int = Field(default=0)

class Magazynek(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    uzytkownik_id: int = Field(foreign_key="uzytkownik.id")
    dostepna_amunicja: int = Field(default=3)
    data_resetu: datetime

class Transakcja(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    aktywo: str  # BTC, ETH, BNB
    interwal: str  # H1, H4, D1
    kierunek: str  # LONG, SHORT
    cena_wejscia: float
    kwota_pozycji: float  # Kwota USDC zaangażowana w transakcję (zamrożona)
    stop_loss: float      # Wyliczana automatycznie przez system obronny
    aktualne_rsi: float
    poziom_halasu: str  # NISKI, SREDNI, WYSOKI
    ranga_strzalu: str  # LASEROWY, RYKOSZET
    komentarz: Optional[str] = Field(default=None)
    cena_wyjscia: Optional[float] = Field(default=None)
    wynik_finansowy: Optional[float] = Field(default=None)
    status_pozycji: str = Field(default="OTWARTA")  # OTWARTA, ZAMKNIETA
    data_strzalu: datetime = Field(default_factory=datetime.utcnow)