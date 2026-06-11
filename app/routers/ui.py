import httpx
import json
from typing import Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import Signer, BadSignature
from passlib.context import CryptContext
from sqlmodel import Session, select

from app.database import get_session
from app.models import Uzytkownik, Transakcja, Magazynek, LogZdarzen, TokenRynkowy

SECRET_KEY = "twoj-bardzo-tajny-klucz-snajpera"
signer = Signer(SECRET_KEY)

async def utworz_log_i_toast(session: Session, user_id: int, komunikat: str, typ: str = "INFO") -> str:
    # 1. Zapis zdarzenia do bazy danych dla historii audytowej
    nowy_log = LogZdarzen(uzytkownik_id=user_id, komunikat=komunikat, typ_zdarzenia=typ)
    session.add(nowy_log)
    session.commit()
    
    # 2. Przygotowanie struktury JSON dla nagłówka HX-Trigger
    # Przekazujemy treść oraz typ (np. SUCCESS, WARNING), by frontend wiedział jak zabarwić Toast
    payload = {"pokazToast": {"text": komunikat, "type": typ}}
    return json.dumps(payload)

router = APIRouter(prefix="/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

templates = Jinja2Templates(directory="app/templates")


async def get_current_user(request: Request, session: Session = Depends(get_session)) -> Uzytkownik:
    session_cookie = request.cookies.get("session_id")
    if not session_cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Brak aktywnej sesji.")
    try:
        unsigned_id = signer.unsign(session_cookie).decode()
        user_id = int(unsigned_id)
    except (BadSignature, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Niepoprawna sesja.")

    uzytkownik = session.get(Uzytkownik, user_id)
    if not uzytkownik:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Użytkownik nie istnieje.")
    return uzytkownik


# --- ENDPOINTY GET ---

@router.get("/logowanie", response_class=HTMLResponse)
async def wyswietl_logowanie(request: Request) -> HTMLResponse:
    """Zwraca widok strony logowania."""
    return templates.TemplateResponse(request=request, name="logowanie.html")


@router.get("/rejestracja", response_class=HTMLResponse)
async def wyswietl_rejestracje(request: Request) -> HTMLResponse:
    """Zwraca widok strony rejestracji."""
    return templates.TemplateResponse(request=request, name="rejestracja.html")


# --- ENDPOINTY POST (AUTORYZACJA) ---

@router.post("/rejestracja", response_class=HTMLResponse)
async def proces_rejestracji(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    kapital: float = Form(...),
    session: Session = Depends(get_session)
) -> HTMLResponse:
    statement = select(Uzytkownik).where(Uzytkownik.username == username)
    istniejacy_uzytkownik = session.exec(statement).first()

    if istniejacy_uzytkownik:
        return HTMLResponse(
            content="Użytkownik o takiej nazwie już istnieje!",
            headers={"HX-Retarget": "#error-message"}
        )

    hashed_password = pwd_context.hash(password)
    nowy_uzytkownik = Uzytkownik(
        username=username,
        password_hash=hashed_password,
        kapital=kapital
    )

    session.add(nowy_uzytkownik)
    session.commit()

    # Tworzenie magazynka dla nowego użytkownika
    nowy_magazynek = Magazynek(
        uzytkownik_id=nowy_uzytkownik.id,
        dostepna_amunicja=3,
        data_resetu=datetime.utcnow() + timedelta(seconds=10)  # Szybszy reset dla testów, normalnie byłoby timedelta(days=7
    )
    session.add(nowy_magazynek)
    session.commit()

    return templates.TemplateResponse(
        request=request,
        name="logowanie.html",
        context={"success": "Rejestracja udana! Możesz się teraz zalogować."}
    )


@router.post("/logowanie", response_class=HTMLResponse)
async def proces_logowania(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session)
) -> HTMLResponse:
    statement = select(Uzytkownik).where(Uzytkownik.username == username)
    uzytkownik = session.exec(statement).first()

    if not uzytkownik or not pwd_context.verify(password, uzytkownik.password_hash):
        return HTMLResponse(
            content="Nieprawidłowa nazwa użytkownika lub hasło!",
            headers={"HX-Retarget": "#error-message"}
        )

    # NOWOŚĆ: Generowanie podpisanego ciasteczka sesji
    signed_id = signer.sign(str(uzytkownik.id).encode()).decode()
    
    response = HTMLResponse(content="", headers={"HX-Redirect": "/auth/hud"})
    # Zapisujemy ciasteczko bezpiecznie (httponly chroni przed atakami XSS)
    response.set_cookie(key="session_id", value=signed_id, httponly=True, path="/")
    return response


# --- ENDPOINT WYSZUKIWANIA TOKENÓW (AUTOCOMPLETE) ---

@router.post("/hud/szukaj-tokena", response_class=HTMLResponse)
async def szukaj_tokena(
    aktywo: str = Form(""),
    session: Session = Depends(get_session)
) -> HTMLResponse:
    """Wyszukuje tokeny z bazy TokenRynkowy pasujące do danej frazy."""
    if len(aktywo.strip()) == 0:
        return HTMLResponse(content="")
    
    # Wyszukaj tokeny, których symbol zaczyna się od wpisanej frazy (np. SOL, BTC)
    statement = select(TokenRynkowy).where(
        TokenRynkowy.symbol.like(f"{aktywo.upper()}%")
    ).limit(8)
    
    tokeny = session.exec(statement).all()
    
    if not tokeny:
        return HTMLResponse(content='<div class="text-xs text-red-500 p-2 border border-red-800 bg-red-950 mt-1 rounded">Brak tokenu na Binance</div>')
    
    # Generuj taktyczne przyciski dla każdego znalezionego tokenu
    html_wyniki = ""
    for token in tokeny:
        html_wyniki += f'''
        <button type="button" 
                hx-on:click="document.getElementById('aktywo-input').value = '{token.symbol}'; document.getElementById('wyniki-szukania').innerHTML = ''; document.getElementById('aktywo-input').focus();"
                class="block w-full text-left p-2 bg-gray-800 hover:bg-green-500 hover:text-black text-xs font-mono border-b border-gray-700 text-green-400 transition-colors">
            {token.symbol} ({token.nazwa_pary})
        </button>
        '''
    
    return HTMLResponse(content=html_wyniki)


# --- BEZPIECZNY ENDPOINT HUD (Z LOGIKĄ REFRESHU MAGAZYNKA) ---

@router.get("/hud", response_class=HTMLResponse)
async def wyswietl_hud(
    request: Request, 
    session: Session = Depends(get_session),
    uzytkownik: Uzytkownik = Depends(get_current_user)  # WTRZYKNIĘCIE SESJI
) -> HTMLResponse:
    """Pobiera zalogowanego użytkownika, obsługuje odnowienie amunicji, pobiera pozycje i historię."""
    
    headers = None

    # 1. Sprawdzenie aktywnej blokady Karcera
    if uzytkownik.blokada_do:
        if datetime.utcnow() > uzytkownik.blokada_do:
            uzytkownik.status_snajpera = "CZUWANIE"
            uzytkownik.blokada_do = None
            uzytkownik.licznik_prob = 0
            session.add(uzytkownik)
            session.commit()

    if uzytkownik.status_snajpera == 'BLOKADA':
        headers = {
            "HX-Trigger": json.dumps({
                "pokazToast": {
                    "text": "🚨 PROTOKÓŁ OCHRONY AKTYWNY: Terminal zablokowany!",
                    "type": "DANGER"
                }
            })
        }
            
    # 2. NOWOŚĆ: Pobranie magazynka (odświeżenie amunicji nastąpi po wyliczeniu poziomu)
    magazynek = session.exec(select(Magazynek).where(Magazynek.uzytkownik_id == uzytkownik.id)).first()
    
    # 3. Filtrowanie aktywnych pozycji użytkownika
    statement_pozycje = select(Transakcja).where(
        Transakcja.status_pozycji == 'OTWARTA',
        Transakcja.uzytkownik_id == uzytkownik.id
    )
    otwarte_pozycje = session.exec(statement_pozycje).all()
    
    # 4. Filtrowanie zamkniętych pozycji użytkownika
    statement_zamkniete = select(Transakcja).where(
        Transakcja.status_pozycji == 'ZAMKNIETA',
        Transakcja.uzytkownik_id == uzytkownik.id
    )
    zamkniete_pozycje = session.exec(statement_zamkniete).all()
    
    total_pnl = sum(p.wynik_finansowy for p in zamkniete_pozycje if p.wynik_finansowy is not None)
    liczba_zamknietych = len(zamkniete_pozycje)
    pozycje_zyskowne = sum(1 for p in zamkniete_pozycje if p.wynik_finansowy is not None and p.wynik_finansowy > 0)
    
    win_rate = round((pozycje_zyskowne / liczba_zamknietych) * 100, 1) if liczba_zamknietych > 0 else 0.0
    laczna_liczba_strzalow = len(otwarte_pozycje) + liczba_zamknietych

    # 5. Dynamiczne przyznawanie rang i poziomów
    if liczba_zamknietych >= 7 and win_rate >= 65.0:
        uzytkownik.poziom = 3
        if uzytkownik.status_snajpera != 'BLOKADA':
            uzytkownik.status_snajpera = 'ELITARNY SNAJPER'
    elif liczba_zamknietych >= 3 and win_rate >= 50.0:
        uzytkownik.poziom = 2
        if uzytkownik.status_snajpera != 'BLOKADA':
            uzytkownik.status_snajpera = 'STRZELEC WYBOROWY'
    else:
        uzytkownik.poziom = 1
        if uzytkownik.status_snajpera != 'BLOKADA':
            uzytkownik.status_snajpera = 'REKRUT'

    session.add(uzytkownik)
    session.commit()

    max_amunicji = 3
    if uzytkownik.poziom == 2:
        max_amunicji = 4
    elif uzytkownik.poziom == 3:
        max_amunicji = 5

    if magazynek:
        if datetime.utcnow() > magazynek.data_resetu:
            magazynek.dostepna_amunicja = max_amunicji
            magazynek.data_resetu = datetime.utcnow() + timedelta(seconds=10)  # Szybszy reset dla testów
            session.add(magazynek)
            session.commit()
        
    wykres_kapitalu = []
    kapital_poczatkowy = uzytkownik.kapital - total_pnl
    wykres_kapitalu.append(round(kapital_poczatkowy, 2))
    biezacy_kapital = kapital_poczatkowy
    for p in sorted(zamkniete_pozycje, key=lambda x: x.id or 0):
        if p.wynik_finansowy is not None:
            biezacy_kapital += p.wynik_finansowy
            wykres_kapitalu.append(round(biezacy_kapital, 2))

    return templates.TemplateResponse(
        request=request,
        name="hud.html",
        context={
            "uzytkownik": uzytkownik,
            "magazynek": magazynek,  # KLUCZOWE: Przekazujemy magazynek do frontu!
            "pozycje": otwarte_pozycje,
            "historia": zamkniete_pozycje,
            "total_pnl": round(total_pnl, 2),
            "win_rate": win_rate,
            "laczna_liczba_strzalow": laczna_liczba_strzalow,
            "max_amunicji": max_amunicji,
            "dane_wykresu": wykres_kapitalu
        },
        headers=headers
    )


# --- DYNAMICZNE FORMULARZE RYGORU (BEZMIAN) ---

def _oblicz_ema(ceny: list[float], okres: int) -> float:
    """Oblicza wygładzoną średnią EMA dla podanego okresu."""
    wspolczynnik = 2 / (okres + 1)
    ema = sum(ceny[:okres]) / okres
    for cena in ceny[okres:]:
        ema = (cena - ema) * wspolczynnik + ema
    return ema


def _oblicz_rsi(ceny: list[float], okres: int) -> float:
    """Oblicza RSI 14 wykorzystując wygładzanie Wildera."""
    if len(ceny) <= okres:
        return 50.0

    zmiany = [ceny[i] - ceny[i - 1] for i in range(1, len(ceny))]
    zyski = [max(z, 0) for z in zmiany[:okres]]
    straty = [max(-z, 0) for z in zmiany[:okres]]

    sredni_zysk = sum(zyski) / okres
    srednia_strata = sum(straty) / okres

    for delta in zmiany[okres:]:
        zysk = max(delta, 0)
        strata = max(-delta, 0)
        sredni_zysk = (sredni_zysk * (okres - 1) + zysk) / okres
        srednia_strata = (srednia_strata * (okres - 1) + strata) / okres

    if srednia_strata == 0:
        return 100.0

    rs = sredni_zysk / srednia_strata
    return 100.0 - (100.0 / (1.0 + rs))


async def _pobierz_wskazniki_awaryjne(aktywo: str) -> tuple[float, float, float]:
    ceny_awaryjne = {"BTC": 65000.0, "ETH": 35000.0, "BNB": 580.0}
    cena = ceny_awaryjne.get(aktywo.upper(), 1.0)
    return round(cena, 4), 50.0, round(cena, 4)


async def pobierz_wskazniki_rynkowe(aktywo: str, interwal: str) -> tuple[float, float, float]:
    """Pobiera z Binance aktualną cenę, EMA20 oraz RSI14 dla danego aktywa i interwału."""
    symbol = f"{aktywo.upper()}USDT"
    url = "https://api.binance.com/api/v3/klines"
    params = {"symbol": symbol, "interval": interwal, "limit": 50}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params, timeout=5.0)
            response.raise_for_status()
            dane = response.json()
            if not isinstance(dane, list) or len(dane) < 20:
                raise ValueError("Nieprawidłowa odpowiedź Binance")

            zamkniecia = [float(k[4]) for k in dane if len(k) > 4]
            if len(zamkniecia) < 20:
                raise ValueError("Za mało danych do obliczeń")

            aktualna_cena = zamkniecia[-1]
            ema20 = _oblicz_ema(zamkniecia, 20)
            rsi = _oblicz_rsi(zamkniecia, 14)
            return round(aktualna_cena, 4), round(rsi, 2), round(ema20, 4)
    except Exception:
        return await _pobierz_wskazniki_awaryjne(aktywo)


async def pobierz_cene_na_zywo(aktywo: str) -> float:
    """Pobiera aktualną cenę z Binance API. W razie błędu zwraca cenę awaryjną."""
    symbol = f"{aktywo.upper()}USDC"
    url = f"https://api.binance.com/api/v3/ticker/price?symbol={symbol}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=3.0)
            if response.status_code == 200:
                data = response.json()
                return float(data["price"])
    except Exception:
        pass
    # Cena awaryjna (fallback) w razie braku sieci lub błędu API
    ceny_awaryjne = {"BTC": 65000.0, "ETH": 35000.0, "BNB": 580.0}
    return ceny_awaryjne.get(aktywo.upper(), 1.0)


@router.post("/hud/krok2", response_class=HTMLResponse)
async def proces_krok2(
    request: Request,
    aktywo: str = Form(...),
    interwal: str = Form(...),
    kierunek: str = Form(...),
    procent_ryzyka: float = Form(...),
    uzytkownik: Uzytkownik = Depends(get_current_user)
) -> HTMLResponse:
    cena_wejscia, rsi, ema20 = await pobierz_wskazniki_rynkowe(aktywo, interwal)
    stop_loss = cena_wejscia * 0.95 if kierunek.upper() == "LONG" else cena_wejscia * 1.05

    ostrzezenie_trendu = False
    komunikat_trendu = ""
    if kierunek.upper() == "LONG" and cena_wejscia < ema20:
        ostrzezenie_trendu = True
        komunikat_trendu = "⚠️ GRA POD PRĄD: Rynek w trendzie spadkowym (Cena poniżej EMA20)!"
    elif kierunek.upper() == "SHORT" and cena_wejscia > ema20:
        ostrzezenie_trendu = True
        komunikat_trendu = "⚠️ GRA POD PRĄD: Rynek w trendzie wzrostowym (Cena powyżej EMA20)!"

    if ostrzezenie_trendu:
        procent_ryzyka = procent_ryzyka / 2
        komunikat_trendu += " Ryzyko zredukowane o 50% ze względów bezpieczeństwa."

    kwota_ryzyka_usdc = uzytkownik.kapital * (procent_ryzyka / 100)
    dystans_sl = abs(cena_wejscia - stop_loss) / cena_wejscia

    if dystans_sl <= 0:
        return HTMLResponse(
            content="Błąd: Nie można wyliczyć odległości do Stop Loss. Sprawdź parametry.",
            headers={"HX-Retarget": "#error-message"}
        )

    kwota_pozycji = kwota_ryzyka_usdc / dystans_sl
    kwota_pozycji = round(kwota_pozycji, 2)

    if kwota_pozycji > uzytkownik.kapital:
        return HTMLResponse(
            content=f"Błąd: Wyliczona wielkość pozycji ({kwota_pozycji:.2f} USDC) przekracza Twój dostępny kapitał! Zmniejsz procent ryzyka.",
            headers={"HX-Retarget": "#error-message"}
        )

    return templates.TemplateResponse(
        request=request,
        name="krok2.html",
        context={
            "aktywo": aktywo,
            "interwal": interwal,
            "kierunek": kierunek,
            "cena_wejscia": cena_wejscia,
            "procent_ryzyka": procent_ryzyka,
            "stop_loss": round(stop_loss, 4),
            "kwota_pozycji": kwota_pozycji,
            "kwota_ryzyka_usdc": round(kwota_ryzyka_usdc, 2),
            "rsi": rsi,
            "ema20": ema20,
            "ostrzezenie_trendu": ostrzezenie_trendu,
            "komunikat_trendu": komunikat_trendu
        }
    )


@router.post("/hud/krok3", response_class=HTMLResponse)
async def proces_krok3(
    request: Request,
    aktywo: str = Form(...),
    interwal: str = Form(...),
    kierunek: str = Form(...),
    cena_wejscia: float = Form(...),
    kwota_pozycji: float = Form(...),
    kwota_ryzyka_usdc: float = Form(...),
    procent_ryzyka: float = Form(...),
    aktualne_rsi: float = Form(...),
    ema20: float = Form(...),
    ostrzezenie_trendu: bool = Form(False),
    komunikat_trendu: str = Form(""),
    stop_loss: float = Form(...)
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="krok3.html",
        context={
            "aktywo": aktywo, "interwal": interwal, "kierunek": kierunek,
            "cena_wejscia": cena_wejscia, "kwota_pozycji": kwota_pozycji,
            "kwota_ryzyka_usdc": kwota_ryzyka_usdc, "procent_ryzyka": procent_ryzyka,
            "aktualne_rsi": aktualne_rsi, "ema20": ema20,
            "ostrzezenie_trendu": ostrzezenie_trendu,
            "komunikat_trendu": komunikat_trendu,
            "stop_loss": stop_loss
        }
    )


@router.post("/hud/krok4", response_class=HTMLResponse)
async def proces_krok4(
    request: Request,
    aktywo: str = Form(...),
    interwal: str = Form(...),
    kierunek: str = Form(...),
    cena_wejscia: float = Form(...),
    kwota_pozycji: float = Form(...),
    kwota_ryzyka_usdc: float = Form(...),
    procent_ryzyka: float = Form(...),
    aktualne_rsi: float = Form(...),
    stop_loss: float = Form(...),
    poziom_halasu: str = Form(...),
    ranga_strzalu: str = Form(...),
    komentarz: Optional[str] = Form(None)
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="krok4.html",
        context={
            "aktywo": aktywo, "interwal": interwal, "kierunek": kierunek,
            "cena_wejscia": cena_wejscia, "kwota_pozycji": kwota_pozycji,
            "kwota_ryzyka_usdc": kwota_ryzyka_usdc, "procent_ryzyka": procent_ryzyka,
            "aktualne_rsi": aktualne_rsi, "stop_loss": stop_loss,
            "poziom_halasu": poziom_halasu, "ranga_strzalu": ranga_strzalu,
            "komentarz": komentarz
        }
    )


# --- STRZAŁ Z POWIĄZANIEM USER_ID ---

@router.post("/hud/strzal", response_class=HTMLResponse)
async def proces_strzalu(
    aktywo: str = Form(...),
    interwal: str = Form(...),
    kierunek: str = Form(...),
    cena_wejscia: float = Form(...),
    kwota_pozycji: float = Form(...),
    kwota_ryzyka_usdc: Optional[float] = Form(None),
    procent_ryzyka: Optional[float] = Form(None),
    aktualne_rsi: float = Form(...),
    stop_loss: float = Form(...),
    poziom_halasu: str = Form(...),
    ranga_strzalu: str = Form(...),
    komentarz: Optional[str] = Form(None),
    session: Session = Depends(get_session),
    uzytkownik: Uzytkownik = Depends(get_current_user)  # ZEZWOLENIE Z SESJI
) -> HTMLResponse:
    print(f"[AUDYT] przychodząca kwota_pozycji: {kwota_pozycji}")
    if kwota_pozycji <= 0:
        return HTMLResponse(
            content="Błąd: Nieprawidłowa kwota pozycji!",
            headers={"HX-Retarget": "#error-message"}
        )

    if uzytkownik.kapital < kwota_pozycji:
        return HTMLResponse(
            content="Błąd: Brak funduszy na tę pozycję!",
            headers={"HX-Retarget": "#error-message"}
        )

    # Pobierz magazynek zalogowanego użytkownika
    magazynek = session.exec(select(Magazynek).where(Magazynek.uzytkownik_id == uzytkownik.id)).first()
    
    # Warunek bezpieczeństwa: czy jest magazynek i czy jest dostępna amunicja
    if not magazynek or magazynek.dostepna_amunicja < 1:
        return HTMLResponse(
            content="Błąd: Brak dostępnej amunicji!",
            headers={"HX-Retarget": "#error-message"}
        )

    uzytkownik.kapital -= kwota_pozycji
    session.add(uzytkownik)

    # Pomniejsz amunicję
    magazynek.dostepna_amunicja -= 1
    session.add(magazynek)

    nowa_transakcja = Transakcja(
        uzytkownik_id=uzytkownik.id,  # KLUCZOWE: Powiązanie z zalogowanym userem
        aktywo=aktywo,
        interwal=interwal,
        kierunek=kierunek,
        cena_wejscia=cena_wejscia,
        kwota_pozycji=kwota_pozycji,
        stop_loss=stop_loss,
        aktualne_rsi=aktualne_rsi,
        poziom_halasu=poziom_halasu,
        ranga_strzalu=ranga_strzalu,
        komentarz=komentarz,
        status_pozycji="OTWARTA"
    )

    session.add(nowa_transakcja)
    session.commit()

    trigger_toast = await utworz_log_i_toast(
        session,
        uzytkownik.id,
        f"⚡ Strzał oddany pomyślnie na aktywie {aktywo}!",
        "SUCCESS"
    )

    hx_location_config = {
        "path": "/auth/hud",
        "target": "#app-container",
        "swap": "innerHTML"
    }

    return HTMLResponse(
        content="",
        headers={
            "HX-Location": json.dumps(hx_location_config),
            "HX-Trigger": trigger_toast
        }
    )


# --- OBSŁUGA ROZLICZEŃ Z ZABEZPIECZENIEM ---

@router.post("/hud/pozycja/{id}/zamknij-widok", response_class=HTMLResponse)
async def wyswietl_zamknij_widok(
    id: int,
    request: Request,
    session: Session = Depends(get_session),
    uzytkownik: Uzytkownik = Depends(get_current_user)  # OBRONA PRZED INTRUZEM
) -> HTMLResponse:
    pozycja = session.get(Transakcja, id)
    
    # Defensywny warunek: nie pozwól zamknąć pozycji, jeśli nie należy do Ciebie!
    if not pozycja or pozycja.uzytkownik_id != uzytkownik.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Brak uprawnień.")
        
    return templates.TemplateResponse(request=request, name="zamknij_form.html", context={"pozycja": pozycja})


@router.post("/hud/pozycja/{id}/rozlicz", response_class=HTMLResponse)
async def rozlicz_pozycja(
    id: int,
    cena_wyjscia: float = Form(...),
    session: Session = Depends(get_session),
    uzytkownik: Uzytkownik = Depends(get_current_user)  # AUTORYZACJA
) -> HTMLResponse:
    transakcja = session.get(Transakcja, id)

    if not transakcja or transakcja.uzytkownik_id != uzytkownik.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Brak uprawnień.")

    zmiana = (cena_wyjscia - transakcja.cena_wejscia) / transakcja.cena_wejscia
    wynik_finansowy = transakcja.kwota_pozycji * zmiana if transakcja.kierunek.upper() == "LONG" else transakcja.kwota_pozycji * (-zmiana)

    # --- SYSTEM BLOKADY KARCERA (3 STRATY Z RZĘDU) ---
    if wynik_finansowy < 0:
        # Strata - zwiększamy licznik
        uzytkownik.licznik_prob = getattr(uzytkownik, 'licznik_prob', 0) + 1
        
        # Sprawdzamy, czy osiągnęliśmy limit 3 strat
        if uzytkownik.licznik_prob >= 3:
            uzytkownik.status_snajpera = 'BLOKADA'
            uzytkownik.blokada_do = datetime.utcnow() + timedelta(seconds=10)
    else:
        # Zysk lub wyjście na zero - resetujemy licznik
        uzytkownik.licznik_prob = 0
        uzytkownik.status_snajpera = 'CZUWANIE'
        uzytkownik.blokada_do = None

    transakcja.cena_wyjscia = cena_wyjscia
    transakcja.wynik_finansowy = round(wynik_finansowy, 2)
    transakcja.status_pozycji = "ZAMKNIETA"

    uzytkownik.kapital += (transakcja.kwota_pozycji + wynik_finansowy)

    session.add(transakcja)
    session.add(uzytkownik)
    session.commit()

    if transakcja.wynik_finansowy < 0:
        if uzytkownik.licznik_prob >= 3 and uzytkownik.status_snajpera == 'BLOKADA':
            trigger_toast = await utworz_log_i_toast(
                session,
                uzytkownik.id,
                "🚨 STRAŻNIK RYGORU: Terminal zablokowany po 3 stratach!",
                "DANGER"
            )
        else:
            trigger_toast = await utworz_log_i_toast(
                session,
                uzytkownik.id,
                f"📉 Pozycja zamknięta ze stratą: {transakcja.wynik_finansowy} USDC",
                "DANGER"
            )
    else:
        trigger_toast = await utworz_log_i_toast(
            session,
            uzytkownik.id,
            f"💰 Cel trafiony! Zysk Netto: +{transakcja.wynik_finansowy} USDC",
            "SUCCESS"
        )

    hx_location_config = {
        "path": "/auth/hud",
        "target": "#app-container",
        "swap": "innerHTML"
    }

    return HTMLResponse(
        content="",
        headers={
            "HX-Location": json.dumps(hx_location_config),
            "HX-Trigger": trigger_toast
        }
    )