from typing import Generator, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import Signer, BadSignature
from passlib.context import CryptContext
from sqlmodel import Session, select

from app.database import get_session
from app.models import Uzytkownik, Transakcja

SECRET_KEY = "twoj-bardzo-tajny-klucz-snajpera"
signer = Signer(SECRET_KEY)

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


# --- BEZPIECZNY ENDPOINT HUD (POWIĄZANY Z SESJĄ) ---

@router.get("/hud", response_class=HTMLResponse)
async def wyswietl_hud(
    request: Request, 
    session: Session = Depends(get_session),
    uzytkownik: Uzytkownik = Depends(get_current_user)  # WTRZYKNIĘCIE SESJI
) -> HTMLResponse:
    """Pobiera zalogowanego użytkownika, JEGO pozycje oraz JEGO historię."""
    
    # Sprawdzenie aktywnej blokady
    if uzytkownik.blokada_do:
        if datetime.utcnow() > uzytkownik.blokada_do:
            # Czas blokady minął - automatyczne ułaskawienie
            uzytkownik.status_snajpera = "CZUWANIE"
            uzytkownik.blokada_do = None
            uzytkownik.licznik_prob = 0
            session.add(uzytkownik)
            session.commit()
    
    # Filtrowanie aktywnych pozycji należących tylko do zalogowanego użytkownika
    statement_pozycje = select(Transakcja).where(
        Transakcja.status_pozycji == 'OTWARTA',
        Transakcja.uzytkownik_id == uzytkownik.id
    )
    otwarte_pozycje = session.exec(statement_pozycje).all()
    
    # Filtrowanie zamkniętych pozycji należących tylko do zalogowanego użytkownika
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
        
    return templates.TemplateResponse(
        request=request,
        name="hud.html",
        context={
            "uzytkownik": uzytkownik,
            "pozycje": otwarte_pozycje,
            "historia": zamkniete_pozycje,
            "total_pnl": round(total_pnl, 2),
            "win_rate": win_rate,
            "laczna_liczba_strzalow": laczna_liczba_strzalow
        }
    )


# --- DYNAMICZNE FORMULARZE RYGORU (BEZMIAN) ---

@router.post("/hud/krok2", response_class=HTMLResponse)
async def proces_krok2(
    request: Request,
    aktywo: str = Form(...),
    interwal: str = Form(...),
    kierunek: str = Form(...)
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="krok2.html",
        context={"aktywo": aktywo, "interwal": interwal, "kierunek": kierunek}
    )


@router.post("/hud/krok3", response_class=HTMLResponse)
async def proces_krok3(
    request: Request,
    aktywo: str = Form(...),
    interwal: str = Form(...),
    kierunek: str = Form(...),
    cena_wejscia: float = Form(...),
    kwota_pozycji: float = Form(...),
    aktualne_rsi: float = Form(...)
) -> HTMLResponse:
    stop_loss = cena_wejscia * 0.98 if kierunek.upper() == "LONG" else cena_wejscia * 1.02
    return templates.TemplateResponse(
        request=request,
        name="krok3.html",
        context={
            "aktywo": aktywo, "interwal": interwal, "kierunek": kierunek,
            "cena_wejscia": cena_wejscia, "kwota_pozycji": kwota_pozycji,
            "aktualne_rsi": aktualne_rsi, "stop_loss": round(stop_loss, 4)
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
    aktualne_rsi: float = Form(...),
    stop_loss: float = Form(...),
    poziom_halasu: str = Form(...),
    ranga_strzalu: str = Form(...),
    komentarz: Optional[str] = Form(None),
    session: Session = Depends(get_session),
    uzytkownik: Uzytkownik = Depends(get_current_user)  # ZEZWOLENIE Z SESJI
) -> HTMLResponse:
    if uzytkownik.kapital < kwota_pozycji:
        return HTMLResponse(
            content="Błąd: Brak funduszy na tę pozycję!",
            headers={"HX-Retarget": "#error-message"}
        )

    uzytkownik.kapital -= kwota_pozycji
    session.add(uzytkownik)

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

    return HTMLResponse(content="", headers={"HX-Redirect": "/auth/hud"})


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
            uzytkownik.blokada_do = datetime.utcnow() + timedelta(hours=24)
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

    return HTMLResponse(content="", headers={"HX-Redirect": "/auth/hud"})