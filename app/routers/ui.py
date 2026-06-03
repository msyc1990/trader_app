from typing import Generator, Optional
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlmodel import Session, select

from app.database import get_session
from app.models import Uzytkownik, Transakcja

router = APIRouter(prefix="/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# PROFESJONALNA POPRAWKA: Ścieżka uwzględniająca folder app/
templates = Jinja2Templates(directory="app/app/templates" if False else "app/templates")


# --- ENDPOINTY GET (Wyświetlanie formularzy) ---

@router.get("/logowanie", response_class=HTMLResponse)
async def wyswietl_logowanie(request: Request) -> HTMLResponse:
    """Zwraca widok strony logowania."""
    return templates.TemplateResponse(
        request=request, 
        name="logowanie.html"
    )


@router.get("/rejestracja", response_class=HTMLResponse)
async def wyswietl_rejestracje(request: Request) -> HTMLResponse:
    """Zwraca widok strony rejestracji."""
    return templates.TemplateResponse(
        request=request, 
        name="rejestracja.html"
    )


# --- ENDPOINTY POST (Przetwarzanie danych z formularzy) ---

@router.post("/rejestracja", response_class=HTMLResponse)
async def proces_rejestracji(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    kapital: float = Form(...),
    session: Session = Depends(get_session)
) -> HTMLResponse:
    """Przetwarza formularz rejestracji, tworząc nowego użytkownika w bazie."""
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
    session.refresh(nowy_uzytkownik)

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
    """Weryfikuje dane logowania użytkownika."""
    statement = select(Uzytkownik).where(Uzytkownik.username == username)
    uzytkownik = session.exec(statement).first()

    if not uzytkownik or not pwd_context.verify(password, uzytkownik.password_hash):
        return HTMLResponse(
            content="Nieprawidłowa nazwa użytkownika lub hasło!",
            headers={"HX-Retarget": "#error-message"}
        )

    return HTMLResponse(
        content="",
        headers={"HX-Redirect": "/auth/hud"}
    )


# --- ZMODYFIKOWANY ENDPOINT HUD ---

@router.get("/hud", response_class=HTMLResponse)
async def wyswietl_hud(
    request: Request, 
    session: Session = Depends(get_session)
) -> HTMLResponse:
    """Pobiera użytkownika, otwarte pozycje oraz historię zamkniętych pozycji i wyświetla HUD."""
    # 1. Pobieranie użytkownika
    uzytkownik = session.exec(select(Uzytkownik)).first()
    
    if not uzytkownik:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Nie znaleziono żadnego użytkownika w bazie danych."
        )
    
    # 2. Pobieranie wszystkich otwartych pozycji (Nienaruszone)
    statement_pozycje = select(Transakcja).where(Transakcja.status_pozycji == 'OTWARTA')
    otwarte_pozycje = session.exec(statement_pozycje).all()
    
    # 3. NOWOŚĆ: Pobieranie historii zamkniętych pozycji
    statement_zamkniete = select(Transakcja).where(Transakcja.status_pozycji == 'ZAMKNIETA')
    zamkniete_pozycje = session.exec(statement_zamkniete).all()
        
    return templates.TemplateResponse(
        request=request,
        name="hud.html",
        context={
            "uzytkownik": uzytkownik,
            "pozycje": otwarte_pozycje,
            "historia": zamkniete_pozycje
        }
    )


# --- ENDPOINT KROK 2 (Wstrzykiwany dynamicznie przez HTMX) ---

@router.post("/hud/krok2", response_class=HTMLResponse)
async def proces_krok2(
    request: Request,
    aktywo: str = Form(...),
    interwal: str = Form(...),
    kierunek: str = Form(...)
) -> HTMLResponse:
    """Odbiera wstępne parametry transakcji z formularza HUD i renderuje krok 2."""
    return templates.TemplateResponse(
        request=request,
        name="krok2.html",
        context={
            "aktywo": aktywo,
            "interwal": interwal,
            "kierunek": kierunek
        }
    )


# --- ENDPOINT KROK 3 (Obliczenia obronne i podsumowanie) ---

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
    """Odbiera dane szczegółowe, wylicza automatyczny Stop Loss i renderuje krok 3."""
    if kierunek.upper() == "LONG":
        stop_loss = cena_wejscia * 0.98
    elif kierunek.upper() == "SHORT":
        stop_loss = cena_wejscia * 1.02
    else:
        stop_loss = cena_wejscia

    return templates.TemplateResponse(
        request=request,
        name="krok3.html",
        context={
            "aktywo": aktywo,
            "interwal": interwal,
            "kierunek": kierunek,
            "cena_wejscia": cena_wejscia,
            "kwota_pozycji": kwota_pozycji,
            "aktualne_rsi": aktualne_rsi,
            "stop_loss": round(stop_loss, 4)
        }
    )


# --- ENDPOINT KROK 4 (Ostateczna walidacja przed strzałem) ---

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
    """Zbiera absolutnie wszystkie parametry z poprzednich kroków i wyświetla krok 4."""
    return templates.TemplateResponse(
        request=request,
        name="krok4.html",
        context={
            "aktywo": aktywo,
            "interwal": interwal,
            "kierunek": kierunek,
            "cena_wejscia": cena_wejscia,
            "kwota_pozycji": kwota_pozycji,
            "aktualne_rsi": aktualne_rsi,
            "stop_loss": stop_loss,
            "poziom_halasu": poziom_halasu,
            "ranga_strzalu": ranga_strzalu,
            "komentarz": komentarz
        }
    )


# --- ENDPOINT: REJESTRACJA TRANSAKCJI (STRZAŁ) ---

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
    session: Session = Depends(get_session)
) -> HTMLResponse:
    """Finalizuje transakcję: sprawdza fundusze, aktualizuje kapitał i zapisuje pozycję."""
    uzytkownik = session.exec(select(Uzytkownik)).first()
    if not uzytkownik:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nie znaleziono żadnego użytkownika w bazie danych."
        )

    if uzytkownik.kapital < kwota_pozycji:
        return HTMLResponse(
            content="Błąd: Brak wystarczających funduszy (kapitału) na otwarcie tej pozycji!",
            headers={"HX-Retarget": "#error-message"}
        )

    uzytkownik.kapital -= kwota_pozycji
    session.add(uzytkownik)

    nowa_transakcja = Transakcja(
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

    return HTMLResponse(
        content="",
        headers={"HX-Redirect": "/auth/hud"}
    )


# --- ENDPOINT: FORMULARZ ZAMKNIĘCIA POZYCJI ---

@router.post("/hud/pozycja/{id}/zamknij-widok", response_class=HTMLResponse)
async def wyswietl_zamknij_widok(
    id: int,
    request: Request,
    session: Session = Depends(get_session)
) -> HTMLResponse:
    """Pobiera transakcję po ID i zwraca szablon formularza zamknięcia pozycji."""
    pozycja = session.get(Transakcja, id)
    
    if not pozycja:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Nie znaleziono transakcji o ID {id}."
        )
        
    return templates.TemplateResponse(
        request=request,
        name="zamknij_form.html",
        context={"pozycja": pozycja}
    )


# --- ENDPOINT: ROZLICZENIE TRANSAKCJI (FINISH) ---

@router.post("/hud/pozycja/{id}/rozlicz", response_class=HTMLResponse)
async def rozlicz_pozycja(
    id: int,
    cena_wyjscia: float = Form(...),
    session: Session = Depends(get_session)
) -> HTMLResponse:
    """Wylicza PnL zamkniętej pozycji, aktualizuje stan transakcji oraz kapitał tradera."""
    transakcja = session.get(Transakcja, id)
    uzytkownik = session.exec(select(Uzytkownik)).first()

    if not transakcja:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Nie znaleziono transakcji o ID {id}."
        )
    if not uzytkownik:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nie znaleziono użytkownika dla rozliczenia kapitału."
        )

    zmiana = (cena_wyjscia - transakcja.cena_wejscia) / transakcja.cena_wejscia

    if transakcja.kierunek.upper() == "LONG":
        wynik_finansowy = transakcja.kwota_pozycji * zmiana
    elif transakcja.kierunek.upper() == "SHORT":
        wynik_finansowy = transakcja.kwota_pozycji * (-zmiana)
    else:
        wynik_finansowy = 0.0

    transakcja.cena_wyjscia = cena_wyjscia
    transakcja.wynik_finansowy = round(wynik_finansowy, 2)
    transakcja.status_pozycji = "ZAMKNIETA"

    uzytkownik.kapital += (transakcja.kwota_pozycji + wynik_finansowy)

    session.add(transakcja)
    session.add(uzytkownik)
    session.commit()

    return HTMLResponse(
        content="",
        headers={"HX-Redirect": "/auth/hud"}
    )