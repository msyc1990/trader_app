from typing import Generator
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlmodel import Session, select

# Założenie: Twoja konfiguracja bazy danych i modele znajdują się w tych ścieżkach
from app.database import get_session
from app.models import Uzytkownik

# Inicjalizacja routera z odpowiednim prefiksem i tagami
router = APIRouter(prefix="/auth", tags=["auth"])

# Konfiguracja bezpiecznego haszowania haseł za pomocą bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Konfiguracja szablonów Jinja2 (zakładamy katalog 'templates' w głównym folderze)
templates = Jinja2Templates(directory="app/templates")


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
    # 1. Sprawdzenie, czy użytkownik o podanym username już istnieje
    statement = select(Uzytkownik).where(Uzytkownik.username == username)
    istniejacy_uzytkownik = session.exec(statement).first()

    if istniejacy_uzytkownik:
        # Jeśli użytkownik istnieje, zwracamy ten sam szablon z komunikatem błędu
        return templates.TemplateResponse(
            request=request,
            name="rejestracja.html",
            context={"error": "Użytkownik o takiej nazwie już istnieje!"}
        )

    # 2. Haszowanie hasła i tworzenie nowego obiektu
    hashed_password = pwd_context.hash(password)
    nowy_uzytkownik = Uzytkownik(
        username=username,
        password_hash=hashed_password,
        kapital=kapital
    )

    # 3. Zapis do bazy danych
    session.add(nowy_uzytkownik)
    session.commit()
    session.refresh(nowy_uzytkownik)

    # 4. Przekierowanie do logowania lub ekranu głównego (HUD) po sukcesie
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
    # 1. Wyszukanie użytkownika w bazie
    statement = select(Uzytkownik).where(Uzytkownik.username == username)
    uzytkownik = session.exec(statement).first()

    # 2. Weryfikacja istnienia użytkownika oraz poprawności zahaszowanego hasła
    if not uzytkownik or not pwd_context.verify(password, uzytkownik.password_hash):
        return templates.TemplateResponse(
            request=request,
            name="logowanie.html",
            context={"error": "Nieprawidłowa nazwa użytkownika lub hasło!"}
        )

    # 3. Autoryzacja udana - przekierowanie do HUD (ekranu głównego aplikacji)
    # Status 303 See Other jest zalecany przy przekierowaniach z metod POST
    return RedirectResponse(
        url="/auth/hud", 
        status_code=status.HTTP_303_SEE_OTHER
    )


# --- NOWY ENDPOINT HUD ---

@router.get("/hud", response_class=HTMLResponse)
async def wyswietl_hud(
    request: Request, 
    session: Session = Depends(get_session)
) -> HTMLResponse:
    """Pobiera pierwszego użytkownika z bazy danych i wyświetla panel główny HUD."""
    uzytkownik = session.exec(select(Uzytkownik)).first()
    
    # Dodanie zabezpieczenia na wypadek braku użytkowników w bazie
    if not uzytkownik:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Nie znaleziono żadnego użytkownika w bazie danych."
        )
        
    return templates.TemplateResponse(
        request=request,
        name="hud.html",
        context={"uzytkownik": uzytkownik}
    )