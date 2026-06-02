from typing import Generator  # <-- Tego importu nam brakowało!
from sqlmodel import SQLModel, create_engine, Session

# Zmieniamy ścieżkę tak, aby plik bazy danych tworzył się w katalogu głównym projektu
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

# check_same_thread=False jest wymagane tylko dla SQLite w aplikacjach wielowątkowych
connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, echo=True, connect_args=connect_args)

def create_db_and_tables() -> None:
    """Tworzy plik bazy danych oraz wszystkie tabele zdefiniowane w models.py."""
    SQLModel.metadata.create_all(engine)

def get_session() -> Generator:
    """Generator sesji bazy danych dla wstrzykiwania zależności w FastAPI."""
    with Session(engine) as session:
        yield session