"""SQLite in-memory database (shared single connection via StaticPool)."""
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


def init_db() -> None:
    """Drop, recreate and seed everything. Called on every app start."""
    from . import models  # noqa: F401  (register tables)
    from .seed import seed

    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        seed(s)


def get_session():
    with Session(engine) as s:
        yield s
