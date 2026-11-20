from typing import Optional

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    email: str
    role: str = "user"
    displayName: str = ""
    passwordHash: str = ""
    updatedAt: str = "2026-01-01T00:00:00Z"


class Order(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ownerId: int
    item: str
    total: float
    note: str = ""
    updatedAt: str = "2026-01-01T00:00:00Z"


class Invoice(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ownerId: int
    amount: float


class Product(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    price: float
