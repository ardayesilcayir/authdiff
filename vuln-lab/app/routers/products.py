from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..db import get_session
from ..models import Product

router = APIRouter()


@router.get("/products")
def list_products(s: Session = Depends(get_session)):
    rows = s.exec(select(Product).order_by(Product.id)).all()
    return {"items": [p.model_dump() for p in rows]}


@router.get("/products/{id}")
def get_product(id: int, s: Session = Depends(get_session)):
    p = s.get(Product, id)
    if p is None:
        raise HTTPException(404, "not found")
    return p.model_dump()
