import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from ..auth import current_user
from ..db import get_session
from ..models import Order, User

router = APIRouter()


class NewOrder(BaseModel):
    item: str
    total: float


class NotePatch(BaseModel):
    note: str


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.post("/orders")
def create_order(body: NewOrder, user: User = Depends(current_user), s: Session = Depends(get_session)):
    # correct: owner comes from the token; any ownerId in the body is ignored
    o = Order(ownerId=user.id, item=body.item, total=body.total, updatedAt=_now())
    s.add(o)
    s.commit()
    s.refresh(o)
    return o.model_dump()


@router.get("/orders/{orderId}")
def get_order(orderId: int, user: User = Depends(current_user), s: Session = Depends(get_session)):
    # V1: BOLA - no ownership check
    o = s.get(Order, orderId)
    if o is None:
        raise HTTPException(404, "not found")
    return {**o.model_dump(), "requestId": str(uuid.uuid4())}


@router.patch("/orders/{orderId}")
def patch_order(orderId: int, body: NotePatch, user: User = Depends(current_user),
                s: Session = Depends(get_session)):
    # V2: BOLA on write - no ownership check
    o = s.get(Order, orderId)
    if o is None:
        raise HTTPException(404, "not found")
    o.note = body.note
    o.updatedAt = _now()
    s.add(o)
    s.commit()
    s.refresh(o)
    return o.model_dump()


@router.get("/orders/{orderId}/status")
def order_status(orderId: int, user: User = Depends(current_user), s: Session = Depends(get_session)):
    # correct: foreign orders look non-existent
    o = s.get(Order, orderId)
    if o is None or o.ownerId != user.id:
        raise HTTPException(404, "not found")
    return {"id": o.id, "status": "shipped"}
