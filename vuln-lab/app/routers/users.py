from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlmodel import Session, select

from ..auth import current_user, user_dict
from ..db import get_session
from ..models import Order, User

router = APIRouter()


class ProfileUpdate(BaseModel):
    # V7: only displayName is declared, but extra fields are accepted ...
    model_config = ConfigDict(extra="allow")
    displayName: str | None = None


@router.get("/me")
def me(user: User = Depends(current_user)):
    return user_dict(user)


@router.get("/me/orders")
def my_orders(user: User = Depends(current_user), s: Session = Depends(get_session)):
    rows = s.exec(select(Order).where(Order.ownerId == user.id).order_by(Order.id)).all()
    return {"items": [o.model_dump() for o in rows]}


# NOTE: /users/me routes must come before /users/{userId}
@router.get("/users/me")
def users_me(user: User = Depends(current_user)):
    return user_dict(user)


@router.put("/users/me")
def update_me(
    body: ProfileUpdate,
    user: User = Depends(current_user),
    s: Session = Depends(get_session),
):
    # V7: ... and every provided field that matches a column (e.g. `role`) is written.
    for key, value in body.model_dump(exclude_unset=True).items():
        if key in User.model_fields and key != "id":
            setattr(user, key, value)
    user.updatedAt = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    s.add(user)
    s.commit()
    s.refresh(user)
    return user_dict(user)


@router.get("/users/{userId}/profile")
def profile(userId: int, s: Session = Depends(get_session)):
    # V6: no authentication at all.
    u = s.get(User, userId)
    if u is None:
        raise HTTPException(404, "not found")
    return {"userId": u.id, "displayName": u.displayName, "email": u.email}


@router.get("/users/{userId}")
def get_user(userId: int, user: User = Depends(current_user), s: Session = Depends(get_session)):
    # owner/admin check is correct, but V8: passwordHash is returned.
    if user.id != userId and user.role != "admin":
        raise HTTPException(403, "forbidden")
    u = s.get(User, userId)
    if u is None:
        raise HTTPException(404, "not found")
    return user_dict(u, with_hash=True)
