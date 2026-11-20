from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..auth import current_user, user_dict
from ..db import get_session
from ..models import Order, User

router = APIRouter()


@router.get("/admin/users")
def list_users(user: User = Depends(current_user), s: Session = Depends(get_session)):
    # V4: BFLA - login check only, no role check
    rows = s.exec(select(User).order_by(User.id)).all()
    return {"items": [user_dict(u) for u in rows]}


@router.delete("/admin/users/{userId}")
def delete_user(userId: int, user: User = Depends(current_user), s: Session = Depends(get_session)):
    # V5: BFLA - login check only, no role check
    u = s.get(User, userId)
    if u is None:
        raise HTTPException(404, "not found")
    s.delete(u)
    s.commit()
    return {"deleted": userId}


@router.get("/admin/stats")
def stats(user: User = Depends(current_user), s: Session = Depends(get_session)):
    # correct: admin only
    if user.role != "admin":
        raise HTTPException(403, "admin only")
    return {
        "users": len(s.exec(select(User)).all()),
        "orders": len(s.exec(select(Order)).all()),
    }
