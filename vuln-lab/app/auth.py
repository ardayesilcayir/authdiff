import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session

from .db import get_session
from .models import User
from .tokens import SECRET

bearer = HTTPBearer()  # shows up as `security` in /openapi.json


def current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    session: Session = Depends(get_session),
) -> User:
    try:
        claims = jwt.decode(creds.credentials, SECRET, algorithms=["HS256"])
        user = session.get(User, int(claims["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        user = None
    if user is None:
        raise HTTPException(status_code=401, detail="invalid token")
    return user


def user_dict(u: User, with_hash: bool = False) -> dict:
    d = {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "displayName": u.displayName,
        "updatedAt": u.updatedAt,
    }
    if with_hash:
        d["passwordHash"] = u.passwordHash
    return d
