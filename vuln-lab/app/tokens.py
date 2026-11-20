"""Deterministic lab-only JWTs (HS256, fixed secret, no exp)."""
import jwt

SECRET = "vuln-lab-insecure-secret"
USERS = [("ADMIN", 1, "admin"), ("ALICE", 2, "alice"), ("BOB", 3, "bob")]


def make_token(user_id: int, name: str) -> str:
    return jwt.encode({"sub": str(user_id), "name": name}, SECRET, algorithm="HS256")


def token_lines() -> list[str]:
    return [f"{label}_TOKEN={make_token(uid, name)}" for label, uid, name in USERS]


if __name__ == "__main__":
    print("\n".join(token_lines()))
