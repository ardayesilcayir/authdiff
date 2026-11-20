from sqlmodel import Session

from .models import Invoice, Order, Product, User

TS = "2026-01-01T00:00:00Z"


def seed(s: Session) -> None:
    s.add_all(
        [
            User(id=1, username="admin", email="admin@vuln.lab", role="admin",
                 displayName="admin", passwordHash="$lab$admin-fake-hash", updatedAt=TS),
            User(id=2, username="alice", email="alice@vuln.lab", role="user",
                 displayName="alice", passwordHash="$lab$alice-fake-hash", updatedAt=TS),
            User(id=3, username="bob", email="bob@vuln.lab", role="user",
                 displayName="bob", passwordHash="$lab$bob-fake-hash", updatedAt=TS),
        ]
    )
    for oid, owner, item, total in [
        (11, 1, "admin-widget-a", 10.0),
        (12, 1, "admin-widget-b", 20.0),
        (101, 2, "alice-book", 15.5),
        (102, 2, "alice-lamp", 42.0),
        (201, 3, "bob-keyboard", 99.9),
        (202, 3, "bob-mouse", 25.0),
    ]:
        s.add(Order(id=oid, ownerId=owner, item=item, total=total,
                    note="initial note", updatedAt=TS))
    s.add_all(
        [
            Invoice(id=9000, ownerId=1, amount=30.0),
            Invoice(id=9001, ownerId=2, amount=57.5),
            Invoice(id=9002, ownerId=3, amount=124.9),
            Product(id=1, name="Widget", price=9.99),
            Product(id=2, name="Gadget", price=19.99),
            Product(id=3, name="Gizmo", price=29.99),
        ]
    )
    s.commit()
