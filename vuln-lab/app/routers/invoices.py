from fastapi import APIRouter, Depends, HTTPException, Response
from sqlmodel import Session

from ..auth import current_user
from ..db import get_session
from ..models import Invoice, User

router = APIRouter()


def _esc(t: str) -> str:
    return t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf(lines: list[str]) -> bytes:
    """Minimal deterministic single-page PDF (no timestamps)."""
    text = "BT /F1 12 Tf 72 720 Td 14 TL " + " T* ".join(f"({_esc(l)}) Tj" for l in lines) + " ET"
    stream = text.encode("latin-1")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(out)


@router.get("/invoices/{invoiceId}/pdf")
def invoice_pdf(invoiceId: int, user: User = Depends(current_user), s: Session = Depends(get_session)):
    # V3: BOLA - no ownership check
    inv = s.get(Invoice, invoiceId)
    if inv is None:
        raise HTTPException(404, "not found")
    owner = s.get(User, inv.ownerId)
    email = owner.email if owner else "unknown"
    pdf = build_pdf([f"Invoice {inv.id}", f"Customer: {email}", f"Amount: {inv.amount:.2f}"])
    return Response(content=pdf, media_type="application/pdf")
