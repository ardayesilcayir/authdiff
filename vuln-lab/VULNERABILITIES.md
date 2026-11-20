---
expected:
  - id: V1
    rule: AD-BOLA-001
    method: GET
    path: /orders/{orderId}
    destructive: false
  - id: V2
    rule: AD-BOLA-002
    method: PATCH
    path: /orders/{orderId}
    destructive: true
  - id: V3
    rule: AD-BOLA-001
    method: GET
    path: /invoices/{invoiceId}/pdf
    destructive: false
  - id: V4
    rule: AD-BFLA-001
    method: GET
    path: /admin/users
    destructive: false
  - id: V5
    rule: AD-BFLA-001
    method: DELETE
    path: /admin/users/{userId}
    destructive: true
  - id: V6
    rule: AD-NOAUTH-001
    method: GET
    path: /users/{userId}/profile
    destructive: false
  - id: V7
    rule: AD-MASS-001
    method: PUT
    path: /users/me
    destructive: true
  - id: V8
    rule: AD-LEAK-001
    method: GET
    path: /users/{userId}
    destructive: false
negatives:
  - method: GET
    path: /orders/{orderId}/status
  - method: GET
    path: /products/{id}
  - method: GET
    path: /products
  - method: GET
    path: /me
  - method: GET
    path: /me/orders
  - method: GET
    path: /users/me
  - method: GET
    path: /admin/stats
  - method: POST
    path: /orders
---

# vuln-lab: expected findings

> **WARNING: do not run in production.** This API is deliberately vulnerable.
> Run it only on localhost, never expose it to a network.

The front-matter above is the oracle for the authdiff end-to-end test:
`expected` entries must be reported, `negatives` must produce no findings.

| ID | Rule | Endpoint | Description | Destructive |
|----|------|----------|-------------|-------------|
| V1 | AD-BOLA-001 | `GET /orders/{orderId}` | No ownership check; any user reads any order | no |
| V2 | AD-BOLA-002 | `PATCH /orders/{orderId}` | No ownership check; any user edits any order | yes |
| V3 | AD-BOLA-001 | `GET /invoices/{invoiceId}/pdf` | No ownership check; any user downloads any invoice PDF | no |
| V4 | AD-BFLA-001 | `GET /admin/users` | Login check only; no admin role check | no |
| V5 | AD-BFLA-001 | `DELETE /admin/users/{userId}` | Login check only; any user deletes users | yes |
| V6 | AD-NOAUTH-001 | `GET /users/{userId}/profile` | No authentication at all | no |
| V7 | AD-MASS-001 | `PUT /users/me` | Mass assignment: `role` in body is persisted | yes |
| V8 | AD-LEAK-001 | `GET /users/{userId}` | Response leaks `passwordHash` | no |

Correctly protected (must NOT be flagged): `GET /orders/{orderId}/status`,
`GET /products/{id}`, `GET /products`, `GET /me`, `GET /me/orders`,
`GET /users/me`, `GET /admin/stats`, `POST /orders`.
