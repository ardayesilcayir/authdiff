#!/usr/bin/env sh
# Prepare a local VAmPI (https://github.com/erev0s/VAmPI) for examples/vampi.yaml
# and print the token exports. Source it, do not run it in a subshell:
#
#   docker run -d --name vampi -p 127.0.0.1:5000:5000 erev0s/vampi:latest
#   . examples/vampi-setup.sh
#   authdiff scan -c examples/vampi.yaml
#
# It resets VAmPI's database (GET /createdb), logs in as VAmPI's seeded users
# (name1/pass1, name2/pass2, admin/pass1: VAmPI's public demo credentials),
# and adds one book with a known title per user, so that examples/vampi.yaml
# can list it under `owns`. Tokens live only in this shell's environment.
VAMPI_URL="${VAMPI_URL:-http://localhost:5000}"

# /createdb fails now and then (HTTP 500): VAmPI's seeded book titles are
# random and can collide. Retry a few times.
vampi_ok=""
for _ in 1 2 3 4 5; do
  if curl -fsS "$VAMPI_URL/createdb" >/dev/null 2>&1; then vampi_ok=1; break; fi
done
[ -n "$vampi_ok" ] || {
  echo "vampi-setup: GET $VAMPI_URL/createdb failed" >&2; return 1 2>/dev/null || exit 1
}

vampi_login() {
  curl -fsS -X POST "$VAMPI_URL/users/v1/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" |
    sed -n 's/.*"auth_token": *"\([^"]*\)".*/\1/p'
}

vampi_add_book() {
  curl -fsS -X POST "$VAMPI_URL/books/v1" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $1" \
    -d "{\"book_title\":\"$2\",\"secret\":\"secret of $2\"}" >/dev/null
}

VAMPI_ADMIN_TOKEN="$(vampi_login admin pass1)"
VAMPI_NAME1_TOKEN="$(vampi_login name1 pass1)"
VAMPI_NAME2_TOKEN="$(vampi_login name2 pass2)"
for t in "$VAMPI_ADMIN_TOKEN" "$VAMPI_NAME1_TOKEN" "$VAMPI_NAME2_TOKEN"; do
  [ -n "$t" ] || { echo "vampi-setup: login failed" >&2; return 1 2>/dev/null || exit 1; }
done
export VAMPI_ADMIN_TOKEN VAMPI_NAME1_TOKEN VAMPI_NAME2_TOKEN

vampi_add_book "$VAMPI_ADMIN_TOKEN" admin-book
vampi_add_book "$VAMPI_NAME1_TOKEN" name1-book
vampi_add_book "$VAMPI_NAME2_TOKEN" name2-book

echo "vampi-setup: database reset, VAMPI_*_TOKEN exported" >&2
