#!/usr/bin/env bash
# verify_matrix.sh: Part 4 / Step 6
# Exercises role x sensitivity x ownership x tenant against /api/documents/.
#
# Usage:
#   read -rs SV_TEST_PASSWORD; export SV_TEST_PASSWORD   # password seed_rbac_users set
#   ./verify_matrix.sh
#
# Requires: curl, jq, dev server running (python manage.py runserver)
# Assumes the list endpoint returns a plain JSON array (no pagination).

BASE="${BASE:-http://127.0.0.1:8000}"
PASSWORD="${SV_TEST_PASSWORD:?set SV_TEST_PASSWORD (the password seed_rbac_users gave the test users)}"
TENANT_A="5afd53de-3ba4-4506-ba69-d71b43cbc38e"
TENANT_B="3ca0886e-105b-48c7-8f3f-9a41336bfd4b"
D="/api/documents"

for dep in curl jq; do
  command -v "$dep" >/dev/null || { echo "missing dependency: $dep (sudo apt install -y $dep)"; exit 1; }
done

TMP="$(mktemp)"
PASS=0
FAIL=0

# ---------- helpers ----------

# api TOKEN METHOD PATH [JSON]  -> prints HTTP status; response body is left in $TMP
api() {
  local tok="$1" method="$2" path="$3" data="${4:-}"
  local args=(-s -o "$TMP" -w '%{http_code}' -X "$method" "$BASE$path")
  [[ -n "$tok" ]] && args+=(-H "Authorization: Bearer $tok")
  [[ -n "$data" ]] && args+=(-H "Content-Type: application/json" -d "$data")
  curl "${args[@]}"
}

login() {
  local tok
  tok=$(curl -s -X POST "$BASE/api/token/" -H "Content-Type: application/json" \
        -d "$(jq -n --arg u "$1" --arg p "$PASSWORD" '{username:$u,password:$p}')" \
        | jq -r '.access // empty')
  [[ -n "$tok" ]] || { echo "login failed for $1" >&2; return 1; }
  echo "$tok"
}

# mkdoc TOKEN TITLE SENSITIVITY -> prints new document id
mkdoc() {
  local code
  code=$(api "$1" POST "$D/" "$(jq -n --arg t "$2" --arg s "$3" '{title:$t,content:"matrix seed",sensitivity:$s}')")
  if [[ "$code" != "201" ]]; then
    echo "seed failed ($2): HTTP $code" >&2
    cat "$TMP" >&2
    return 1
  fi
  jq -r .id "$TMP"
}

# listed TOKEN ID -> yes|no  (is the document in this user's list response?)
listed() {
  api "$1" GET "$D/" >/dev/null
  jq -r --arg id "$2" 'if any(.[]; .id==$id) then "yes" else "no" end' "$TMP"
}

# check LABEL EXPECTED ACTUAL
check() {
  if [[ "$2" == "$3" ]]; then
    PASS=$((PASS + 1))
    printf '  \033[32mPASS\033[0m  %-54s expected=%-4s got=%s\n' "$1" "$2" "$3"
  else
    FAIL=$((FAIL + 1))
    printf '  \033[31mFAIL\033[0m  %-54s expected=%-4s got=%s\n' "$1" "$2" "$3"
  fi
}

cleanup() {
  local tok id
  for tok in "$ADM_A" "$ADM_B"; do
    [[ -n "$tok" ]] || continue
    api "$tok" GET "$D/" >/dev/null
    for id in $(jq -r '.[]? | select(.title|startswith("MATRIX:")) | .id' "$TMP" 2>/dev/null); do
      api "$tok" DELETE "$D/$id/" >/dev/null
    done
  done
  rm -f "$TMP"
}

# ---------- setup ----------

ADM_A=""; ADM_B=""
trap cleanup EXIT

ADM_A=$(login admin_a)  || exit 1
MEM_A=$(login member_a) || exit 1
VIE_A=$(login viewer_a) || exit 1
ADM_B=$(login admin_b)  || exit 1
MEM_B=$(login member_b) || exit 1

A_ADM_PUB=$(mkdoc "$ADM_A" "MATRIX: admin_a PUBLIC" PUBLIC)
A_ADM_INT=$(mkdoc "$ADM_A" "MATRIX: admin_a INTERNAL" INTERNAL)
A_ADM_CONF=$(mkdoc "$ADM_A" "MATRIX: admin_a CONFIDENTIAL" CONFIDENTIAL)
A_MEM_INT=$(mkdoc "$MEM_A" "MATRIX: member_a INTERNAL" INTERNAL)
A_MEM_CONF=$(mkdoc "$MEM_A" "MATRIX: member_a CONFIDENTIAL" CONFIDENTIAL)
B_ADM_PUB=$(mkdoc "$ADM_B" "MATRIX: admin_b PUBLIC" PUBLIC)

for v in A_ADM_PUB A_ADM_INT A_ADM_CONF A_MEM_INT A_MEM_CONF B_ADM_PUB; do
  [[ -n "${!v}" ]] || { echo "seeding failed ($v empty); aborting"; exit 1; }
done

EDIT='{"title":"MATRIX: edited"}'
NEWDOC='{"title":"MATRIX: create probe","content":"x","sensitivity":"CONFIDENTIAL"}'

# ---------- 1. detail reads ----------
echo; echo "== 1. Detail reads: GET /{id}/ =="
check "admin_a  reads member_a CONFIDENTIAL"             200 "$(api "$ADM_A" GET "$D/$A_MEM_CONF/")"
check "admin_a  reads admin_a CONFIDENTIAL"              200 "$(api "$ADM_A" GET "$D/$A_ADM_CONF/")"
check "member_a reads admin_a PUBLIC"                    200 "$(api "$MEM_A" GET "$D/$A_ADM_PUB/")"
check "member_a reads admin_a INTERNAL"                  200 "$(api "$MEM_A" GET "$D/$A_ADM_INT/")"
check "member_a reads admin_a CONFIDENTIAL (not owner)"  404 "$(api "$MEM_A" GET "$D/$A_ADM_CONF/")"
check "member_a reads own CONFIDENTIAL"                  200 "$(api "$MEM_A" GET "$D/$A_MEM_CONF/")"
check "viewer_a reads admin_a PUBLIC"                    200 "$(api "$VIE_A" GET "$D/$A_ADM_PUB/")"
check "viewer_a reads admin_a INTERNAL"                  200 "$(api "$VIE_A" GET "$D/$A_ADM_INT/")"
check "viewer_a reads admin_a CONFIDENTIAL"              404 "$(api "$VIE_A" GET "$D/$A_ADM_CONF/")"
check "viewer_a reads member_a CONFIDENTIAL"             404 "$(api "$VIE_A" GET "$D/$A_MEM_CONF/")"

# ---------- 2. list visibility ----------
echo; echo "== 2. List visibility: GET /documents/ =="
check "admin_a  list contains member_a CONFIDENTIAL"     yes "$(listed "$ADM_A" "$A_MEM_CONF")"
check "member_a list contains admin_a INTERNAL"          yes "$(listed "$MEM_A" "$A_ADM_INT")"
check "member_a list contains admin_a CONFIDENTIAL"      no  "$(listed "$MEM_A" "$A_ADM_CONF")"
check "member_a list contains own CONFIDENTIAL"          yes "$(listed "$MEM_A" "$A_MEM_CONF")"
check "viewer_a list contains admin_a PUBLIC"            yes "$(listed "$VIE_A" "$A_ADM_PUB")"
check "viewer_a list contains member_a CONFIDENTIAL"     no  "$(listed "$VIE_A" "$A_MEM_CONF")"
check "viewer_a list contains admin_a CONFIDENTIAL"      no  "$(listed "$VIE_A" "$A_ADM_CONF")"

# ---------- 3. cross-tenant ----------
echo; echo "== 3. Cross-tenant isolation =="
check "admin_a  GET Tenant B doc"                        404 "$(api "$ADM_A" GET "$D/$B_ADM_PUB/")"
check "admin_a  list contains Tenant B doc"              no  "$(listed "$ADM_A" "$B_ADM_PUB")"
check "member_b GET Tenant A PUBLIC doc"                 404 "$(api "$MEM_B" GET "$D/$A_ADM_PUB/")"
check "admin_b  GET Tenant A member CONFIDENTIAL"        404 "$(api "$ADM_B" GET "$D/$A_MEM_CONF/")"
check "admin_a  PATCH Tenant B doc"                      404 "$(api "$ADM_A" PATCH "$D/$B_ADM_PUB/" "$EDIT")"
check "admin_a  DELETE Tenant B doc"                     404 "$(api "$ADM_A" DELETE "$D/$B_ADM_PUB/")"

# ---------- 4. create ----------
echo; echo "== 4. Create: POST =="
check "member_a POST (CONFIDENTIAL allowed)"             201 "$(api "$MEM_A" POST "$D/" "$NEWDOC")"
check "viewer_a POST"                                    403 "$(api "$VIE_A" POST "$D/" "$NEWDOC")"

# ---------- 5. update ----------
echo; echo "== 5. Update: PATCH =="
check "admin_a  PATCH member_a INTERNAL"                 200 "$(api "$ADM_A" PATCH "$D/$A_MEM_INT/" "$EDIT")"
check "admin_a  PATCH member_a CONFIDENTIAL"             200 "$(api "$ADM_A" PATCH "$D/$A_MEM_CONF/" "$EDIT")"
check "member_a PATCH own INTERNAL"                      200 "$(api "$MEM_A" PATCH "$D/$A_MEM_INT/" "$EDIT")"
check "member_a PATCH admin_a PUBLIC (not owner)"        403 "$(api "$MEM_A" PATCH "$D/$A_ADM_PUB/" "$EDIT")"
check "member_a PATCH admin_a INTERNAL (not owner)"      403 "$(api "$MEM_A" PATCH "$D/$A_ADM_INT/" "$EDIT")"
check "member_a PATCH admin_a CONFIDENTIAL (hidden)"     404 "$(api "$MEM_A" PATCH "$D/$A_ADM_CONF/" "$EDIT")"
check "viewer_a PATCH admin_a PUBLIC"                    403 "$(api "$VIE_A" PATCH "$D/$A_ADM_PUB/" "$EDIT")"

# ---------- 6. delete ----------
echo; echo "== 6. Delete: DELETE =="
TMP1=$(mkdoc "$MEM_A" "MATRIX: tmp member 1" INTERNAL)
TMP2=$(mkdoc "$MEM_A" "MATRIX: tmp member 2" INTERNAL)
TMP3=$(mkdoc "$ADM_A" "MATRIX: tmp admin 3" PUBLIC)
check "viewer_a DELETE admin_a PUBLIC"                   403 "$(api "$VIE_A" DELETE "$D/$TMP3/")"
check "member_a DELETE admin_a PUBLIC (not owner)"       403 "$(api "$MEM_A" DELETE "$D/$TMP3/")"
check "member_a DELETE admin_a CONFIDENTIAL (hidden)"    404 "$(api "$MEM_A" DELETE "$D/$A_ADM_CONF/")"
check "member_a DELETE own doc"                          204 "$(api "$MEM_A" DELETE "$D/$TMP1/")"
check "admin_a  DELETE member_a doc"                     204 "$(api "$ADM_A" DELETE "$D/$TMP2/")"
check "admin_a  GET deleted doc (really gone)"           404 "$(api "$ADM_A" GET "$D/$TMP1/")"

# ---------- 7. tampering + unauthenticated ----------
echo; echo "== 7. Mass-assignment tampering + unauthenticated =="
api "$MEM_A" GET "$D/$A_MEM_INT/" >/dev/null
CREATED_BEFORE=$(jq -r .created_by "$TMP")
CODE=$(api "$MEM_A" PATCH "$D/$A_MEM_INT/" \
  "$(jq -n --arg t "$TENANT_B" '{title:"MATRIX: tamper",tenant:$t,created_by:"00000000-0000-0000-0000-000000000001"}')")
check "member_a PATCH own doc w/ tenant+created_by override" 200 "$CODE"
check "  ...tenant unchanged (still Tenant A)"          "$TENANT_A" "$(jq -r .tenant "$TMP")"
check "  ...created_by unchanged"                       "$CREATED_BEFORE" "$(jq -r .created_by "$TMP")"
check "no token: GET list"                               401 "$(api "" GET "$D/")"
check "no token: GET detail"                             401 "$(api "" GET "$D/$A_ADM_PUB/")"

# ---------- summary ----------
echo
echo "RESULT: $PASS passed, $FAIL failed (total $((PASS + FAIL)))"
[[ "$FAIL" -eq 0 ]]
