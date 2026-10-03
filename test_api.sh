#!/bin/bash
ACCESS=$(curl -s -X POST http://localhost:8000/api/token/ -H "Content-Type: application/json" -d '{"username": "admin_a", "password": "'"${TEST_PASSWORD:-testpass123}"'"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")

echo "--- GET as admin_a ---"
curl -s http://localhost:8000/api/documents/ -H "Authorization: Bearer $ACCESS"
echo

echo "--- POST as admin_a (create CONFIDENTIAL doc) ---"
curl -s -X POST http://localhost:8000/api/documents/ -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" -d '{"title": "Admin A Test Doc", "content": "hello", "sensitivity": "CONFIDENTIAL"}'
echo

echo "--- POST as admin_a, tenant override attempt (IDOR check) ---"
curl -s -X POST http://localhost:8000/api/documents/ -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" -d '{"title": "Hijack Attempt", "content": "x", "tenant": "3ca0886e-105b-48c7-8f3f-9a41336bfd4b"}'
echo

ACCESS_B=$(curl -s -X POST http://localhost:8000/api/token/ -H "Content-Type: application/json" -d '{"username": "member_b", "password": "'"${TEST_PASSWORD:-testpass123}"'"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")

echo "--- GET as member_b (should see nothing from Tenant A) ---"
curl -s http://localhost:8000/api/documents/ -H "Authorization: Bearer $ACCESS_B"
echo

ACCESS_V=$(curl -s -X POST http://localhost:8000/api/token/ -H "Content-Type: application/json" -d '{"username": "viewer_a", "password": "'"${TEST_PASSWORD:-testpass123}"'"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")

echo "--- POST as viewer_a (should be 403) ---"
curl -s -w "\nHTTP_STATUS:%{http_code}\n" -X POST http://localhost:8000/api/documents/ -H "Authorization: Bearer $ACCESS_V" -H "Content-Type: application/json" -d '{"title": "Viewer Attempt", "content": "x"}'

echo "--- GET as viewer_a (should now be 200) ---"
curl -s -w "\nHTTP_STATUS:%{http_code}\n" http://localhost:8000/api/documents/ -H "Authorization: Bearer $ACCESS_V"
