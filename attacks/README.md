# Attacks — build & run

Lab recap (from the provided `docker-compose.yml`):

```bash
docker compose up as3_server          # terminal 1 — server on :9000
docker compose run --rm bob           # terminal 2 — register + publish bundle FIRST
docker compose run --rm alice         # terminal 3 — sends first
# reset client state between attacks:
docker volume rm as3state             # (or: docker compose down -v)
```

All attacks are plain C++17, no external dependencies.

```bash
g++ -O2 -std=c++17 -o attack0 attack0.cpp -lpthread
g++ -O2 -std=c++17 -o attack1 attack1.cpp -lpthread
# attack2 uses OpenSSL (X25519 / HKDF / HMAC / ChaCha20-Poly1305):
g++ -O2 -std=c++17 -o attack2 attack2.cpp -lpthread -lcrypto
```

Attack 0 and Attack 1 have no external dependencies. Attack 2 links OpenSSL
(`libssl-dev`); it is the only attack that needs it, because it reimplements the client
crypto to decrypt/re-encrypt intercepted traffic.

---

## Attack 0 — header counter manipulation + mailbox flood  [owner: 23b1075]

`attack0.cpp` has two modes.

### Mode 1: MITM counter tamper (result: PREVENTED by header authentication)

Mallory is a transparent TCP proxy between Bob and the server. She forwards traffic
unchanged except that, in every delivered `Frame` (including every frame inside a
multi-frame poll response), she rewrites the header's message number `n` to `real_n +
gap`. The hypothesis was that the receiver derives/stores skipped keys before the AEAD
check (`protocol.md` §4.4) → CPU/memory DoS.

**Measured outcome:** it does NOT work. The header is bound as AEAD associated data, and
the implementation authenticates before any skipped-key work, so every forged frame is
rejected with `DECRYPT FAIL … AEAD authentication failed` — using *less* CPU than a real
message. Tested up to gap=5000 (5× MAX_SKIP): flat/below-baseline CPU and memory, no
`too many skipped` error. This is the "report that the attack is prevented and explain
why" case.

```bash
# 1) Mallory on the as3net network, pointing at the real server
docker run -d --name mallory --network as3net -v "$PWD/build:/b" debian:stable-slim \
    /b/mallory --listen 0.0.0.0:9100 --server as3_server:9000 --gap 1000
# 2) Bob pointed at Mallory instead of the server
docker run -d -i --name bob --network as3net -e USER_NAME=bob -e STATE_DIR=/state \
    --entrypoint /client s4ch1n/as3:latest --server-addr mallory --port 9100
# 3) Alice sends normally (direct to server); Bob logs DECRYPT FAIL, CPU/mem stay flat
```

### Mode 2: mailbox flood (result: the real availability DoS)

Since the header path is safe, Mode 2 exploits the real flaw: `send` has **no
per-mailbox quota and no rate limit**. The server does reject a spoofed `from`
(`{"err":"bad sender"}`), so Mallory registers first, then enqueues unlimited junk
frames into Bob's mailbox. Server memory grows linearly and without bound.

```bash
docker run --rm --network as3net -v "$PWD/build:/b" debian:stable-slim \
    /b/mallory --flood-mailbox --server as3_server:9000 --as evil --target bob --count 100000
# measured: server RSS 1.3 MiB -> 25.7 MiB per 100k frames, ~0.7s; 400k -> 167 MiB
```

### Build (Linux container, for running on as3net)

```bash
docker run --rm -v "$PWD:/src" gcc:13 \
    bash -c "g++ -O2 -std=c++17 -static -o /src/build/mallory /src/attack0.cpp -lpthread"
```

### Measurement + plots

```bash
# from the submission root: runs both experiments and writes results/*.csv
bash scripts/run_attack0_experiments.sh
python3 scripts/plot_attack0.py       # writes results/*.png from the measured CSVs
```

Real data and figures are committed under `results/`.

---

## Attack 1 — one-time prekey exhaustion ("Prekey Pogo")  [owner: 23b1057]

A malicious ordinary client drains Bob's one-time-prekey inventory with unauthenticated,
unrate-limited `fetch_bundle` requests (one OPK consumed per fetch), then shows that no
new session can be started with Bob until he republishes.

```bash
docker run --rm --network as3net -v "$PWD/build:/b" debian:stable-slim \
    /b/attack1 --server as3_server:9000 --target bob
# measured: 5 OPKs drained in one burst -> fetch_bundle refused; a fresh client (Carol)
# can no longer start a session with bob (results/attack1_drain.txt)
```

## Attack 2 — malicious-server MITM / key substitution  [owner: 23b1057]

A **malicious server** (Mallory) exploits the unverified signed-prekey signature: when an
initiator fetches a peer's bundle she substitutes her own identity/prekeys, establishes
separate Double-Ratchet sessions with each side, decrypts every message, and re-encrypts
it for the other party — a transparent MITM. Point **both** clients at Mallory
(`--server-addr mallory --port 9000`). Three modes produce the three required evidence
classes:

```bash
# transparent MITM: recover plaintext AND forward so both sides see a working session
docker run -d --name mallory --network as3net -v "$PWD/build:/b" debian:stable-slim \
    /b/attack2 --listen 0.0.0.0:9000 --mode reencrypt
#   --mode honest : relay e2e ciphertext unchanged (server cannot read it) — the baseline
#   --mode raw    : substitute+decrypt but relay Alice's original ct -> Bob's decrypt FAILS
# evidence: results/attack2_evidence.txt
```

### Build (Linux container, for running on as3net)

```bash
docker run --rm -v "$PWD:/src" gcc:13 bash -c \
    "g++ -O2 -std=c++17 -static -o /src/build/attack1 /src/attack1.cpp -lpthread"
docker run --rm -v "$PWD:/src" gcc:13 bash -c \
    "apt-get update -qq && apt-get install -y -qq libssl-dev && \
     g++ -O2 -std=c++17 -static -o /src/build/attack2 /src/attack2.cpp -lssl -lcrypto -lpthread -ldl"
```

### Measurement + evidence

```bash
# from the submission root: builds both attacks and regenerates results/attack1_drain.txt
# and results/attack2_evidence.txt from real lab runs
bash scripts/run_attack12_experiments.sh
```

---

## Authorized use

These proof-of-concepts target the provided, self-contained lab (`s4ch1n/as3`) for the
course assignment only.
