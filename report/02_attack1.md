## 4. Attack 1 — one-time prekey exhaustion ("Prekey Pogo")

### 4.1 Prekey lifecycle (as implemented)

We traced an OPK from creation to consumption using the client/server logs and raw
`fetch_bundle` probes against the lab (all claims below are measured, not assumed):

1. **Generation / storage / publish.** On startup each client generates `OPK_COUNT`
   one-time prekeys (the lab sets `OPK_COUNT=5`) and `publish`es a bundle: the identity
   keys (`ik_sig`, `ik_dh`) and signed prekey (`spk`, `spk_sig`) plus an `opks` array of
   `{id, pub}` entries. The server stores the bundle and the OPK list in memory.
   `publish` **appends** OPKs rather than replacing them, and the client replenishes by
   publishing again (menu option *2, upload prekey bundle*).
2. **Does fetching consume an OPK?** **Yes — consumption happens at `fetch_bundle`
   time, not when a session is actually established.** Each `fetch_bundle(bob)` returns
   one OPK (`opk`, `opk_id`) and decrements the reported `count`. An attacker therefore
   never has to complete X3DH, send a message, or even register — merely *asking* for the
   bundle burns a prekey.
3. **Concurrent allocation.** We issued 5 simultaneous `fetch_bundle(bob)` requests; the
   server returned five **distinct** ids `{1,2,3,4,5}` with no duplicate, so it
   serialises OPK hand-out and does not hand the *same* OPK to concurrent requests. This
   closes a key-reuse race but does nothing to slow draining — concurrency just empties
   the inventory faster.
4. **What happens at zero.** After the fifth OPK is issued the inventory is empty and the
   server stops returning a bundle **entirely**, replying
   `{"type":"err","err":"no one-time prekeys available for bob"}`. It refuses the *whole*
   bundle, not just the optional OPK — so an initiator cannot even obtain Bob's identity
   key and signed prekey to run the SPK-only form of X3DH. **No new session can be
   started with Bob until he comes online and republishes.**

**Root causes.** `fetch_bundle` is (a) **unauthenticated** — anyone who can reach the
server fetches anyone's bundle; (b) **unrate-limited** — unlimited fetches from a single
reused TCP connection; (c) **eagerly consuming** — an OPK is spent on *fetch*, decoupled
from any real session; and (d) **fail-closed with no fallback** — an empty inventory
denies the entire bundle instead of degrading to signed-prekey-only X3DH. OPKs are a
finite per-publish handshake resource, and nothing binds their consumption to a genuine
session attempt.

### 4.2 The PoC

`attacks/attack1.cpp` is an ordinary client (the Attack-1 scenario: Bob is offline,
Mallory has no special network position). It opens one TCP connection and sends
`fetch_bundle(target)` in a loop, parsing `opk_id`/`count` until the server refuses, then
confirms that a fresh fetch — what a legitimate new initiator like Alice would do — is
now rejected.

```
./attack1 --server as3_server:9000 --target bob
```

### 4.3 Result: new-session denial of service (measured)

Reproduced by `scripts/run_attack12_experiments.sh` (log in
`results/attack1_drain.txt`):

| fetch # | OPK id returned | `count` remaining |
|--------:|----------------:|------------------:|
| 1 | 1 | 4 |
| 2 | 2 | 3 |
| 3 | 3 | 2 |
| 4 | 4 | 1 |
| 5 | 5 | 0 *(field omitted)* |
| 6 | — | **REFUSED:** `no one-time prekeys available for bob` |

Five trivial requests (no auth, no session, <1 ms each) empty Bob's inventory. We then
confirmed the impact with a real client: a fresh user **Carol** attempting to message Bob
fails immediately with `fetch_bundle(bob): no one-time prekeys available for bob` and
never establishes a session. Because Bob is offline he cannot replenish, so the denial
persists for the whole outage. With `OPK_COUNT=5` the attack is five packets; it scales
linearly, so any finite inventory is drained in one burst.

**Why this is the X3DH analogue of a DoS:** OPKs exist to give the *first* message
post-compromise security before the ratchet warms up. Treating them as a free, anonymous,
fetch-time-consumed resource lets an unprivileged attacker convert "Bob is briefly
offline" into "nobody can start talking to Bob."

### 4.4 Fix (pseudocode)

Address the root causes: stop consuming OPKs on fetch, authenticate and rate-limit the
request, reserve (don't burn) an OPK and bind it to a real session, and **degrade to
signed-prekey-only X3DH** instead of refusing the bundle when the inventory is empty.

```python
RATE_PER_REQUESTER = 5        # fetch_bundle / minute / registered requester
OPK_RESERVATION_TTL = 30      # seconds a reserved OPK is held before being returned

def handle_fetch_bundle(conn, req):
    if conn.registered_user is None:               # (a) authenticate the fetch
        return err("register first")
    if not rate_ok(conn.registered_user, RATE_PER_REQUESTER):
        return err("rate limited")                 # (b) bound anonymous draining

    u = req.user
    bundle = identity_and_spk(u)                   # ALWAYS returned (identity + signed prekey)

    # (c) reserve rather than consume: the OPK is only *spent* once a matching first
    #     message actually arrives; unused reservations expire and return to the pool.
    opk = reserve_opk(u, holder=conn.registered_user, ttl=OPK_RESERVATION_TTL)
    if opk is not None:
        bundle.opk, bundle.opk_id = opk.pub, opk.id
    else:
        bundle.opk, bundle.opk_id = "", 0          # (d) SPK-only X3DH fallback: sessions
                                                   #     still start, just without the
                                                   #     extra OPK on the first message
    return bundle                                  # never a hard refusal

def handle_first_message(frame):                   # consume only on real use
    if frame.header.init.opk_id != 0:
        commit_opk(frame.to, frame.header.init.opk_id)   # now it is truly spent
```

Reservations with a TTL defeat "fetch-and-drop" draining (unused OPKs come back); the
rate limit plus required registration make draining attributable and slow; and the
SPK-only fallback means an empty pool degrades first-message forward secrecy rather than
denying service outright. A server should also keep a safety floor of OPKs and warn the
owner to replenish.
