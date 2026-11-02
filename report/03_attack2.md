## 5. Attack 2 — malicious server / MITM (identity-key substitution)

### 5.1 Trust model (as implemented)

The assignment's four trust questions, answered from the implementation:

1. **How Alice obtains Bob's bundle.** Entirely from the server: Alice sends
   `fetch_bundle(bob)` and trusts whatever identity key, signed prekey and OPK come back.
   There is no second channel.
2. **How identity keys are verified.** They are **not**. The bundle carries `spk_sig` (an
   Ed25519 signature over the signed prekey), but the initiator never checks it — every
   session start logs `X3DH initiator: session with bob (… warn: SPK sig NOT verified)`.
   We confirmed the signature is ignored by serving a **deliberately bogus** `spk_sig`
   (64 bytes of `0x41`): the client accepts it without complaint and establishes a
   session. Nothing binds `spk`/`ik_dh` to a verified identity.
3. **Can the server replace key material undetected?** Yes. Since the signature is
   unchecked and there is no pinning, the server can return any keys it likes.
4. **Independent identity verification (safety numbers / fingerprints).** None. Alice and
   Bob have no out-of-band way to compare identity keys, so a substitution is invisible to
   them.

This is a textbook **fake-key / unauthenticated-key-exchange** flaw: X3DH's security
assumes the initiator authenticates the responder's prekey bundle (verify `spk_sig`
against a *trusted* identity key). The implementation performs neither the signature check
nor any identity trust decision, so the "server cannot read E2EE" guarantee collapses.

### 5.2 The attack and the PoC

`attacks/attack2.cpp` is a **malicious server** (C++/OpenSSL). When an initiator fetches a
peer's bundle, Mallory substitutes **her own** identity + prekeys. Alice then runs X3DH
against Mallory's keys while believing she is talking to Bob (session **A**). Mallory runs
a *second* X3DH as initiator toward the real Bob using his genuine bundle (session **B**).
She now shares an independent Double-Ratchet session with **each** side, decrypts Alice's
messages on session A, and re-encrypts them on session B toward Bob — a transparent MITM.
Our PoC demonstrates the Alice→Bob direction (which exhibits all three evidence classes
below); the Bob→Alice return path is symmetric (decrypt on session B, re-encrypt on session
A).

**Implementation note — the associated-data finding.** To decrypt, Mallory must reproduce
the AEAD exactly. By decrypting real captured client traffic we established that the
implementation's associated data is `AD = ik_dh_initiator ‖ ik_dh_responder` (64 raw
bytes) **only**; unlike `protocol.md` §4.3 it does **not** append `serialize(header)` to
the AEAD AD. (The header is still indirectly bound, because `n`/`dh` drive key
derivation — see Attack 0 — but it is not in the Poly1305 tag.) Everything else matches
the spec: X3DH with the `0xFF*32` prefix and `AS3_X3DH` info, SPK-only when `opk_id==0`,
`kdf_rk = HKDF(salt=RK, ikm=DH, info="AS3_ROOT")`, `kdf_ck = HMAC(CK,1)/HMAC(CK,2)`,
ChaCha20-Poly1305 with a zero nonce. With that recipe Mallory's decrypts succeed against
the unmodified lab clients.

### 5.3 Evidence: forward vs. recover vs. fail (measured)

`attacks/attack2.cpp` runs in three modes that produce exactly the three evidence classes
the brief requires (full logs in `results/attack2_evidence.txt`, reproduced by
`scripts/run_attack12_experiments.sh`). In every case Alice and Bob are **unmodified lab
clients** pointed at Mallory.

**(1) A message the server merely forwards (`--mode honest`).** Mallory does *not*
substitute; she relays the real bundle and the end-to-end ciphertext untouched. Bob reads
the message, and Mallory cannot:

```
[mallory] mode=honest: FORWARDED e2e ciphertext alice->bob (plaintext is NOT recoverable by the server)
Bob:  recv <- alice (dh=...e6163c7b, n=0, pn=0)   [alice] hello-bob-baseline
```

This is the E2EE baseline the protocol is supposed to guarantee — the honest server is a
blind relay.

**(2) A message whose plaintext the server recovers (`--mode reencrypt`).** Mallory
substitutes, decrypts Alice's message, re-encrypts under session B, and delivers it. Bob
sees a normal message from Alice; neither side notices:

```
[mallory] SUBSTITUTED bundle for 'bob' -> handed Mallory's keys to the initiator
[mallory] *** RECOVERED PLAINTEXT alice->bob: "meet me at 5pm -alice" ***
[mallory] FORWARDED re-encrypted frame to real 'bob' (transparent; both sides see a working session)
Bob:  recv <- alice (dh=...f4d8a701, n=0, pn=0)   [alice] meet me at 5pm -alice
```

Confidentiality is fully broken: the server read the plaintext *and* the conversation
still works, so the attack is undetected.

**(3) A message that fails authentication (`--mode raw`).** Mallory substitutes and
decrypts (so she still reads the plaintext), but forwards Alice's **original** ciphertext
to Bob instead of re-encrypting. Alice encrypted under the Alice↔Mallory key, whereas
Bob's X3DH with his own keys derives a *different* key, so his AEAD tag check fails:

```
[mallory] *** RECOVERED PLAINTEXT alice->bob: "this will not arrive" ***
[mallory] mode=raw: relayed Alice's ORIGINAL ciphertext to 'bob' -> his decrypt will FAIL
Bob:  DECRYPT FAIL from alice (dh=...23f3bc05, n=0): AEAD authentication failed
```

This shows the two sessions are genuinely independent: the attacker *must* decrypt and
re-encrypt (mode 2) to stay transparent — a naive relay of the original ciphertext (mode
3) is rejected. Together the three modes demonstrate that the malicious server establishes
separate sessions with each party, recovers the initiator's plaintext, and forwards it to
the other party transparently (the reverse direction follows by symmetry).

### 5.4 Fix (pseudocode)

The root cause is unauthenticated key establishment. Two layers of defence:

**(a) Verify the signed-prekey signature (closes the demonstrated attack).** The
initiator must check `spk_sig` against the responder's identity key before using the
bundle — and must only trust that identity key if it has been authenticated (pinned or
verified out of band), otherwise the server can simply substitute a *consistent* identity
+ signature of its own.

```python
def x3dh_initiate(my_ik, bundle):
    # 1) the signed prekey must be signed by the bundle's identity key
    if not ed25519_verify(bundle.ik_sig, bundle.spk, bundle.spk_sig):
        abort("SPK signature invalid")                 # <-- the missing check
    # 2) that identity key must be one we actually trust (see (b)), not just
    #    whatever the server handed us this time
    if not identity_is_trusted(bundle.user, bundle.ik_sig):
        abort("unverified identity key for %s" % bundle.user)
    ...                                                # proceed with X3DH only now
```

**(b) Give Alice and Bob an independent way to detect a malicious server.** Signature
verification alone is insufficient, because a malicious server can present its own
self-consistent identity. Add identity trust that does not route through the server:

- **TOFU pinning:** on first contact, pin `ik_sig` for a peer; on any later change, warn
  loudly. A server that substitutes keys for an *existing* contact is caught.
- **Safety numbers / fingerprints:** derive a short code from both parties' identity keys
  (`fingerprint = H(ik_A ‖ ik_B)`) that users compare out of band (QR scan, read aloud).
  Under MITM Alice sees `H(ik_A ‖ ik_Mallory)` while Bob sees `H(ik_Mallory ‖ ik_B)` — the
  codes differ, exposing the attack.

```python
def on_session_established(peer, peer_ik_sig):
    pinned = trust_store.get(peer)
    if pinned is None:
        trust_store.put(peer, peer_ik_sig)             # TOFU: trust first key
    elif pinned != peer_ik_sig:
        warn("SAFETY NUMBER CHANGED for %s — possible MITM" % peer)  # detect substitution
    show_safety_number(H(my_ik_sig, peer_ik_sig))      # user-comparable, server-independent
```

**Assumptions of the fix.** (a) assumes a trustworthy binding between a peer and their
identity key; on its own it only forces the attacker to use a consistent fake identity.
(b) removes that assumption by letting users verify identities through a channel the
malicious server does not control — which is exactly what real Signal/WhatsApp safety
numbers provide.
