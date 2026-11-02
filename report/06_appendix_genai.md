## 6. Appendix — Generative AI usage

We used a generative-AI coding assistant (Anthropic Claude) while building the attacks
and report. **Every behavioural and cryptographic claim in this report was verified by
running the provided Docker lab**, not taken from the model: all logs, tables and
recovered plaintexts come from real runs on the `s4ch1n/as3` image (see `results/*.txt`,
`results/*.csv`, and the `scripts/run_attack*_experiments.sh` scripts that regenerate
them).

### 6.1 How outputs were verified (methodology)

- **Protocol/wire facts** (framing, response shapes, OPK consumption, the empty-inventory
  error) were confirmed by raw TCP probes and packet captures against the live server,
  not from the model's description.
- **Attack 1** numbers (OPK draining 5→0, the refusal, a fresh client being denied) are
  the actual program output in `results/attack1_drain.txt`.
- **Attack 2** crypto was treated as unverified until the malicious server could decrypt
  **real** traffic from the unmodified lab client. The exact associated-data construction
  (`AD = ik_dh_init ‖ ik_dh_resp`, header *not* in the AEAD) was discovered empirically by
  an oracle search that re-encrypted the known plaintext and matched the real ciphertext —
  only then was it trusted. The three evidence classes in `results/attack2_evidence.txt`
  are live Mallory/Bob logs.

### 6.2 Representative prompts (Attack 1, Attack 2, report — 23b1057)

- "Here is `protocol.md` and the Attack 0 PoC. Write a C++ `fetch_bundle` client that
  drains a target's one-time prekeys and proves no new session can start." → produced
  `attack1.cpp`; **verified** by running it against the lab and watching `count` reach 0
  and a fresh client (Carol) get refused.
- "Analyse the OPK lifecycle: does fetching consume an OPK, and can the same OPK go to
  concurrent requests?" → model's hypotheses were **checked** with sequential and 5-way
  concurrent `fetch_bundle` probes (distinct ids, no reuse).
- "The client logs `SPK sig NOT verified`. Write a malicious C++ server that substitutes
  its own bundle and show whether it can recover the initiator's plaintext." → produced
  `attack2.cpp`. The suggested associated-data formula was **wrong twice** and only the
  empirically-matched recipe (confirmed by decrypting real client output) was kept.
- "Give the attack three modes so the report can show a forwarded message, a recovered
  plaintext, and a message that fails authentication." → produced the honest / reencrypt /
  raw modes; **verified** each against a real Bob client.
- "Write Python-style fix pseudocode for each attack (OPK reservation + SPK-only fallback;
  verify `spk_sig` + TOFU/safety numbers)." → reviewed against the X3DH/Double-Ratchet
  specs for correctness.

> The Attack 0 / lab-setup / state-diagram prompts (23b1075) are listed with that section;
> all Attack 0 quantitative claims were likewise reproduced on the Docker lab via
> `scripts/run_attack0_experiments.sh` with recorded `docker stats` output.
