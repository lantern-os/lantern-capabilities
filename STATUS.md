# lantern-capabilities — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). First prototype code now exists — see "Done".

## Done
- Three-layer model and invariants specified ([RFC-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0003-capability-model.md), Accepted; see [ADR-0005](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0005-object-capabilities-as-universal-authority-model.md), [ADR-0006](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0006-three-layer-capability-structure.md)).
- Operation surface and badging drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)); auditability invariant and ADR-0005/0006 cross-links added during review.
- Threat model drafted and reviewed.
- **First prototype code merged** (`src/lib.rs`): a generic `Broker` — mints attenuated,
  badged capabilities (real `CNodeInvoke::Mint`) and hands them to a waiting client over a
  real, live `extra_caps == 1` IPC transfer ([RFC-0010](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0010-cross-process-capability-transfer-and-brokering.md),
  now real in `lantern-kernel`), gated on `Rights::GRANT`. Revocation is broker-local (a
  `badge → revoked` table, deny-by-default for unknown badges) — the sanctioned Phase 2
  answer RFC-0010 fixes, since kernel-level `Revoke` still needs a capability-derivation
  tree `lantern-kernel` doesn't have yet. Deliberately **not a policy engine**: `Broker`
  knows how to mint/grant/revoke a badge, nothing about what any given badge's object
  *means* — that's left to whichever concrete service (the eventual `lantern-filesystem`,
  `lantern-crypto` keystore) builds its own request dispatch on top of it. 5 unit tests
  pass, each exercising the mechanism against a real `lantern_kernel::state::KernelState`
  with two real threads (broker + client) rendezvousing over real IPC — not a simulation of
  the kernel calls, the actual `cnode::invoke`/`ipc::send` functions, the same discipline
  `lantern-boot/src/loader.rs` follows for its own privileged operations. `cargo clippy -D
  warnings` clean on host and `riscv64gc-unknown-none-elf`.
- **`Broker::grant_via_reply`**: the request/response-shaped grant `grant`'s own doc always
  named as the more natural fit — client `Call`s a request (registering its own destination
  slot via `tag.extra_caps == 2` on that `Call`), this broker replies with the capability
  attached in the same round trip, via `lantern_kernel::ipc::reply`'s now-real
  `extra_caps == 1` reply-leg transfer. `grant` (bare `Recv`-then-`Send`) is unchanged and
  still the right fit for an unsolicited grant. 6 unit tests pass (1 new, driving a real
  `Call`→`Recv`→mint→`Reply`-with-a-grant sequence end to end), `cargo clippy -D warnings`
  clean on host and `riscv64gc-unknown-none-elf`.

## Next
- Fix the rights lattice per object type.
- ~~The sealed-cap token format (RFC-0003's third layer) — blocked on `lantern-crypto`'s
  keystore.~~ Unblocked and drafted —
  [RFC-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0011-sealed-capability-token-format.md)
  (Draft, awaiting acceptance) proposes a macaroon-style BLAKE3-keyed-MAC-chained format on
  top of `Broker::mint`/`grant` and `lantern-crypto`'s `Keystore` MAC keys. Implementation
  waits on RFC acceptance, not on any remaining code blocker.
- **The mint/grant sequence `Broker` implements is now proven under real confined U-mode
  `ecall`s, not just against a direct `KernelState`** — `lantern-boot`'s new, isolated
  `lantern-boot-broker-demo` binary (`lantern-boot/src/broker_demo/`,
  `lantern-boot/STATUS.md`) hand-reimplements the same `Recv`→`Mint`→`Reply`-with-
  `extra_caps==1` sequence as raw `ecall`s in a standalone confined program
  (`broker-service/`), and a confined client (`broker-client/`) proves the granted
  capability is genuinely functional by `Signal`-ing it — confirmed reproducible under
  real QEMU. **`Broker`'s own Rust API still isn't what's running, and structurally can't
  be as written**: its methods take `&mut lantern_kernel::state::KernelState` directly,
  valid only for privileged, same-address-space code (`lantern-boot/src/loader.rs`'s own
  category), never for a real confined U-mode program, which has no such pointer. Turning
  `Broker` itself into deployable confined-service code — rather than a hand-duplicated
  reimplementation of its logic — needs a genuine WASM/native confined runtime capable of
  hosting real Rust service code (`lantern-runtime`'s eventual job), not more loader work;
  `lantern-boot/STATUS.md`'s own "Next" has the fuller reasoning.
- ~~A concrete first consumer: either `lantern-filesystem` (Filesystem v0) or the
  `lantern-crypto` keystore building real object semantics on top of `Broker`.~~ Resolved —
  `lantern-crypto`'s `Keystore` (`lantern-crypto/STATUS.md`) now builds real object semantics
  (key ID + operation scoping) on top of `Broker::mint`/`grant`/`grant_via_reply`/`revoke`,
  exercised end to end against a real `KernelState`. `lantern-filesystem` remains open as a
  second, still-unstarted consumer.

## Blocked on
- ~~Kernel capability mechanism ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).~~ Resolved —
  RFC-0009/ADR-0014, and now RFC-0010's `extra_caps == 1` transfer + `CopyCross`, both real
  and QEMU-validated (`lantern-kernel/STATUS.md`).
- ~~Crypto signing for sealed caps ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)) —
  `lantern-crypto`'s keystore/signing service doesn't exist yet.~~ Resolved —
  `lantern-crypto`'s `Keystore` now has real Ed25519 signing and BLAKE3-keyed MAC keys
  (`lantern-crypto/STATUS.md`), and
  [RFC-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0011-sealed-capability-token-format.md)
  (Draft) specifies the sealed-capability format built on them. Only blocks *implementing*
  RFC-0011 pending its acceptance; kernel- and service-layer capability work has been
  unblocked since RFC-0010.
