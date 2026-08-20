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

## Next
- Fix the rights lattice per object type.
- The sealed-cap token format (RFC-0003's third layer) — blocked on `lantern-crypto`'s
  keystore, see "Blocked on".
- Wire `Broker` into a real, standalone confined program `lantern-boot` loads and runs
  under QEMU as a third party to its existing two-thread demo — this session's work proves
  the broker's logic against a real `KernelState`, but nothing yet deploys it as an actual
  running service. Needs `lantern-boot/src/loader.rs` extended to load a third ELF binary
  (or a generalization of `load()` beyond the current hardcoded two-copies-of-one-binary
  demo shape).
- `Broker::grant`'s `Send`-not-`Call`/`Reply` limitation is a direct consequence of
  `Reply`'s return leg not supporting capability transfer yet
  (`lantern-kernel/STATUS.md`'s "Next") — revisit once that lands, since a
  request/response-shaped grant (`Call` in, capability back on `Reply`) is a more natural
  client-side API than a bare `Recv`-then-`Send`.
- A concrete first consumer: either `lantern-filesystem` (Filesystem v0) or the
  `lantern-crypto` keystore building real object semantics on top of `Broker`.

## Blocked on
- ~~Kernel capability mechanism ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).~~ Resolved —
  RFC-0009/ADR-0014, and now RFC-0010's `extra_caps == 1` transfer + `CopyCross`, both real
  and QEMU-validated (`lantern-kernel/STATUS.md`).
- Crypto signing for sealed caps ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)) — still open;
  `lantern-crypto`'s Phase 1 primitive set is accepted (RFC-0007/ADR-0011) but its
  keystore/signing service doesn't exist yet. Only blocks the *sealed*-capability layer
  (RFC-0003's third layer); kernel- and service-layer capability work is unblocked now.
