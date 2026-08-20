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
- The sealed-cap token format (RFC-0003's third layer) — blocked on `lantern-crypto`'s
  keystore, see "Blocked on".
- **`Broker` as written is not a deployable confined-service implementation.** Its methods
  take `&mut lantern_kernel::state::KernelState` directly — valid only for privileged,
  same-address-space code (exactly the category `lantern-boot/src/loader.rs`'s root task is
  in), not for a real confined U-mode program, which has no such pointer and can only reach
  the kernel via actual `ecall`s (the way `hello-service` does, with hand-written inline
  asm). This session's work proves the *sequence of kernel operations* a broker needs is
  correct, the same validate-before-deployment role `loader.rs` plays for its own logic —
  it is not itself that deployment. Turning this into a real running service needs a
  from-scratch raw-`ecall` reimplementation of `mint`/`grant`/`revoke` (or `Broker` itself
  compiled as a genuinely separate, `no_std`, `ecall`-issuing binary — either way, a
  different code path from what exists today, not a thin wrapper around it), plus
  `lantern-boot/src/loader.rs` extended to load it as a third program alongside its
  existing two-thread demo (or a generalization of `load()` beyond the current
  hardcoded two-copies-of-one-binary shape).
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
