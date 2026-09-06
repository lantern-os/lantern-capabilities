# lantern-capabilities — Status

**Phase:** 2 — opened per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md), **closed** per [RFC-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0017-phase-2-to-phase-3-transition.md)/[ADR-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0021-phase-2-complete-phase-3-opened.md): the Phase 2 exit criterion is met — `Broker`'s mint/grant/revoke is what a confined Wasm app's granted capabilities are built on (`lantern-example-signer`). This crate's "Next" items (rights lattice per object type) continue; the Roadmap's gate has moved to Phase 3. **Carried forward from ADR-0021, now RESOLVED for `Broker` (2026-09-05, [RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md)/[ADR-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0022-confined-service-model-and-call-transport.md)):** `Broker`'s logic is written once against the new `BrokerBackend` trait and runs in either of two places — `Abi` (a confined U-mode program, every op a real `ecall` via [`lantern-abi`](https://github.com/lantern-os/lantern-abi); `default-features = false` links nothing from the TCB) or `KernelBackend` (feature `kernel-backend`, default — a privileged root task or a host test, `&mut KernelState`). `lantern-boot`'s `broker-service` now runs **this crate's own `Broker` code** under QEMU via the `Abi` backend. `Keystore`/`Store` still thread a `KernelBackend` internally (their own confinement + wire protocols are the remaining ADR-0022 Part 1 work).

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

- **Backend split shipped** (2026-09-05, [RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md)/[ADR-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0022-confined-service-model-and-call-transport.md)):
  new `backend` module — `trait BrokerBackend` (`mint` / `grant_send` / `grant_reply`),
  `struct Abi` (ZST, forwards to `lantern_abi::sys::{cnode::mint, send_with_cap,
  reply_with_cap}`), `struct KernelBackend<'a>` (feature `kernel-backend`, default;
  `{ &mut KernelState, TcbId }`, builds `TrapFrame`s + calls `lantern_kernel::{cnode, ipc}`).
  `Broker` dropped its `TcbId` field, methods take `&mut impl BrokerBackend` instead of
  `&mut KernelState`, and re-export `lantern_abi::wire::{Rights, SyscallError}` as this
  crate's. Cargo: `lantern-abi` is the one non-optional dep; `lantern-hal`/`lantern-kernel`
  are `optional`, behind `kernel-backend`. Builds for `riscv64gc-unknown-none-elf` with
  `--no-default-features` (only `lantern-abi` linked). 6 unit tests still green (now driving
  the real kernel via `KernelBackend`); `broker-service` runs the real `Broker` under QEMU
  (all 4 demo steps `ok=true`). `lantern-crypto`/`lantern-filesystem` updated to thread a
  `KernelBackend` (mechanical; their public `&mut KernelState` API unchanged, 31 + 12 tests
  green). clippy clean host + `riscv64` (both feature sets).

## Next
- **`Keystore`/`Store` onto the backend abstraction** (ADR-0022 Part 1, remaining): give
  each a real request/reply wire protocol (SIGN/ENCRYPT/DECRYPT; READ/WRITE) and an `Abi`
  path so they too can run confined, not just `Broker`. Each wire protocol is an ADR-0022
  follow-up.
- Fix the rights lattice per object type.
- ~~The sealed-cap token format (RFC-0003's third layer) — blocked on `lantern-crypto`'s
  keystore.~~ Resolved —
  [RFC-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0011-sealed-capability-token-format.md)/[ADR-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0015-sealed-capability-token-format.md)
  (Accepted) fix a macaroon-style BLAKE3-keyed-MAC-chained format on top of `Broker::mint`/
  `grant` and `lantern-crypto`'s `Keystore` MAC keys. Implementation now in
  `lantern-crypto` (see its `STATUS.md`) — `unseal` calling back into this crate's `Broker`
  is the only piece that lives here.
- ~~The mint/grant sequence `Broker` implements is proven under real confined U-mode
  `ecall`s, but `Broker`'s own Rust API isn't what's running (it takes `&mut KernelState`);
  turning it into deployable confined-service code needs a WASM/native runtime.~~
  **Wrong, and resolved 2026-09-05** — the `BrokerBackend` split (above) needed no runtime,
  just a trait. `lantern-boot`'s `broker-service` now constructs a real `Broker` with the
  `Abi` backend and runs its actual `mint` (`Rights::GRANT` check + `CNodeInvoke::Mint` +
  badge bookkeeping) and `grant_via_reply` under QEMU — no hand-duplicated logic.
- ~~A concrete first consumer: either `lantern-filesystem` (Filesystem v0) or the
  `lantern-crypto` keystore building real object semantics on top of `Broker`.~~ Resolved
  twice over — `lantern-crypto`'s `Keystore` (`lantern-crypto/STATUS.md`) builds real object
  semantics (key ID + operation scoping) on top of `Broker::mint`/`grant`/`grant_via_reply`/
  `revoke`, and `lantern-filesystem`'s `Store` (`lantern-filesystem/STATUS.md`) does the same
  one layer up (file ID + read/write scoping), both exercised end to end against a real
  `KernelState`.

## Blocked on
- ~~Kernel capability mechanism ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).~~ Resolved —
  RFC-0009/ADR-0014, and now RFC-0010's `extra_caps == 1` transfer + `CopyCross`, both real
  and QEMU-validated (`lantern-kernel/STATUS.md`).
- ~~Crypto signing for sealed caps ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)) — `lantern-crypto`'s
  keystore/signing service doesn't exist yet.~~ Resolved — `lantern-crypto`'s `Keystore` now
  has real Ed25519 signing and BLAKE3-keyed MAC keys (`lantern-crypto/STATUS.md`), and
  [RFC-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0011-sealed-capability-token-format.md)/[ADR-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0015-sealed-capability-token-format.md)
  (Accepted) fix the sealed-capability format built on them.
