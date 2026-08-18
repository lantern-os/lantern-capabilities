# lantern-capabilities — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md): the kernel capability mechanism this crate was blocked on now exists, is proven under real QEMU, and its IPC path is benchmarked. No prototype code yet — see "Next".

## Done
- Three-layer model and invariants specified ([RFC-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0003-capability-model.md), Accepted; see [ADR-0005](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0005-object-capabilities-as-universal-authority-model.md), [ADR-0006](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0006-three-layer-capability-structure.md)).
- Operation surface and badging drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)); auditability invariant and ADR-0005/0006 cross-links added during review.
- Threat model drafted and reviewed.

## Next
- Fix the rights lattice per object type.
- Define the service-layer brokering API and the sealed-cap token format.
- Phase 2 prototype: brokering + mint/grant/revoke over kernel endpoints.

## Blocked on
- ~~Kernel capability mechanism ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).~~
  Resolved — RFC-0009/ADR-0014. The kernel-layer capability mechanism (CSpace, untyped
  retyping, IPC endpoints) is real, QEMU-validated, and benchmarked; brokering +
  mint/grant/revoke prototype work over it can start.
- Crypto signing for sealed caps ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto))
  — still open; `lantern-crypto`'s Phase 1 primitive set is accepted (RFC-0007/ADR-0011)
  but its keystore/signing service doesn't exist yet. Only blocks the *sealed*-capability
  layer (RFC-0003's third layer); kernel- and service-layer capability work is unblocked
  now.
