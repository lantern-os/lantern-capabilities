# lantern-capabilities — Status

**Phase:** 0 (Foundations) — design only.

## Done
- Three-layer model and invariants specified ([RFC-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0003-capability-model.md), Accepted; see [ADR-0005](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0005-object-capabilities-as-universal-authority-model.md), [ADR-0006](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0006-three-layer-capability-structure.md)).
- Operation surface and badging drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)); auditability invariant and ADR-0005/0006 cross-links added during review.
- Threat model drafted and reviewed.

## Next
- Fix the rights lattice per object type.
- Define the service-layer brokering API and the sealed-cap token format.
- Phase 2 prototype: brokering + mint/grant/revoke over kernel endpoints.

## Blocked on
- Kernel capability mechanism ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).
- Crypto signing for sealed caps ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).
