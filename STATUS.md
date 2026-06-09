# lantern-capabilities — Status

**Phase:** 0 (Foundations) — design only.

## Done
- Three-layer model and invariants specified ([RFC-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0003-capability-model.md), Proposed).
- Operation surface and badging drafted ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted.

## Next (gated on RFC-0003 → Accepted)
- Fix the rights lattice per object type.
- Define the service-layer brokering API and the sealed-cap token format.
- Phase 2 prototype: brokering + mint/grant/revoke over kernel endpoints.

## Blocked on
- Kernel capability mechanism ([`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).
- Crypto signing for sealed caps ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).
