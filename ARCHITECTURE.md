# lantern-capabilities — Architecture

Companion to [wiki/Security](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Security.md) and the authoritative
[RFC-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0003-capability-model.md).

## Core properties (invariants)
- **Unforgeability** — kernel-enforced for live caps; signature-enforced for sealed caps.
- **Designation = authority** — holding a cap to an object *is* permission to act on it; no
  separate ACL is consulted (eliminates the confused deputy).
- **Monotone attenuation** — `mint` only ever produces an equal-or-weaker capability.
- **Transitive revocation** — revoking a parent revokes everything derived from it.
- **No ambient authority** — a component with no caps can compute and nothing else.

## Operations
| Op | Semantics |
| --- | --- |
| `invoke(cap, method, args)` | Act, iff `rights ⊇ required`. |
| `mint(cap, subset_rights, badge)` | Attenuated copy; never adds rights. |
| `grant(cap, endpoint)` | Transfer a cap to another component via IPC. |
| `revoke(cap)` | Recursively invalidate the cap and its descendants. |
| `seal(cap)` / `unseal(token)` | Convert between live and cryptographic forms. |

## Badging
Endpoints may be **badged** so a service can distinguish callers without trusting
self-asserted identity — the basis for safely multiplexing one service across mutually
distrusting clients.

## Layer responsibilities
- **Kernel layer** (in `lantern-kernel`): CSpace, rights checks, the primitive cap objects.
- **Service layer** (here + `lantern-runtime`): brokering higher-level object caps, the
  mint/grant/revoke surface, and a capability-aware API for the [SDK](https://github.com/lantern-os/lantern-sdk).
- **Sealed layer** (with `lantern-crypto`): macaroon-style attenuable tokens binding caps to
  [DIDs](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md) for decentralised delegation.

## Open questions
- The rights lattice per object type and its SDK representation.
- Revocation cost model; whether to bound delegation depth.
- Mapping sealed ⇄ live caps at trust boundaries.
- CHERI hardware backing when targeting capable RISC-V cores.
