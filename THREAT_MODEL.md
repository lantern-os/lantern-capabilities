# lantern-capabilities — Threat Model

Inherits the [system threat model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md). Capabilities *are*
authority, so their integrity is a top-tier asset (system threats T1, T3, T8).

## Assets
- Integrity and unforgeability of capabilities (live and sealed).
- Correctness of attenuation (no rights amplification).
- Correctness and completeness of revocation.

## Threats and mitigations
| # | Threat | Mitigation |
| --- | --- | --- |
| C1 | Forge a capability | Kernel-managed CSpaces; signed sealed caps; possession is the only way to hold one. |
| C2 | Amplify rights via `mint` | Monotone attenuation enforced; `mint` mathematically cannot add rights. |
| C3 | Confused deputy | Designation = authority; caller must supply the cap; no ambient ACL. |
| C4 | Incomplete / ineffective revocation | Transitive, kernel-tracked derivation tree; revocation invalidates descendants. |
| C5 | Replay/forgery of sealed (cryptographic) caps | Signatures, freshness/expiry, and binding to context/DID. |
| C6 | Capability leakage via a buggy broker | Brokers run in confined user space; a broker bug is bounded by the broker's own caps. |

## Non-goals
- Preventing a user from *intentionally* delegating authority they legitimately hold.
- Covert channels that leak information without transferring a capability (system non-goal).
