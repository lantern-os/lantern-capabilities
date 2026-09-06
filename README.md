# lantern-capabilities

The **capability model** of LanternOS — the cross-cutting authority fabric. Authority is
expressed only as unforgeable, attenuable, revocable capabilities. No ambient authority, no
global namespace, no identity-based ACLs.

- **Layer:** security core (spans kernel mechanism → user-space brokering → cryptographic
  delegation).
- **Decision of record:** [RFC-0003 — The LanternOS capability model](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0003-capability-model.md).
- **System context:** [wiki/Security](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Security.md).

> **Phase 2 complete** (RFC-0017/ADR-0021), roadmap gate now Phase 3. As of 2026-09-05
> (RFC-0018/ADR-0022) `Broker` runs its own code in a **confined U-mode program** via the
> `Abi` backend — `lantern-boot`'s `broker-service` proves it under QEMU. A host/root-task
> caller uses the `KernelBackend` (`&mut KernelState`, feature `kernel-backend`, default).
> `Keystore`/`Store` confinement is the remaining ADR-0022 Part 1 work. See [`STATUS.md`](./STATUS.md).

## The three layers
1. **Kernel capabilities** — seL4-style handles to kernel objects (in [`lantern-kernel`](https://github.com/lantern-os/lantern-kernel)).
2. **Service capabilities** — higher-level handles (file, socket) brokered by user-space
   services over kernel endpoints (this repo + [`lantern-runtime`](https://github.com/lantern-os/lantern-runtime)).
3. **Sealed capabilities** — signed, attenuable tokens for delegation that persists or
   crosses machines ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).
