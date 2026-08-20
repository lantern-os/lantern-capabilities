//! `lantern-capabilities` — the service (layer 2) capability broker
//! ([RFC-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0003-capability-model.md),
//! [ADR-0006](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0006-three-layer-capability-structure.md)).
//! Phase 2's first prototype code in this crate ([RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/
//! [ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md)),
//! built directly on the kernel-layer mechanism [RFC-0010](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0010-cross-process-capability-transfer-and-brokering.md)
//! added to [`lantern_kernel`]: real `CNodeInvoke::Mint` for attenuation, real
//! `extra_caps == 1` IPC transfer for `grant`, gated on `Rights::GRANT`.
//!
//! [`Broker`] is deliberately **generic, not a policy engine**: it knows how to
//! mint an attenuated, badged capability and hand it to a waiting client over
//! real IPC, and how to track per-badge revocation — nothing about what a
//! badge's underlying object *means* (a file, a keystore entry, ...). Each
//! concrete Phase 2 service (the eventual `lantern-filesystem`,
//! `lantern-crypto` keystore) is expected to build its own request dispatch
//! and object semantics on top of this, the same way RFC-0003 draws the line
//! between the generic service-capability *mechanism* (this crate,
//! `lantern-runtime`) and what any one service's capabilities designate.
//!
//! **What this is not yet:** a real, standalone confined program. Every
//! [`Broker`] method takes `&mut lantern_kernel::state::KernelState` directly
//! — valid only for privileged, same-address-space code (the category
//! `lantern-boot/src/loader.rs`'s root task is in), not a real confined
//! U-mode program, which has no such pointer and can only reach the kernel
//! via actual `ecall`s (the way `hello-service` does, with hand-written
//! inline asm). This crate proves the *sequence of kernel operations* a
//! broker needs is correct — the same validate-before-deployment role
//! `loader.rs` plays for its own logic — not a deployable implementation of
//! it. `lantern-boot`'s `lantern-boot-broker-demo` binary now proves that
//! same sequence for real under confined U-mode `ecall`s, but as a
//! hand-written reimplementation (`broker-service/`), not this crate's own
//! code running — see `STATUS.md` for why that gap remains and what closing
//! it would actually take.
#![cfg_attr(not(test), no_std)]

use lantern_hal::{MessageTag, TrapFrame};
use lantern_kernel::cap::{CPtr, Rights, TcbId};
use lantern_kernel::cnode;
use lantern_kernel::error::SyscallError;
use lantern_kernel::ipc;
use lantern_kernel::state::KernelState;

/// Fixed capacity, no heap — matches every other Phase 1/2 kernel-adjacent
/// pool in this project ([`lantern_kernel::limits`]'s own convention).
const MAX_GRANTS: usize = 32;

#[derive(Clone, Copy, Debug)]
struct GrantRecord {
    badge: u64,
    revoked: bool,
}

/// A service-layer capability broker: mints attenuated, badged capabilities
/// from capabilities it already holds and grants them to waiting clients over
/// real IPC, tracking revocation itself (kernel-level `Revoke` remains
/// unimplemented — needs a capability-derivation tree,
/// `lantern-kernel/STATUS.md` — broker-local tracking is the sanctioned Phase 2
/// answer, RFC-0010).
///
/// Every operation here is a real call into `lantern_kernel` (`CNodeInvoke`,
/// IPC `Send`) exactly as a real syscall from this thread would make, not a
/// simulation of one — the same "calls the real, capability-checked thing"
/// discipline `lantern-boot/src/loader.rs` follows for its own privileged
/// operations.
pub struct Broker {
    /// This broker's own thread identity.
    self_tcb: TcbId,
    /// A CPtr, in the broker's own CSpace, naming a capability to the
    /// broker's own CNode — required to invoke `CNodeInvoke::Mint` on itself
    /// (`cnode.rs`'s "self-administration ... requires that thread to
    /// actually hold a capability to its own CNode" discipline, the same one
    /// `lantern-boot/src/loader.rs`'s `SELF_CNODE_CPTR` satisfies for root).
    self_cnode_cptr: CPtr,
    next_badge: u64,
    grants: [Option<GrantRecord>; MAX_GRANTS],
}

impl Broker {
    /// `self_tcb`/`self_cnode_cptr` — see their field docs; the caller (real
    /// broker setup code, or a test) is responsible for having already placed
    /// a self-referencing `Capability::CNode` at `self_cnode_cptr` in the
    /// broker's own CSpace, the same bootstrap step `lantern-boot`'s root task
    /// performs for itself.
    pub const fn new(self_tcb: TcbId, self_cnode_cptr: CPtr) -> Self {
        Self { self_tcb, self_cnode_cptr, next_badge: 1, grants: [None; MAX_GRANTS] }
    }

    /// Mints an attenuated copy of the capability at `source_slot` (in the
    /// broker's own CSpace) into `scratch_slot` (also the broker's own
    /// CSpace), with `rights`, and records a fresh badge for it in this
    /// broker's revocation table. Returns the badge — callers pass it (and
    /// `scratch_slot`) to [`Broker::grant`] to actually hand the minted
    /// capability to a client.
    ///
    /// **Requires `rights` to include `Rights::GRANT`.** This is a `Broker`
    /// policy choice, not a kernel one (`CNodeInvoke::Mint` itself only
    /// enforces monotone attenuation against the *source* capability's
    /// rights) — but a capability minted here that can't itself be granted
    /// onward is useless for this broker's actual job, so this fails fast
    /// with a clear error instead of succeeding here and only failing later,
    /// confusingly, inside `grant`.
    pub fn mint(
        &mut self,
        state: &mut KernelState,
        source_slot: CPtr,
        scratch_slot: CPtr,
        rights: Rights,
    ) -> Result<u64, SyscallError> {
        if !rights.contains(Rights::GRANT) {
            return Err(SyscallError::IllegalOperation);
        }
        let slot = self.grants.iter().position(Option::is_none).ok_or(SyscallError::NotEnoughMemory)?;

        let badge = self.next_badge;
        let packed = ((badge as usize) << 8) | rights.bits() as usize;
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label: cnode::LABEL_MINT, length: 0, extra_caps: 0, flags: 0 });
        frame.set_mr(1, source_slot);
        frame.set_mr(2, scratch_slot);
        frame.set_mr(3, packed);
        cnode::invoke(state, self.self_tcb, self.self_cnode_cptr, &mut frame)?;

        // Nothing above this point can fail once the mint itself succeeds, so
        // there's no risk of recording a badge for a mint that didn't happen
        // (checked-before-acting, same discipline `lantern_kernel::admin`'s
        // own retype path documents for itself).
        self.next_badge += 1;
        self.grants[slot] = Some(GrantRecord { badge, revoked: false });
        Ok(badge)
    }

    /// Transfers the capability at `scratch_slot` (in the broker's own
    /// CSpace — normally one [`Broker::mint`] just produced) to whichever
    /// thread is waiting on `endpoint_cptr` with a registered destination
    /// slot, via a real `extra_caps == 1` IPC `Send` (RFC-0010) — a live,
    /// `Rights::GRANT`-checked kernel transfer, not a pool write. `payload`
    /// becomes the delivered message's `mr2`/`mr3` (`mr1` is spent naming the
    /// transferred capability, same convention `lantern_kernel::ipc` uses
    /// throughout).
    ///
    /// Fits an unsolicited grant, or a client waiting in a bare `Recv`. For
    /// the more common request/response shape — a client `Call`s asking for
    /// something, this broker replies with the grant in the same round trip
    /// — see [`Broker::grant_via_reply`] instead.
    pub fn grant(
        &self,
        state: &mut KernelState,
        endpoint_cptr: CPtr,
        scratch_slot: CPtr,
        payload: (usize, usize),
    ) -> Result<(), SyscallError> {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 1, flags: 0 });
        frame.set_mr(1, scratch_slot);
        frame.set_mr(2, payload.0);
        frame.set_mr(3, payload.1);
        ipc::send(state, self.self_tcb, endpoint_cptr, &mut frame, false)
    }

    /// Like [`Broker::grant`], but replies to whichever `Call` this broker is
    /// currently holding a `reply_to` link for, instead of `Send`ing to an
    /// explicit endpoint — `lantern_kernel::ipc::reply`'s `tag.extra_caps ==
    /// 1` reply-leg transfer, real as of RFC-0010's kernel-side completion.
    /// Lands in whatever destination slot the client registered on its
    /// *original* `Call` (`tag.extra_caps == 2` there — this crate doesn't
    /// manage that side, a client library or the SDK would); this broker's
    /// own dispatch loop is expected to have already `Recv`'d that `Call`
    /// (establishing the `reply_to` link `ipc::reply` needs) before calling
    /// this. The natural shape for "ask, then be granted, in one round trip,"
    /// rather than [`Broker::grant`]'s bare `Recv`-then-`Send`.
    pub fn grant_via_reply(
        &self,
        state: &mut KernelState,
        scratch_slot: CPtr,
        payload: (usize, usize),
    ) -> Result<(), SyscallError> {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 1, flags: 0 });
        frame.set_mr(1, scratch_slot);
        frame.set_mr(2, payload.0);
        frame.set_mr(3, payload.1);
        ipc::reply(state, self.self_tcb, &mut frame)
    }

    /// Marks `badge` revoked. Does **not** touch the kernel capability the
    /// client already holds — the client's `Endpoint` capability to this
    /// broker keeps working at the kernel level; every dispatch the broker
    /// itself handles for `badge` must consult [`Broker::is_revoked`] and
    /// refuse once this is set. `InvalidCapability` if `badge` was never
    /// minted here (or has already been dropped — this broker never reclaims
    /// a badge slot once granted, matching `CNodeInvoke::Delete`'s own
    /// documented no-reclaim gap for the same underlying reason: no
    /// refcounting yet).
    pub fn revoke(&mut self, badge: u64) -> Result<(), SyscallError> {
        let record = self
            .grants
            .iter_mut()
            .flatten()
            .find(|g| g.badge == badge)
            .ok_or(SyscallError::InvalidCapability)?;
        record.revoked = true;
        Ok(())
    }

    /// Whether `badge` should be treated as revoked — **deny by default**: a
    /// badge this broker never minted (or has forgotten) reads as revoked,
    /// not as "not applicable"/permitted. A real dispatch loop calls this
    /// before honouring any request keyed by a client-supplied badge.
    pub fn is_revoked(&self, badge: u64) -> bool {
        self.grants.iter().flatten().find(|g| g.badge == badge).map(|g| g.revoked).unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_kernel::cap::{CNode, CNodeId, Capability, EndpointId, NotificationId};
    use lantern_kernel::object::{Notification, Tcb};

    /// A broker thread (its own CSpace, holding a self-CNode capability at
    /// slot 0 and a shared endpoint at slot 1) and a client thread (its own
    /// CSpace, holding the same shared endpoint at slot 1) — the same
    /// two-party shape `lantern-boot`'s real demo and `lantern_kernel::ipc`'s
    /// own `transfer_tests` use.
    struct Fixture {
        state: KernelState,
        broker: Broker,
        broker_tcb: TcbId,
        client_tcb: TcbId,
        ep_cptr: CPtr,
    }

    fn setup() -> Fixture {
        let mut state = KernelState::new();

        let broker_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let broker_tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(broker_tcb.0 as usize).unwrap().cspace = Some(broker_cnode);
        *state.cnodes.get_mut(broker_cnode.0 as usize).unwrap().slot_mut(0).unwrap() =
            Capability::CNode(broker_cnode);

        let ep_idx = state.endpoints.alloc(lantern_kernel::object::Endpoint::new()).unwrap();
        let ep = Capability::Endpoint { id: EndpointId(ep_idx as u16), badge: 0, rights: Rights::ALL };
        *state.cnodes.get_mut(broker_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;

        let client_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let client_tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(client_tcb.0 as usize).unwrap().cspace = Some(client_cnode);
        *state.cnodes.get_mut(client_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;

        let broker = Broker::new(broker_tcb, 0);
        Fixture { state, broker, broker_tcb, client_tcb, ep_cptr: 1 }
    }

    fn recv_frame(dest_slot: usize) -> TrapFrame {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 1, flags: 0 });
        frame.set_mr(1, dest_slot);
        frame
    }

    #[test]
    fn mint_then_grant_delivers_a_real_capability_to_a_waiting_client() {
        let mut f = setup();
        // Something the broker itself administers -- a Notification with
        // GRANT, standing in for whatever real object type a concrete Phase 2
        // service would hold (a file, a key).
        let notif_idx = f.state.notifications.alloc(Notification::new()).unwrap();
        let source = Capability::Notification {
            id: NotificationId(notif_idx as u16),
            badge: 0,
            rights: Rights::READ.union(Rights::GRANT),
        };
        *f.state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = source;

        // Client blocks in Recv, registering slot 9 as its destination.
        f.state.make_ready(f.broker_tcb);
        f.state.scheduler.current = Some(f.client_tcb);
        let mut frame = recv_frame(9);
        ipc::recv(&mut f.state, f.client_tcb, f.ep_cptr, &mut frame).unwrap();
        assert_eq!(f.state.scheduler.current, Some(f.broker_tcb));

        let badge = f.broker.mint(&mut f.state, 5, 6, Rights::READ.union(Rights::GRANT)).unwrap();
        assert!(!f.broker.is_revoked(badge));

        f.broker.grant(&mut f.state, f.ep_cptr, 6, (111, 222)).unwrap();

        let client_cnode = f.state.tcbs.get(f.client_tcb.0 as usize).unwrap().cspace.unwrap();
        let landed = f.state.cnodes.get(client_cnode.0 as usize).unwrap().get(9).unwrap();
        // Transfer is a real copy of whatever the scratch slot held -- exactly
        // the READ|GRANT that was minted, not attenuated further in transit.
        assert_eq!(landed.rights(), Rights::READ.union(Rights::GRANT));
        assert!(matches!(landed, Capability::Notification { id, .. } if id == NotificationId(notif_idx as u16)));

        // The broker's own scratch copy is untouched -- transfer is a copy.
        assert_eq!(f.state.cnodes.get(0).unwrap().get(6), Some(landed));

        let client_ctx = f.state.tcbs.get(f.client_tcb.0 as usize).unwrap().context;
        assert_eq!(client_ctx.mr(2), 111);
        assert_eq!(client_ctx.mr(3), 222);
    }

    #[test]
    fn mint_rejects_rights_without_grant() {
        let mut f = setup();
        let notif_idx = f.state.notifications.alloc(Notification::new()).unwrap();
        let source = Capability::Notification {
            id: NotificationId(notif_idx as u16),
            badge: 0,
            rights: Rights::READ.union(Rights::GRANT),
        };
        *f.state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = source;

        f.state.scheduler.current = Some(f.broker_tcb);
        // The source itself has GRANT, but the *requested* rights don't --
        // Broker's own policy rejects this before ever calling into the
        // kernel (a mint that can't be granted onward is useless here).
        assert_eq!(f.broker.mint(&mut f.state, 5, 6, Rights::READ), Err(SyscallError::IllegalOperation));
        assert_eq!(f.state.cnodes.get(0).unwrap().get(6), Some(Capability::Null), "nothing minted");
    }

    #[test]
    fn mint_still_enforces_monotone_attenuation_against_the_source() {
        let mut f = setup();
        let notif_idx = f.state.notifications.alloc(Notification::new()).unwrap();
        let source = Capability::Notification {
            id: NotificationId(notif_idx as u16),
            badge: 0,
            rights: Rights::READ.union(Rights::GRANT), // no WRITE
        };
        *f.state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = source;

        f.state.scheduler.current = Some(f.broker_tcb);
        // Broker's own GRANT check passes (WRITE|GRANT includes GRANT), but
        // the kernel's monotone-attenuation check still applies: the source
        // doesn't have WRITE, so Mint can't grant it either.
        assert_eq!(
            f.broker.mint(&mut f.state, 5, 6, Rights::WRITE.union(Rights::GRANT)),
            Err(SyscallError::IllegalOperation)
        );
    }

    #[test]
    fn revoke_marks_the_badge_without_touching_the_clients_capability() {
        let mut f = setup();
        let notif_idx = f.state.notifications.alloc(Notification::new()).unwrap();
        let source = Capability::Notification {
            id: NotificationId(notif_idx as u16),
            badge: 0,
            rights: Rights::READ.union(Rights::GRANT),
        };
        *f.state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = source;

        f.state.make_ready(f.broker_tcb);
        f.state.scheduler.current = Some(f.client_tcb);
        let mut frame = recv_frame(9);
        ipc::recv(&mut f.state, f.client_tcb, f.ep_cptr, &mut frame).unwrap();

        let badge = f.broker.mint(&mut f.state, 5, 6, Rights::READ.union(Rights::GRANT)).unwrap();
        f.broker.grant(&mut f.state, f.ep_cptr, 6, (0, 0)).unwrap();

        f.broker.revoke(badge).unwrap();
        assert!(f.broker.is_revoked(badge));

        // The client's kernel capability is untouched -- it's still sitting
        // in its CSpace, exactly as `grant` placed it. Revocation is enforced
        // by whatever dispatch loop consults `is_revoked`, not by the kernel.
        let client_cnode = f.state.tcbs.get(f.client_tcb.0 as usize).unwrap().cspace.unwrap();
        assert!(f.state.cnodes.get(client_cnode.0 as usize).unwrap().get(9).is_some());
    }

    #[test]
    fn unknown_badge_reads_as_revoked_deny_by_default() {
        let f = setup();
        assert!(f.broker.is_revoked(999));
    }

    #[test]
    fn grant_via_reply_delivers_in_the_same_round_trip_as_a_call() {
        let mut f = setup();
        let notif_idx = f.state.notifications.alloc(Notification::new()).unwrap();
        let source = Capability::Notification {
            id: NotificationId(notif_idx as u16),
            badge: 0,
            rights: Rights::READ.union(Rights::GRANT),
        };
        *f.state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = source;

        // Broker Recv's first (nobody there yet), so it blocks and the client runs.
        f.state.make_ready(f.client_tcb);
        f.state.scheduler.current = Some(f.broker_tcb);
        let mut recv_frame = TrapFrame::zeroed();
        recv_frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 0, flags: 0 });
        ipc::recv(&mut f.state, f.broker_tcb, f.ep_cptr, &mut recv_frame).unwrap();
        assert_eq!(f.state.scheduler.current, Some(f.client_tcb));

        // Client Calls, registering slot 9 as its own reply-leg destination
        // (tag.extra_caps == 2 -- lantern_kernel::ipc::call's own convention,
        // not something this crate manages).
        let mut call_frame = TrapFrame::zeroed();
        call_frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 2, flags: 0 });
        call_frame.set_mr(1, 9);
        ipc::call(&mut f.state, f.client_tcb, f.ep_cptr, &mut call_frame).unwrap();
        assert_eq!(f.state.scheduler.current, Some(f.broker_tcb));

        // Broker mints and replies with the grant attached, in one round trip.
        let badge = f.broker.mint(&mut f.state, 5, 6, Rights::READ.union(Rights::GRANT)).unwrap();
        f.broker.grant_via_reply(&mut f.state, 6, (111, 222)).unwrap();

        assert_eq!(f.state.scheduler.current, Some(f.client_tcb));
        assert!(!f.broker.is_revoked(badge));
        let client_cnode = f.state.tcbs.get(f.client_tcb.0 as usize).unwrap().cspace.unwrap();
        let landed = f.state.cnodes.get(client_cnode.0 as usize).unwrap().get(9).unwrap();
        assert_eq!(landed.rights(), Rights::READ.union(Rights::GRANT));
        assert!(matches!(landed, Capability::Notification { id, .. } if id == NotificationId(notif_idx as u16)));
    }
}
