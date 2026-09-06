//! The kernel operations a [`crate::Broker`] issues, abstracted behind a trait
//! so the *same* broker logic runs in two places
//! ([RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md) /
//! [ADR-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0022-confined-service-model-and-call-transport.md)):
//!
//! - [`Abi`] — a confined U-mode program. Every operation is a real `ecall`
//!   through [`lantern_abi::sys`]. Depends on nothing from the TCB.
//! - [`KernelBackend`] (feature `kernel-backend`) — a privileged,
//!   same-address-space caller (a root task) or a host test, calling
//!   `lantern_kernel` directly with a `&mut KernelState`.
//!
//! `Broker` itself is written once, against [`BrokerBackend`], and never
//! mentions either.

use lantern_abi::wire::{CPtr, Rights, SyscallError};

/// The three kernel operations [`crate::Broker`] performs. All slot arguments
/// name slots in the broker's own single CNode.
pub trait BrokerBackend {
    /// `CNodeInvoke::Mint` — place an attenuated (`rights` ⊆ source rights),
    /// `badge`-stamped copy of `src` into the empty slot `dest`. `self_cnode`
    /// names the broker's capability to its own CNode.
    fn mint(
        &mut self,
        self_cnode: CPtr,
        src: CPtr,
        dest: CPtr,
        badge: u64,
        rights: Rights,
    ) -> Result<(), SyscallError>;

    /// `Send` with `tag.extra_caps == 1` — transfer the capability in
    /// `transfer_slot` to a receiver waiting on `endpoint` with a registered
    /// destination slot. `payload` becomes the delivered `mr2`/`mr3`.
    fn grant_send(
        &mut self,
        endpoint: CPtr,
        transfer_slot: CPtr,
        payload: (usize, usize),
    ) -> Result<(), SyscallError>;

    /// `Reply` with `tag.extra_caps == 1` — transfer the capability in
    /// `transfer_slot` to whichever `Call` this thread is currently the
    /// `reply_to` target of.
    fn grant_reply(
        &mut self,
        transfer_slot: CPtr,
        payload: (usize, usize),
    ) -> Result<(), SyscallError>;
}

/// The confined backend: every operation is an `ecall` via [`lantern_abi::sys`].
/// Zero-sized — a confined program is a single thread the kernel identifies as
/// `current`, so there is no `TcbId` to carry.
#[derive(Clone, Copy, Debug, Default)]
pub struct Abi;

impl BrokerBackend for Abi {
    fn mint(
        &mut self,
        self_cnode: CPtr,
        src: CPtr,
        dest: CPtr,
        badge: u64,
        rights: Rights,
    ) -> Result<(), SyscallError> {
        lantern_abi::sys::cnode::mint(self_cnode, src, dest, badge, rights)
    }

    fn grant_send(
        &mut self,
        endpoint: CPtr,
        transfer_slot: CPtr,
        payload: (usize, usize),
    ) -> Result<(), SyscallError> {
        lantern_abi::sys::send_with_cap(endpoint, transfer_slot, [payload.0, payload.1])
    }

    fn grant_reply(
        &mut self,
        transfer_slot: CPtr,
        payload: (usize, usize),
    ) -> Result<(), SyscallError> {
        lantern_abi::sys::reply_with_cap(transfer_slot, [payload.0, payload.1])
    }
}

#[cfg(feature = "kernel-backend")]
pub use kernel::KernelBackend;

#[cfg(feature = "kernel-backend")]
mod kernel {
    use lantern_abi::wire::{CPtr, Rights, SyscallError};
    use lantern_hal::{MessageTag, TrapFrame};
    use lantern_kernel::cap::{Rights as KRights, TcbId};
    use lantern_kernel::{cnode, ipc};
    use lantern_kernel::state::KernelState;

    use super::BrokerBackend;

    /// The privileged backend: a `&mut KernelState` and the invoking thread's
    /// identity. Valid only for same-address-space, TCB-resident code (a root
    /// task) and host tests — a confined program has no such pointer.
    pub struct KernelBackend<'a> {
        state: &'a mut KernelState,
        tcb: TcbId,
    }

    impl<'a> KernelBackend<'a> {
        pub fn new(state: &'a mut KernelState, tcb: TcbId) -> Self {
            Self { state, tcb }
        }
    }

    /// The kernel's `SyscallError` and `lantern-abi`'s mirror it — map by code
    /// so `Broker`'s single error type is the ABI one.
    fn to_abi(e: lantern_kernel::error::SyscallError) -> SyscallError {
        SyscallError::from_code(e.code())
    }

    fn krights(r: Rights) -> KRights {
        KRights::from_bits_truncate(r.bits())
    }

    impl BrokerBackend for KernelBackend<'_> {
        fn mint(
            &mut self,
            self_cnode: CPtr,
            src: CPtr,
            dest: CPtr,
            badge: u64,
            rights: Rights,
        ) -> Result<(), SyscallError> {
            let packed = ((badge as usize) << 8) | krights(rights).bits() as usize;
            let mut frame = TrapFrame::zeroed();
            frame.set_tag(MessageTag { label: cnode::LABEL_MINT, length: 0, extra_caps: 0, flags: 0 });
            frame.set_mr(1, src);
            frame.set_mr(2, dest);
            frame.set_mr(3, packed);
            cnode::invoke(self.state, self.tcb, self_cnode, &mut frame).map_err(to_abi)
        }

        fn grant_send(
            &mut self,
            endpoint: CPtr,
            transfer_slot: CPtr,
            payload: (usize, usize),
        ) -> Result<(), SyscallError> {
            let mut frame = TrapFrame::zeroed();
            frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 1, flags: 0 });
            frame.set_mr(1, transfer_slot);
            frame.set_mr(2, payload.0);
            frame.set_mr(3, payload.1);
            ipc::send(self.state, self.tcb, endpoint, &mut frame, false).map_err(to_abi)
        }

        fn grant_reply(
            &mut self,
            transfer_slot: CPtr,
            payload: (usize, usize),
        ) -> Result<(), SyscallError> {
            let mut frame = TrapFrame::zeroed();
            frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 1, flags: 0 });
            frame.set_mr(1, transfer_slot);
            frame.set_mr(2, payload.0);
            frame.set_mr(3, payload.1);
            ipc::reply(self.state, self.tcb, &mut frame).map_err(to_abi)
        }
    }
}
