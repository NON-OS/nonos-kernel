// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::Ordering;

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;
use crate::syscall::signals::types::SigSet;
use crate::syscall::signals::state::{get_signal_state, set_signal_state};

use super::types::{SFD_CLOEXEC, SFD_NONBLOCK, EINVAL, ENOMEM, EBADF};
use super::instance::{
    SignalfdInstance, SIGNALFD_INSTANCES, NEXT_SIGNALFD_ID,
    FD_TO_SIGNALFD, MAX_SIGNALFD_INSTANCES, allocate_signalfd_fd, current_pid,
};

pub fn handle_signalfd(fd: i32, mask: u64, _sizemask: u64) -> SyscallResult {
    handle_signalfd4(fd, mask, _sizemask, 0)
}

pub fn handle_signalfd4(fd: i32, mask: u64, _sizemask: u64, flags: i32) -> SyscallResult {
    let valid_flags = SFD_CLOEXEC | SFD_NONBLOCK;
    if (flags & !valid_flags) != 0 {
        return errno(EINVAL);
    }

    let sig_mask = SigSet(mask);

    if fd == -1 {
        let instances = SIGNALFD_INSTANCES.lock();
        if instances.len() >= MAX_SIGNALFD_INSTANCES {
            drop(instances);
            return errno(ENOMEM);
        }
        drop(instances);

        let sfd_id = NEXT_SIGNALFD_ID.fetch_add(1, Ordering::SeqCst);
        let pid = current_pid();
        let instance = SignalfdInstance::new(sfd_id, sig_mask, flags, pid);

        SIGNALFD_INSTANCES.lock().insert(sfd_id, instance);

        let new_fd = allocate_signalfd_fd();
        FD_TO_SIGNALFD.lock().insert(new_fd, sfd_id);

        block_signals_for_signalfd(pid, &sig_mask);

        SyscallResult {
            value: new_fd as i64,
            capability_consumed: false,
            audit_required: false,
        }
    } else {
        let sfd_id = match FD_TO_SIGNALFD.lock().get(&fd) {
            Some(&id) => id,
            None => return errno(EBADF),
        };

        let mut instances = SIGNALFD_INSTANCES.lock();
        match instances.get_mut(&sfd_id) {
            Some(instance) => {
                let old_mask = instance.mask;
                let pid = instance.owner_pid;

                instance.set_mask(sig_mask);

                unblock_signals_for_signalfd(pid, &old_mask);
                block_signals_for_signalfd(pid, &sig_mask);

                SyscallResult {
                    value: fd as i64,
                    capability_consumed: false,
                    audit_required: false,
                }
            }
            None => errno(EBADF),
        }
    }
}

fn block_signals_for_signalfd(pid: u32, mask: &SigSet) {
    let mut state = get_signal_state(pid);
    state.blocked.0 |= mask.0;
    set_signal_state(pid, state);
}

fn unblock_signals_for_signalfd(pid: u32, mask: &SigSet) {
    let mut state = get_signal_state(pid);
    state.blocked.0 &= !mask.0;
    set_signal_state(pid, state);
}
