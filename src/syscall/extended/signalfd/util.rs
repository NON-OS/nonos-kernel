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

extern crate alloc;

use alloc::vec::Vec;

use crate::syscall::signals::types::PendingSignal;
use crate::syscall::signals::state::{get_signal_state, set_signal_state};

use super::types::{
    SignalfdSiginfo, SignalfdInfo, SignalfdStats,
    SIGNALFD_SIGINFO_SIZE, EINVAL, EAGAIN, EBADF,
};
use super::instance::{SignalfdInstance, SIGNALFD_INSTANCES, FD_TO_SIGNALFD};

pub fn signalfd_read(fd: i32, buf: *mut u8, count: usize) -> Result<usize, i32> {
    if count < SIGNALFD_SIGINFO_SIZE {
        return Err(EINVAL);
    }

    let sfd_id = match FD_TO_SIGNALFD.lock().get(&fd) {
        Some(&id) => id,
        None => return Err(EBADF),
    };

    let mut instances = SIGNALFD_INSTANCES.lock();
    let instance = match instances.get_mut(&sfd_id) {
        Some(inst) => inst,
        None => return Err(EBADF),
    };

    collect_pending_signals(instance);

    if instance.queue.is_empty() {
        if instance.is_nonblock() {
            return Err(EAGAIN);
        }
        return Err(EAGAIN);
    }

    let max_signals = count / SIGNALFD_SIGINFO_SIZE;
    let mut bytes_written = 0;

    for _ in 0..max_signals {
        match instance.dequeue_signal() {
            Some(sig) => {
                let info = SignalfdSiginfo::from_pending(&sig);
                let bytes = info.to_bytes();

                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        buf.add(bytes_written),
                        SIGNALFD_SIGINFO_SIZE,
                    );
                }

                bytes_written += SIGNALFD_SIGINFO_SIZE;
            }
            None => break,
        }
    }

    if bytes_written == 0 {
        if instance.is_nonblock() {
            return Err(EAGAIN);
        }
        return Err(EAGAIN);
    }

    Ok(bytes_written)
}

fn collect_pending_signals(instance: &mut SignalfdInstance) {
    let pid = instance.owner_pid;
    let mut state = get_signal_state(pid);

    let mut to_remove = Vec::new();

    for (i, pending) in state.pending_queue.iter().enumerate() {
        if instance.matches(pending.signo) {
            instance.queue_signal(pending.clone());
            to_remove.push(i);
            state.pending.remove(pending.signo);
        }
    }

    for i in to_remove.into_iter().rev() {
        state.pending_queue.remove(i);
    }

    set_signal_state(pid, state);
}

pub fn signalfd_close(fd: i32) -> Result<(), i32> {
    let sfd_id = match FD_TO_SIGNALFD.lock().remove(&fd) {
        Some(id) => id,
        None => return Err(EBADF),
    };

    let mut instances = SIGNALFD_INSTANCES.lock();
    if let Some(instance) = instances.remove(&sfd_id) {
        let mut state = get_signal_state(instance.owner_pid);
        state.blocked.0 &= !instance.mask.0;
        set_signal_state(instance.owner_pid, state);
    }

    Ok(())
}

pub fn route_signal_to_signalfd(pid: u32, signal: &PendingSignal) -> bool {
    let mut instances = SIGNALFD_INSTANCES.lock();

    for instance in instances.values_mut() {
        if instance.owner_pid == pid && instance.matches(signal.signo) {
            instance.queue_signal(signal.clone());
            return true;
        }
    }

    false
}

pub fn get_signalfd_info(sfd_id: usize) -> Option<SignalfdInfo> {
    let mut instances = SIGNALFD_INSTANCES.lock();
    if let Some(instance) = instances.get_mut(&(sfd_id as u32)) {
        collect_pending_signals(instance);

        Some(SignalfdInfo {
            pending_count: instance.pending_count(),
            mask: instance.mask.0,
        })
    } else {
        None
    }
}

pub fn signalfd_has_pending(sfd_id: usize) -> bool {
    let mut instances = SIGNALFD_INSTANCES.lock();
    if let Some(instance) = instances.get_mut(&(sfd_id as u32)) {
        collect_pending_signals(instance);
        instance.has_pending()
    } else {
        false
    }
}

pub fn fd_to_signalfd_id(fd: i32) -> Option<u32> {
    FD_TO_SIGNALFD.lock().get(&fd).copied()
}

pub fn is_signalfd(fd: i32) -> bool {
    FD_TO_SIGNALFD.lock().contains_key(&fd)
}

pub fn signalfd_count() -> usize {
    SIGNALFD_INSTANCES.lock().len()
}

pub fn get_signalfd_stats() -> SignalfdStats {
    let instances = SIGNALFD_INSTANCES.lock();
    let mut total_pending = 0;
    let mut total_mask_bits = 0u32;

    for inst in instances.values() {
        total_pending += inst.pending_count();
        total_mask_bits += inst.mask.0.count_ones();
    }

    SignalfdStats {
        active_count: instances.len(),
        total_pending_signals: total_pending,
        average_mask_size: if instances.is_empty() {
            0
        } else {
            total_mask_bits as usize / instances.len()
        },
    }
}

pub fn cleanup_process_signalfds(pid: u32) {
    let mut instances = SIGNALFD_INSTANCES.lock();
    let mut fd_map = FD_TO_SIGNALFD.lock();

    let to_remove: Vec<u32> = instances
        .iter()
        .filter(|(_, inst)| inst.owner_pid == pid)
        .map(|(&id, _)| id)
        .collect();

    for id in &to_remove {
        instances.remove(id);
    }

    fd_map.retain(|_, &mut sfd_id| !to_remove.contains(&sfd_id));
}
