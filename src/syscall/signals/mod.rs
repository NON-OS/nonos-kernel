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

pub mod blocked;
pub mod constants;
pub mod delivery;
pub mod handler;
pub mod info;
pub mod pending;
pub mod queue;
pub mod state;
pub mod types;

mod action;
mod mask;
mod send;
mod wait;

pub use constants::*;
pub use delivery::*;
pub use state::*;
pub use types::*;

pub use action::{handle_rt_sigaction, read_sigaction, write_sigaction};
pub use mask::{handle_rt_sigpending, handle_rt_sigprocmask};
pub use send::{handle_kill, handle_rt_sigqueueinfo, handle_tgkill, handle_tkill};
pub use wait::{handle_pause, handle_rt_sigreturn, handle_rt_sigsuspend};

pub use blocked::{
    block_signal, get_blocked_mask, is_blocked, restore_mask, save_mask, set_blocked_mask,
    sigprocmask, unblock_signal,
};
pub use handler::{
    get_action, get_handler, is_caught, is_default, is_ignored, reset_all_handlers,
    reset_to_default, set_action, set_handler,
};
pub use info::{
    copy_siginfo_from_user, copy_siginfo_to_user, SigInfo, SI_KERNEL, SI_QUEUE, SI_TKILL, SI_USER,
};
pub use pending::{
    add_pending, any_deliverable, any_pending, first_deliverable, get_deliverable,
    get_pending_mask, is_pending, remove_pending,
};
pub use queue::{
    clear_pending, dequeue_pending, get_pending_signals, has_pending_signal, pending_count,
    queue_pending, MAX_PENDING_SIGNALS,
};

pub fn send_signal_to_process(pid: u32, sig: u32) -> crate::syscall::SyscallResult {
    send_signal(pid, sig)
}
