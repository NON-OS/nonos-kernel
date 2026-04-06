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
mod stack;
mod timedwait;
mod wait;

pub use constants::*;
pub use types::*;
pub use state::*;
pub use delivery::*;

pub use action::{handle_rt_sigaction, read_sigaction, write_sigaction};
pub use mask::{handle_rt_sigprocmask, handle_rt_sigpending};
pub use wait::{handle_rt_sigreturn, handle_rt_sigsuspend, handle_pause};
pub use timedwait::handle_rt_sigtimedwait;
pub use send::{handle_kill, handle_tgkill, handle_tkill, handle_rt_sigqueueinfo, handle_rt_tgsigqueueinfo};
pub use stack::{handle_sigaltstack, write_siginfo};

pub use blocked::{get_blocked_mask, set_blocked_mask, block_signal, unblock_signal, is_blocked, sigprocmask, save_mask, restore_mask};
pub use handler::{get_handler, set_handler, get_action, set_action, is_ignored, is_default, is_caught, reset_to_default, reset_all_handlers};
pub use info::{SigInfo, copy_siginfo_to_user, copy_siginfo_from_user, SI_USER, SI_KERNEL, SI_QUEUE, SI_TKILL};
pub use pending::{get_pending_mask, add_pending, remove_pending, is_pending, any_pending, get_deliverable, any_deliverable, first_deliverable};
pub use queue::{queue_pending, dequeue_pending, pending_count, clear_pending, get_pending_signals, has_pending_signal, MAX_PENDING_SIGNALS};
