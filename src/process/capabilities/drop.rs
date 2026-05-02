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

//! Self-targeted, one-way capability drop. The caller passes a mask of
//! bits to remove from its own authority. The implementation only ever
//! AND-NOTs against the canonical `pcb.caps_bits`; no path here can
//! introduce a bit that was not already set.

use core::sync::atomic::Ordering;

use crate::process::{current_pid, with_process_mut};

const ESRCH: i64 = -3;

pub fn sys_cap_drop(mask: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ESRCH,
    };
    let updated = with_process_mut(pid, |pcb| {
        pcb.caps_bits.fetch_and(!mask, Ordering::SeqCst);
        let mut caps = pcb.caps.lock();
        caps.permitted &= !mask;
        caps.effective &= !mask;
        caps.inheritable &= !mask;
        caps.bounding &= !mask;
    });
    if updated.is_none() {
        return ESRCH;
    }
    0
}
