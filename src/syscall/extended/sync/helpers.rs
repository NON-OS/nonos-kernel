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

use super::constants::*;
use super::types::{FUTEX_WAITER_MAP, FUTEX_WAKES};

pub(super) fn wake_futex(uaddr: u64, max_wake: usize, bitset: u32) -> usize {
    let mut woken = 0;

    if let Some(waiters) = FUTEX_WAITER_MAP.lock().get_mut(&uaddr) {
        let mut i = 0;
        while woken < max_wake && i < waiters.len() {
            if (waiters[i].bitset & bitset) != 0 {
                waiters.remove(i);
                woken += 1;
            } else {
                i += 1;
            }
        }
    }

    FUTEX_WAKES.fetch_add(woken as u64, Ordering::Relaxed);
    woken
}

pub(super) fn decode_wake_op(val3: u64) -> (u32, u32, u32, u32, u32) {
    let val3 = val3 as u32;

    let oparg = val3 & 0xFFF;
    let cmparg = (val3 >> 12) & 0xFFF;
    let op = (val3 >> 24) & 0x7;
    let cmp = (val3 >> 28) & 0x7;
    let shift = if (val3 >> 27) & 1 != 0 { 1 } else { 0 };

    let final_oparg = if shift != 0 { 1u32 << oparg } else { oparg };

    (op, final_oparg, cmp, cmparg, shift)
}

pub(super) fn apply_wake_op(uaddr2: u64, op: u32, oparg: u32) -> u32 {
    // SAFETY: Applying atomic operation to futex memory
    unsafe {
        let ptr = uaddr2 as *mut u32;
        let old_val = core::ptr::read_volatile(ptr);

        let new_val = match op {
            FUTEX_OP_SET => oparg,
            FUTEX_OP_ADD => old_val.wrapping_add(oparg),
            FUTEX_OP_OR => old_val | oparg,
            FUTEX_OP_ANDN => old_val & !oparg,
            FUTEX_OP_XOR => old_val ^ oparg,
            _ => old_val,
        };

        core::ptr::write_volatile(ptr, new_val);
        old_val
    }
}

pub(super) fn eval_wake_op_cmp(cmp: u32, old_val: u32, cmparg: u32) -> bool {
    match cmp {
        FUTEX_OP_CMP_EQ => old_val == cmparg,
        FUTEX_OP_CMP_NE => old_val != cmparg,
        FUTEX_OP_CMP_LT => old_val < cmparg,
        FUTEX_OP_CMP_LE => old_val <= cmparg,
        FUTEX_OP_CMP_GT => old_val > cmparg,
        FUTEX_OP_CMP_GE => old_val >= cmparg,
        _ => false,
    }
}
