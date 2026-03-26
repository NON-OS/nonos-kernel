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

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub(super) const MAX_CAPSULES: usize = 32;
pub(super) const TREASURY: [u8; 20] = [0xa9,0x4d,0x60,0x09,0x79,0x0b,0xa1,0x35,0x97,0xa1,0xe1,0xb7,0xcf,0x4e,0x15,0x31,0xea,0x51,0x36,0x13];

#[derive(Clone, Copy)]
pub(super) struct Capsule {
    pub(super) app_idx: u8,
    pub(super) fee_paid: u32,
    pub(super) install_time: u64,
    pub(super) launches: u32,
    pub(super) active: bool,
}

impl Default for Capsule {
    fn default() -> Self { Self { app_idx: 0, fee_paid: 0, install_time: 0, launches: 0, active: false } }
}

static CAPSULES: Mutex<[Capsule; MAX_CAPSULES]> = Mutex::new([Capsule { app_idx: 0, fee_paid: 0, install_time: 0, launches: 0, active: false }; MAX_CAPSULES]);
static CAPSULE_COUNT: AtomicU32 = AtomicU32::new(0);

pub(super) fn create_capsule(app_idx: usize, fee: u32) -> Option<usize> {
    let mut caps = CAPSULES.lock();
    for (i, c) in caps.iter_mut().enumerate() {
        if !c.active {
            c.app_idx = app_idx as u8;
            c.fee_paid = fee;
            c.install_time = crate::time::timestamp_millis() / 1000;
            c.launches = 0;
            c.active = true;
            CAPSULE_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(i);
        }
    }
    None
}

