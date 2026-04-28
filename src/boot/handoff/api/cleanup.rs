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

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

use super::super::types::BootHandoffV1;
use super::query::BOOT_HANDOFF;

pub fn wipe_sensitive_handoff_data() {
    if let Some(&handoff) = BOOT_HANDOFF.get() {
        let handoff_ptr = handoff as *const BootHandoffV1 as *mut BootHandoffV1;
        unsafe {
            wipe_handoff_secrets(handoff_ptr);
        }
    }
}

unsafe fn wipe_handoff_secrets(handoff: *mut BootHandoffV1) {
    if handoff.is_null() {
        return;
    }

    let h = &mut *handoff;

    wipe_rng_seed(&mut h.rng.seed32);
    wipe_zk_attestation(&mut h.zk);
    wipe_measurements(&mut h.meas);

    compiler_fence(Ordering::SeqCst);
}

fn wipe_rng_seed(seed: &mut [u8; 32]) {
    for b in seed.iter_mut() {
        unsafe {
            ptr::write_volatile(b, 0);
        }
    }
}

fn wipe_zk_attestation(zk: &mut super::super::types::ZkAttestation) {
    for b in zk.program_hash.iter_mut() {
        unsafe {
            ptr::write_volatile(b, 0);
        }
    }
    for b in zk.capsule_commitment.iter_mut() {
        unsafe {
            ptr::write_volatile(b, 0);
        }
    }
    zk.verified = 0;
}

fn wipe_measurements(meas: &mut super::super::types::Measurements) {
    for b in meas.kernel_blake3.iter_mut() {
        unsafe {
            ptr::write_volatile(b, 0);
        }
    }
}
