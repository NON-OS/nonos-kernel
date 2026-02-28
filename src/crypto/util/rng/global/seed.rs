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
use core::sync::atomic::Ordering;
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};
use super::super::csprng::ChaChaRng;
use super::super::entropy::{
    collect_seed_entropy_secure, get_tsc_entropy, mark_bootloader_entropy_provided,
};
use super::super::error::{RngError, RngResult};
use super::init::{ensure_initialized, entropy_error_to_rng_error};
use super::state::{
    GLOBAL_STATE, GLOBAL_RNG, STATE_UNINITIALIZED, STATE_INITIALIZING, STATE_INITIALIZED,
};

pub fn seed_rng() -> RngResult<()> {
    ensure_initialized()?;

    let seed = collect_seed_entropy_secure()
        .map_err(entropy_error_to_rng_error)?;

    {
        let mut guard = GLOBAL_RNG.lock();
        if let Some(ref mut rng) = *guard {
            rng.reseed(seed);
        }
    }

    let mut seed_erase = seed;
    for b in &mut seed_erase {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();

    Ok(())
}

pub fn seed_from_bootloader(bootloader_entropy: &[u8; 32]) -> RngResult<()> {
    mark_bootloader_entropy_provided();

    let local_entropy = match collect_seed_entropy_secure() {
        Ok(seed) => seed,
        Err(_) => {
            let mut fallback = [0u8; 32];
            let mut offset = 0;
            while offset < 32 {
                let tsc = get_tsc_entropy();
                let remaining = 32 - offset;
                let copy_len = core::cmp::min(8, remaining);
                fallback[offset..offset + copy_len]
                    .copy_from_slice(&tsc.to_le_bytes()[..copy_len]);
                offset += copy_len;
            }
            fallback
        }
    };

    let mut combined = [0u8; 32];
    for i in 0..32 {
        combined[i] = bootloader_entropy[i] ^ local_entropy[i];
    }

    if GLOBAL_STATE.load(Ordering::Acquire) != STATE_INITIALIZED {
        match GLOBAL_STATE.compare_exchange(
            STATE_UNINITIALIZED,
            STATE_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let rng = ChaChaRng::new(combined);
                *GLOBAL_RNG.lock() = Some(rng);
                GLOBAL_STATE.store(STATE_INITIALIZED, Ordering::Release);
            }
            Err(STATE_INITIALIZING) => {
                while GLOBAL_STATE.load(Ordering::Acquire) == STATE_INITIALIZING {
                    core::hint::spin_loop();
                }
                if let Some(ref mut rng) = *GLOBAL_RNG.lock() {
                    rng.reseed(combined);
                }
            }
            Err(STATE_INITIALIZED) => {
                if let Some(ref mut rng) = *GLOBAL_RNG.lock() {
                    rng.reseed(combined);
                }
            }
            Err(_) => {
                secure_erase_seeds(&mut combined, local_entropy);
                return Err(RngError::NotInitialized);
            }
        }
    } else {
        if let Some(ref mut rng) = *GLOBAL_RNG.lock() {
            rng.reseed(combined);
        }
    }

    secure_erase_seeds(&mut combined, local_entropy);
    Ok(())
}

#[inline]
pub(crate) fn secure_erase_seeds(combined: &mut [u8; 32], mut local: [u8; 32]) {
    for b in combined.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    for b in local.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();
}

pub fn seed_direct(bootloader_entropy: &[u8; 32]) -> RngResult<()> {
    mark_bootloader_entropy_provided();

    let mut combined = [0u8; 32];
    let mut offset = 0;

    while offset < 32 {
        let tsc = get_tsc_entropy();
        let remaining = 32 - offset;
        let copy_len = core::cmp::min(8, remaining);
        combined[offset..offset + copy_len].copy_from_slice(&tsc.to_le_bytes()[..copy_len]);
        offset += copy_len;
    }

    for i in 0..32 {
        combined[i] ^= bootloader_entropy[i];
    }

    if GLOBAL_STATE.load(Ordering::Acquire) != STATE_INITIALIZED {
        match GLOBAL_STATE.compare_exchange(
            STATE_UNINITIALIZED,
            STATE_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let rng = ChaChaRng::new(combined);
                *GLOBAL_RNG.lock() = Some(rng);
                GLOBAL_STATE.store(STATE_INITIALIZED, Ordering::Release);
            }
            Err(STATE_INITIALIZING) => {
                while GLOBAL_STATE.load(Ordering::Acquire) == STATE_INITIALIZING {
                    core::hint::spin_loop();
                }
                if let Some(ref mut rng) = *GLOBAL_RNG.lock() {
                    rng.reseed(combined);
                }
            }
            Err(STATE_INITIALIZED) => {
                if let Some(ref mut rng) = *GLOBAL_RNG.lock() {
                    rng.reseed(combined);
                }
            }
            Err(_) => {
                for b in &mut combined {
                    unsafe { ptr::write_volatile(b, 0) };
                }
                compiler_fence();
                memory_fence();
                return Err(RngError::NotInitialized);
            }
        }
    } else {
        if let Some(ref mut rng) = *GLOBAL_RNG.lock() {
            rng.reseed(combined);
        }
    }

    for b in &mut combined {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();

    Ok(())
}
