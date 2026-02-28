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
    collect_seed_entropy_secure, init_entropy, get_tsc_entropy, EntropyError,
};
use super::super::error::{RngError, RngResult};
use super::state::{
    GLOBAL_STATE, GLOBAL_RNG, STATE_UNINITIALIZED, STATE_INITIALIZING, STATE_INITIALIZED,
};

pub(crate) fn entropy_error_to_rng_error(e: EntropyError) -> RngError {
    match e {
        EntropyError::NoHardwareSource => RngError::EntropyUnavailable,
        EntropyError::HardwareFailure => RngError::EntropyUnavailable,
        EntropyError::InsufficientEntropy => RngError::EntropyUnavailable,
        EntropyError::NotInitialized => RngError::NotInitialized,
    }
}

pub fn init_rng() -> RngResult<()> {
    if GLOBAL_STATE.load(Ordering::Acquire) == STATE_INITIALIZED {
        return Ok(());
    }

    match GLOBAL_STATE.compare_exchange(
        STATE_UNINITIALIZED,
        STATE_INITIALIZING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            if let Err(e) = init_entropy() {
                GLOBAL_STATE.store(STATE_UNINITIALIZED, Ordering::Release);
                return Err(entropy_error_to_rng_error(e));
            }

            let seed = match collect_seed_entropy_secure() {
                Ok(s) => s,
                Err(e) => {
                    GLOBAL_STATE.store(STATE_UNINITIALIZED, Ordering::Release);
                    return Err(entropy_error_to_rng_error(e));
                }
            };

            let rng = ChaChaRng::new(seed);
            *GLOBAL_RNG.lock() = Some(rng);
            GLOBAL_STATE.store(STATE_INITIALIZED, Ordering::Release);

            let mut seed_erase = seed;
            for b in &mut seed_erase {
                unsafe { ptr::write_volatile(b, 0) };
            }
            compiler_fence();
            memory_fence();

            Ok(())
        }
        Err(STATE_INITIALIZING) => {
            while GLOBAL_STATE.load(Ordering::Acquire) == STATE_INITIALIZING {
                core::hint::spin_loop();
            }
            if GLOBAL_STATE.load(Ordering::Acquire) == STATE_INITIALIZED {
                Ok(())
            } else {
                Err(RngError::NotInitialized)
            }
        }
        Err(STATE_INITIALIZED) => Ok(()),
        Err(_) => Err(RngError::NotInitialized),
    }
}

pub fn init_rng_simple() -> RngResult<()> {
    if GLOBAL_STATE.load(Ordering::Acquire) == STATE_INITIALIZED {
        return Ok(());
    }

    match GLOBAL_STATE.compare_exchange(
        STATE_UNINITIALIZED,
        STATE_INITIALIZING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            let mut seed = [0u8; 32];
            let mut offset = 0;

            while offset < 32 {
                let tsc = get_tsc_entropy();
                let remaining = 32 - offset;
                let copy_len = core::cmp::min(8, remaining);
                seed[offset..offset + copy_len].copy_from_slice(&tsc.to_le_bytes()[..copy_len]);
                offset += copy_len;
            }

            let rng = ChaChaRng::new(seed);
            *GLOBAL_RNG.lock() = Some(rng);
            GLOBAL_STATE.store(STATE_INITIALIZED, Ordering::Release);

            for b in &mut seed {
                unsafe { ptr::write_volatile(b, 0) };
            }
            compiler_fence();
            memory_fence();

            Ok(())
        }
        Err(STATE_INITIALIZING) => {
            while GLOBAL_STATE.load(Ordering::Acquire) == STATE_INITIALIZING {
                core::hint::spin_loop();
            }
            Ok(())
        }
        Err(STATE_INITIALIZED) => Ok(()),
        Err(_) => Err(RngError::NotInitialized),
    }
}

pub(crate) fn ensure_initialized() -> RngResult<()> {
    if GLOBAL_STATE.load(Ordering::Acquire) != STATE_INITIALIZED {
        init_rng()?;
    }
    Ok(())
}

pub fn is_initialized() -> bool {
    GLOBAL_STATE.load(Ordering::Acquire) == STATE_INITIALIZED
}
