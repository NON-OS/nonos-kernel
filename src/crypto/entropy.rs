// This file is part of the NONOS Operating Systems Kernel.
// 
//  Copyright (C) [2025] [NONOS]
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//! Entropy and RNG for NON-OS

use core::sync::atomic::{AtomicU64, Ordering};

static RNG_STATE: AtomicU64 = AtomicU64::new(1);

pub fn seed_rng() {
    // Initialize with a simple seed
    RNG_STATE.store(0x1337_BEEF_DEAD_CAFE, Ordering::SeqCst);
}

pub fn rand_u64() -> u64 {
    // Simple LFSR for now
    let state = RNG_STATE.load(Ordering::SeqCst);
    let new_state = state.wrapping_mul(1103515245).wrapping_add(12345);
    RNG_STATE.store(new_state, Ordering::SeqCst);
    new_state
}
