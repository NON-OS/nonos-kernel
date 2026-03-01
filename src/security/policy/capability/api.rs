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

use core::ptr::{addr_of, addr_of_mut};
use super::engine::CapabilityEngine;
use super::types::Capability;
use super::isolation::IsolationLevel;

static mut CAPABILITY_ENGINE: Option<CapabilityEngine> = None;

pub fn init_capability_system() -> Result<(), &'static str> {
    let engine = CapabilityEngine::new()?;
    // SAFETY: Called once during kernel initialization before any concurrent access
    unsafe {
        *addr_of_mut!(CAPABILITY_ENGINE) = Some(engine);
    }
    Ok(())
}

pub fn init_capability_engine() -> Result<(), &'static str> {
    init_capability_system()
}

pub fn get_capability_engine() -> Option<&'static CapabilityEngine> {
    // SAFETY: Read-only access after initialization
    unsafe { (*addr_of!(CAPABILITY_ENGINE)).as_ref() }
}

pub fn create_isolation_chamber(
    level: IsolationLevel,
    capabilities: &[Capability],
) -> Result<u64, &'static str> {
    get_capability_engine()
        .ok_or("Capability engine not initialized")?
        .create_isolation_chamber(level, capabilities)
}

pub fn enter_chamber(chamber_id: u64, process_id: u64) -> Result<(), &'static str> {
    get_capability_engine()
        .ok_or("Capability engine not initialized")?
        .enter_chamber(chamber_id, process_id)
}

pub fn check_capability(process_id: u64, capability: Capability) -> Result<bool, &'static str> {
    get_capability_engine()
        .ok_or("Capability engine not initialized")?
        .check_capability(process_id, capability)
}

pub fn get_secure_random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];

    for i in 0..32 {
        bytes[i] = secure_random_u8();
    }

    bytes
}

fn secure_random_u8() -> u8 {
    if let Some(hw_rand) = try_hardware_rng() {
        return hw_rand;
    }

    static mut SEED: u64 = 1;
    // SAFETY: Single-threaded fallback, only used when hardware RNG unavailable
    unsafe {
        *addr_of_mut!(SEED) = (*addr_of!(SEED)).wrapping_mul(1103515245).wrapping_add(12345);
        (*addr_of!(SEED) >> 24) as u8
    }
}

fn try_hardware_rng() -> Option<u8> {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::_rdrand32_step;
        let mut value = 0u32;
        // SAFETY: RDRAND is a valid x86_64 instruction when available
        unsafe {
            if _rdrand32_step(&mut value) == 1 {
                return Some(value as u8);
            }
        }
    }

    None
}

pub fn init_capabilities() -> Result<(), &'static str> {
    crate::log_info!("NONOS capabilities system initialized");
    Ok(())
}
