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

use super::super::types::ModuleHash;
use super::types::AttestationManager;
use crate::crypto::hash::blake3_hash;
use crate::memory::VirtAddr;
use crate::zk_engine::ZKError;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn hash_loaded_modules(_mgr: &AttestationManager) -> Result<Vec<ModuleHash>, ZKError> {
    let mut modules = Vec::new();
    let module_regions = crate::memory::layout::get_module_regions();
    for region in module_regions {
        let start = region.base as *const u8;
        let size = region.size;
        let mut module_hash_input = Vec::new();
        let mut offset = 0;
        while offset < size {
            let chunk_size = core::cmp::min(4096, size - offset);
            let chunk_ptr = unsafe { start.add(offset) };
            let chunk = unsafe { core::slice::from_raw_parts(chunk_ptr, chunk_size) };
            module_hash_input.extend_from_slice(&blake3_hash(chunk));
            offset += chunk_size;
        }
        modules.push(ModuleHash {
            name: String::from(region.name),
            hash: blake3_hash(&module_hash_input),
            address: VirtAddr::new(region.base),
            size: region.size,
        });
    }
    let critical_drivers = crate::drivers::get_critical_drivers();
    for driver in critical_drivers {
        modules.push(ModuleHash {
            name: String::from(driver.name),
            hash: driver.hash,
            address: VirtAddr::new(driver.base_address as u64),
            size: driver.size,
        });
    }
    Ok(modules)
}

pub(super) fn hash_kernel_config(_mgr: &AttestationManager) -> Result<[u8; 32], ZKError> {
    let mut config_input = Vec::new();
    config_input.extend_from_slice(b"NONOS_VERSION=");
    config_input.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
    config_input.push(b'\n');
    config_input.extend_from_slice(b"TARGET=x86_64-unknown-none\n");
    config_input.extend_from_slice(b"CONFIG_ZK_ENGINE=y\nCONFIG_KPTI=y\nCONFIG_KASLR=y\n");
    config_input.extend_from_slice(b"CONFIG_STACK_PROTECTOR=y\nCONFIG_SMAP=y\nCONFIG_SMEP=y\n");
    let slide = crate::memory::layout::get_slide();
    if slide != 0 {
        config_input.extend_from_slice(b"KASLR_ACTIVE=y\nKASLR_SLIDE=");
        config_input.extend_from_slice(&slide.to_le_bytes());
        config_input.push(b'\n');
    }
    #[cfg(target_arch = "x86_64")]
    {
        let cpuid_result = core::arch::x86_64::__cpuid(1);
        config_input.extend_from_slice(b"CPUID_1_ECX=");
        config_input.extend_from_slice(&cpuid_result.ecx.to_le_bytes());
        config_input.push(b'\n');
        config_input.extend_from_slice(b"CPUID_1_EDX=");
        config_input.extend_from_slice(&cpuid_result.edx.to_le_bytes());
        config_input.push(b'\n');
    }
    Ok(blake3_hash(&config_input))
}
