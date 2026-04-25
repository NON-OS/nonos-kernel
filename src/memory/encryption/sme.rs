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

use super::error::{MemEncryptionError, MemEncryptionResult};
use super::types::EncryptionCapability;
use x86_64::PhysAddr;

const MSR_AMD_SYSCFG: u32 = 0xC0010010;
const MSR_AMD_SMEE: u32 = 0xC0010015;
const SYSCFG_MEM_ENCRYPT_BIT: u64 = 1 << 23;

pub fn init_sme(cap: &EncryptionCapability) -> MemEncryptionResult<()> {
    if !cap.sme_supported {
        return Err(MemEncryptionError::NotSupported);
    }
    let syscfg = rdmsr(MSR_AMD_SYSCFG);
    if (syscfg & SYSCFG_MEM_ENCRYPT_BIT) == 0 {
        return Err(MemEncryptionError::NotSupported);
    }
    Ok(())
}

pub fn get_sme_status() -> (bool, u64) {
    let smee_val = rdmsr(MSR_AMD_SMEE);
    let enabled = (smee_val & 1) != 0;
    (enabled, smee_val)
}

pub fn enable_sme(cap: &EncryptionCapability) -> MemEncryptionResult<u64> {
    if !cap.sme_supported {
        return Err(MemEncryptionError::NotSupported);
    }
    let c_bit_mask = 1u64 << cap.c_bit_position;
    Ok(c_bit_mask)
}

pub fn sme_encrypt_page(phys_addr: PhysAddr, c_bit_mask: u64) -> PhysAddr {
    PhysAddr::new(phys_addr.as_u64() | c_bit_mask)
}

pub fn sme_decrypt_page(phys_addr: PhysAddr, c_bit_mask: u64) -> PhysAddr {
    PhysAddr::new(phys_addr.as_u64() & !c_bit_mask)
}

pub fn is_page_encrypted(phys_addr: PhysAddr, c_bit_mask: u64) -> bool {
    (phys_addr.as_u64() & c_bit_mask) != 0
}

fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high);
    }
    ((high as u64) << 32) | (low as u64)
}

#[allow(dead_code)]
fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high);
    }
}
