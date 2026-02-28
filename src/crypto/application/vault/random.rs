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

use crate::crypto::CryptoResult;

pub fn generate_random_bytes(buffer: &mut [u8]) -> CryptoResult<()> {
    for chunk in buffer.chunks_mut(8) {
        let random_u64 = generate_secure_u64()?;
        let bytes = random_u64.to_le_bytes();
        let copy_len = core::cmp::min(chunk.len(), 8);
        chunk[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }
    Ok(())
}

fn generate_secure_u64() -> CryptoResult<u64> {
    for _ in 0..10 {
        if let Some(value) = rdrand_u64() {
            return Ok(value);
        }
    }

    let mut entropy = 0u64;

    unsafe {
        core::arch::asm!("rdtsc", out("rax") entropy, out("rdx") _);
    }

    let stack_addr = &entropy as *const u64 as u64;
    entropy ^= stack_addr;

    let cpuid_result = core::arch::x86_64::__cpuid(1);
    entropy ^= (cpuid_result.ecx as u64) << 32;

    let input_bytes = entropy.to_le_bytes();
    let hash = crate::crypto::blake3::blake3_hash(&input_bytes);
    let result = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
    ]);

    Ok(result)
}

fn rdrand_u64() -> Option<u64> {
    let mut result: u64;
    let success: u8;

    unsafe {
        core::arch::asm!(
            "rdrand {result}",
            "setc {success}",
            result = out(reg) result,
            success = out(reg_byte) success,
            options(nomem, nostack)
        );
    }

    if success != 0 {
        Some(result)
    } else {
        None
    }
}

pub fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    let _ = generate_random_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}
