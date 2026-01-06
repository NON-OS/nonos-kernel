// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicU64, Ordering};
use core::arch::x86_64::{__cpuid, _rdtsc};
use sha3::{Sha3_256, Digest};
use crate::memory::layout;
use super::constants::*;
use super::error::{KaslrError, KaslrResult};
use super::types::*;
static BOOT_NONCE: AtomicU64 = AtomicU64::new(0);
static ENTROPY_POOL: AtomicU64 = AtomicU64::new(INITIAL_ENTROPY_SEED);
static KASLR_SLIDE: AtomicU64 = AtomicU64::new(0);
fn secure_hash(data: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn collect_entropy() -> u64 {
    let mut entropy = ENTROPY_POOL.load(Ordering::Relaxed);

    // SAFETY: _rdtsc is always available on x86_64
    unsafe {
        let tsc1 = _rdtsc();
        for _ in 0..ENTROPY_SPIN_ITERATIONS { core::hint::spin_loop(); }
        let tsc2 = _rdtsc();
        entropy ^= tsc1.wrapping_mul(tsc2);
    }

    // SAFETY: __cpuid is available on all x86_64 CPUs
    unsafe {
        let cpuid0 = __cpuid(0);
        let cpuid1 = __cpuid(CPUID_FEATURES_LEAF);
        entropy ^= (cpuid0.eax as u64) << 32 | (cpuid0.ebx as u64);
        entropy ^= (cpuid1.ecx as u64) << 16 | (cpuid1.edx as u64);
    }

    if has_rdrand() { if let Some(hw_rng) = rdrand64() { entropy ^= hw_rng; } }
    if has_rdseed() { if let Some(hw_rng) = rdseed64() { entropy ^= hw_rng; } }
    entropy = entropy.wrapping_mul(ENTROPY_MIX_MULTIPLIER);
    ENTROPY_POOL.store(entropy, Ordering::Relaxed);
    entropy
}

#[inline]
fn has_rdrand() -> bool {
    // SAFETY: __cpuid only reads CPU feature information
    unsafe { let cpuid = __cpuid(CPUID_FEATURES_LEAF); (cpuid.ecx & (1 << RDRAND_FEATURE_BIT)) != 0 }
}

#[inline]
fn has_rdseed() -> bool {
    // SAFETY: __cpuid only reads CPU feature information
    unsafe { let cpuid = __cpuid(CPUID_EXTENDED_LEAF); (cpuid.ebx & (1 << RDSEED_FEATURE_BIT)) != 0 }
}

#[inline]
fn rdrand64() -> Option<u64> {
    // SAFETY: RDRAND support checked before calling
    unsafe {
        let mut val: u64 = 0;
        let mut success: u8 = 0;
        core::arch::asm!("rdrand {val}", "setc {success}", val = out(reg) val, success = out(reg_byte) success, options(nostack, preserves_flags));
        if success != 0 { Some(val) } else { None }
    }
}

#[inline]
fn rdseed64() -> Option<u64> {
    // SAFETY: RDSEED support checked before calling
    unsafe {
        let mut val: u64 = 0;
        let mut success: u8 = 0;
        core::arch::asm!("rdseed {val}", "setc {success}", val = out(reg) val, success = out(reg_byte) success, options(nostack, preserves_flags));
        if success != 0 { Some(val) } else { None }
    }
}

fn choose_slide(entropy: u64, policy: Policy) -> KaslrResult<u64> {
    if policy.min_slide >= policy.max_slide { return Err(KaslrError::InvalidPolicy); }
    let range = policy.max_slide - policy.min_slide;
    let granularity = if policy.align == 0 { layout::PAGE_SIZE as u64 } else { policy.align };
    if granularity == 0 { return Err(KaslrError::InvalidAlignment); }
    let aligned_range = (range / granularity) * granularity;
    if aligned_range == 0 { return Err(KaslrError::RangeTooSmall); }
    let slide_offset = entropy % aligned_range;
    let aligned_offset = (slide_offset / granularity) * granularity;
    let slide = policy.min_slide + aligned_offset;
    if slide < policy.min_slide || slide >= policy.max_slide { return Err(KaslrError::SlideOutOfRange); }
    if slide % granularity != 0 { return Err(KaslrError::SlideNotAligned); }

    Ok(slide)
}

pub fn init(policy: Policy) -> KaslrResult<Kaslr> {
    let entropy = collect_entropy();
    let slide = choose_slide(entropy, policy)?;
    let nonce = entropy.wrapping_mul(NONCE_GEN_MULTIPLIER).rotate_left(NONCE_ROTATE_BITS);
    BOOT_NONCE.store(nonce, Ordering::SeqCst);
    KASLR_SLIDE.store(slide, Ordering::SeqCst);
    layout::apply_kaslr_slide(slide).map_err(|_| KaslrError::LayoutApplyFailed)?;
    let entropy_bytes = entropy.to_le_bytes();
    let entropy_hash = secure_hash(&entropy_bytes);

    Ok(Kaslr { slide, entropy_hash, boot_nonce: nonce })
}

#[inline]
pub fn boot_nonce() -> KaslrResult<u64> {
    let nonce = BOOT_NONCE.load(Ordering::Relaxed);
    if nonce == 0 { Err(KaslrError::NotInitialized) } else { Ok(nonce) }
}

#[inline]
pub fn get_slide() -> u64 {
    KASLR_SLIDE.load(Ordering::Relaxed)
}

pub fn derive_subkey(label: &[u8], output: &mut [u8]) -> KaslrResult<()> {
    let nonce = boot_nonce()?;
    let slide = get_slide();
    let mut input = alloc::vec::Vec::new();
    input.extend_from_slice(KDF_LABEL_PREFIX);
    input.extend_from_slice(label);
    input.extend_from_slice(&nonce.to_le_bytes());
    input.extend_from_slice(&slide.to_le_bytes());
    let key_hash = secure_hash(&input);
    let mut offset = 0;
    while offset < output.len() {
        let remaining = output.len() - offset;
        let copy_len = core::cmp::min(HASH_OUTPUT_SIZE, remaining);
        output[offset..offset + copy_len].copy_from_slice(&key_hash[..copy_len]);
        offset += copy_len;
        if offset < output.len() {
            let mut expanded_input = input.clone();
            expanded_input.extend_from_slice(&(offset as u64).to_le_bytes());
            let next_hash = secure_hash(&expanded_input);
            let copy_len = core::cmp::min(HASH_OUTPUT_SIZE, output.len() - offset);
            output[offset..offset + copy_len].copy_from_slice(&next_hash[..copy_len]);
            offset += copy_len;
        }
    }
    Ok(())
}

pub fn validate() -> KaslrResult<()> {
    let slide = get_slide();
    let nonce = boot_nonce()?;
    if slide == 0 && nonce == 0 { return Err(KaslrError::NotInitialized); }
    if slide % (layout::PAGE_SIZE as u64) != 0 { return Err(KaslrError::SlideNotAligned); }
    if slide < SAFE_SLIDE_MIN || slide > SAFE_SLIDE_MAX { return Err(KaslrError::SlideOutOfRange); }
    Ok(())
}

pub fn verify_slide_integrity() -> bool {
    if validate().is_err() { return false; }
    let current_slide = get_slide();
    let expected_layout_base = layout::KERNEL_BASE + current_slide;
    let actual_layout_base = layout::KERNEL_BASE + current_slide;
    if actual_layout_base != expected_layout_base { return false; }
    let nonce = match boot_nonce() { Ok(n) => n, Err(_) => return false };
    if nonce == 0 { return false; }
    let mut test_buffer = [0u8; INTEGRITY_CHECK_BUFFER_SIZE];
    if derive_subkey(INTEGRITY_CHECK_LABEL, &mut test_buffer).is_err() { return false; }
    for byte in test_buffer.iter() { if *byte == 0 { return false; } }
    let entropy_check = test_buffer.iter().fold(0u8, |acc, &x| acc ^ x);
    if entropy_check == 0 || entropy_check == 0xFF { return false; }

    true
}

pub fn has_hardware_rng() -> bool {
    has_rdrand() || has_rdseed()
}

pub fn is_initialized() -> bool {
    BOOT_NONCE.load(Ordering::Relaxed) != 0
}
