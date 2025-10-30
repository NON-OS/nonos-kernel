#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};
use core::arch::x86_64::{__cpuid, _rdtsc};
use crate::memory::nonos_layout as layout;

#[derive(Debug)]
pub struct Kaslr {
    pub slide: u64,
    pub entropy_hash: [u8; 32],
    pub boot_nonce: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub align: u64,
    pub window_bytes: u64,
    pub min_slide: u64,
    pub max_slide: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            align: layout::PAGE_SIZE as u64,
            window_bytes: 0x40000000, // 1GB window
            min_slide: 0x10000000,    // 256MB minimum
            max_slide: 0x80000000,    // 2GB maximum
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Range { 
    pub lo: u64, 
    pub hi: u64 
}

impl Range { 
    #[inline] 
    pub const fn contains(&self, x: u64) -> bool { 
        x >= self.lo && x < self.hi 
    } 
}

static BOOT_NONCE: AtomicU64 = AtomicU64::new(0);
static ENTROPY_POOL: AtomicU64 = AtomicU64::new(0x1337DEADBEEF4242);
static KASLR_SLIDE: AtomicU64 = AtomicU64::new(0);

fn secure_hash(data: &[u8]) -> [u8; 32] {
    use sha3::{Sha3_256, Digest};
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn collect_entropy() -> u64 {
    let mut entropy = ENTROPY_POOL.load(Ordering::Relaxed);
    
    unsafe {
        let tsc1 = _rdtsc();
        for _ in 0..1000 { core::hint::spin_loop(); }
        let tsc2 = _rdtsc();
        entropy ^= tsc1.wrapping_mul(tsc2);
    }
    
    unsafe {
        let cpuid0 = __cpuid(0);
        let cpuid1 = __cpuid(1);
        entropy ^= (cpuid0.eax as u64) << 32 | (cpuid0.ebx as u64);
        entropy ^= (cpuid1.ecx as u64) << 16 | (cpuid1.edx as u64);
    }
    
    if has_rdrand() {
        if let Some(hw_rng) = rdrand64() {
            entropy ^= hw_rng;
        }
    }
    
    if has_rdseed() {
        if let Some(hw_rng) = rdseed64() {
            entropy ^= hw_rng;
        }
    }
    
    entropy = entropy.wrapping_mul(0x2545f4914f6cdd1d);
    
    ENTROPY_POOL.store(entropy, Ordering::Relaxed);
    entropy
}

#[inline]
fn has_rdrand() -> bool { 
    unsafe { 
        let cpuid = __cpuid(1); 
        (cpuid.ecx & (1 << 30)) != 0 
    } 
}

#[inline]
fn has_rdseed() -> bool { 
    unsafe { 
        let cpuid = __cpuid(7); 
        (cpuid.ebx & (1 << 18)) != 0 
    } 
}

#[inline]
fn rdrand64() -> Option<u64> {
    unsafe {
        let mut val: u64 = 0;
        let mut success: u8 = 0;
        
        core::arch::asm!(
            "rdrand {val}",
            "setc {success}",
            val = out(reg) val,
            success = out(reg_byte) success,
            options(nostack, preserves_flags)
        );
        
        if success != 0 { Some(val) } else { None }
    }
}

#[inline]
fn rdseed64() -> Option<u64> {
    unsafe {
        let mut val: u64 = 0;
        let mut success: u8 = 0;
        
        core::arch::asm!(
            "rdseed {val}",
            "setc {success}",
            val = out(reg) val,
            success = out(reg_byte) success,
            options(nostack, preserves_flags)
        );
        
        if success != 0 { Some(val) } else { None }
    }
}

fn choose_slide(entropy: u64, policy: Policy) -> Result<u64, &'static str> {
    if policy.min_slide >= policy.max_slide {
        return Err("Invalid KASLR policy: min_slide >= max_slide");
    }
    
    let range = policy.max_slide - policy.min_slide;
    let granularity = if policy.align == 0 { 
        layout::PAGE_SIZE as u64 
    } else { 
        policy.align 
    };
    
    if granularity == 0 {
        return Err("Invalid alignment granularity");
    }
    
    let aligned_range = (range / granularity) * granularity;
    if aligned_range == 0 {
        return Err("KASLR range too small for alignment");
    }
    
    let slide_offset = entropy % aligned_range;
    let aligned_offset = (slide_offset / granularity) * granularity;
    let slide = policy.min_slide + aligned_offset;
    if slide < policy.min_slide || slide >= policy.max_slide {
        return Err("Generated slide out of range");
    }
    
    if slide % granularity != 0 {
        return Err("Generated slide not properly aligned");
    }
    
    Ok(slide)
}

pub fn init(policy: Policy) -> Result<Kaslr, &'static str> {
    let entropy = collect_entropy();
    
    let slide = choose_slide(entropy, policy)?;
    
    let nonce = entropy.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(23);
    
    BOOT_NONCE.store(nonce, Ordering::SeqCst);
    KASLR_SLIDE.store(slide, Ordering::SeqCst);
    
    layout::apply_kaslr_slide(slide)?;
    
    let entropy_bytes = entropy.to_le_bytes();
    let entropy_hash = secure_hash(&entropy_bytes);
    
    Ok(Kaslr { 
        slide, 
        entropy_hash, 
        boot_nonce: nonce 
    })
}

#[inline] 
pub fn boot_nonce() -> Result<u64, &'static str> {
    let nonce = BOOT_NONCE.load(Ordering::Relaxed);
    if nonce == 0 {
        Err("KASLR not initialized")
    } else {
        Ok(nonce)
    }
}

#[inline]
pub fn get_slide() -> u64 {
    KASLR_SLIDE.load(Ordering::Relaxed)
}

pub fn derive_subkey(label: &[u8], output: &mut [u8]) -> Result<(), &'static str> {
    let nonce = boot_nonce()?;
    let slide = get_slide();
    
    let mut input = alloc::vec::Vec::new();
    input.extend_from_slice(b"NONOS-KASLR-KDF:");
    input.extend_from_slice(label);
    input.extend_from_slice(&nonce.to_le_bytes());
    input.extend_from_slice(&slide.to_le_bytes());
    
    let key_hash = secure_hash(&input);
    
    let mut offset = 0;
    while offset < output.len() {
        let remaining = output.len() - offset;
        let copy_len = core::cmp::min(32, remaining);
        
        output[offset..offset + copy_len].copy_from_slice(&key_hash[..copy_len]);
        offset += copy_len;
        
        if offset < output.len() {
            let mut expanded_input = input.clone();
            expanded_input.extend_from_slice(&(offset as u64).to_le_bytes());
            let next_hash = secure_hash(&expanded_input);
            
            let copy_len = core::cmp::min(32, output.len() - offset);
            output[offset..offset + copy_len].copy_from_slice(&next_hash[..copy_len]);
            offset += copy_len;
        }
    }
    
    Ok(())
}


pub fn validate() -> Result<(), &'static str> {
    let slide = get_slide();
    let nonce = boot_nonce()?;
    
    if slide == 0 && nonce == 0 {
        return Err("KASLR not initialized");
    }
    

    if slide % (layout::PAGE_SIZE as u64) != 0 {
        return Err("KASLR slide not page-aligned");
    }
    

    if slide < 0x1000000 || slide > 0x100000000 {
        return Err("KASLR slide out of safe range");
    }
    
    Ok(())
}

pub fn verify_slide_integrity() -> bool {
    if let Ok(_) = validate() {
        let current_slide = get_slide();
        let expected_layout_base = layout::KERNEL_BASE + current_slide;
        
        let actual_layout_base = layout::KERNEL_BASE + current_slide;
        if actual_layout_base != expected_layout_base {
            return false;
        }
        
        let nonce_result = boot_nonce();
        if nonce_result.is_err() {
            return false;
        }
        
        let nonce = match nonce_result {
            Ok(n) => n,
            Err(_) => return false,
        };
        if nonce == 0 {
            return false;
        }
        
        let mut test_buffer = [0u8; 64];
        let seed_label = b"integrity_check";
        
        if let Err(_) = derive_subkey(seed_label, &mut test_buffer) {
            return false;
        }
        
        for byte in test_buffer.iter() {
            if *byte == 0 {
                return false;
            }
        }
        
        let entropy_check = test_buffer.iter().fold(0u8, |acc, &x| acc ^ x);
        if entropy_check == 0 || entropy_check == 0xFF {
            return false;
        }
        
        true
    } else {
        false
    }
}