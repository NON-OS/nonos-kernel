//! NØNOS Advanced Security Module 

#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use alloc::collections::BTreeMap;
use spin::RwLock;

/// Configuration 
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub enable_cet: bool,
    pub enable_smep: bool,
    pub enable_smap: bool,
    pub enable_umip: bool,
    pub enable_mpx: bool,
    pub enable_cfi: bool,
    pub enable_stack_canaries: bool,
    pub enable_aslr: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_cet: true,
            enable_smep: true,
            enable_smap: true,
            enable_umip: true,
            enable_mpx: true,
            enable_cfi: true,
            enable_stack_canaries: true,
            enable_aslr: true,
        }
    }
}

/// Stack canary subsystem
pub struct StackCanary {
    global: AtomicU64,
    per_cpu: RwLock<BTreeMap<u32, u64>>,
    rotations: AtomicU64,
}

impl StackCanary {
    pub fn new() -> Self {
        Self {
            global: AtomicU64::new(Self::gen_canary()),
            per_cpu: RwLock::new(BTreeMap::new()),
            rotations: AtomicU64::new(0),
        }
    }
    fn gen_canary() -> u64 {
        unsafe {
            let mut v = 0u64;
            #[cfg(target_arch = "x86_64")]
            {
                if core::arch::x86_64::_rdrand64_step(&mut v) == 1 { return v; }
            }
            let tsc = core::arch::x86_64::_rdtsc();
            tsc ^ 0xDEAD_BEEF_CAFE_BABE
        }
    }
    pub fn get(&self, cpu: u32) -> u64 {
        let lock = self.per_cpu.read();
        if let Some(c) = lock.get(&cpu) { *c } else { self.global.load(Ordering::Relaxed) }
    }
    pub fn rotate(&self) {
        let new = Self::gen_canary();
        self.global.store(new, Ordering::Release);
        let mut lock = self.per_cpu.write();
        for (_, c) in lock.iter_mut() { *c = Self::gen_canary() ^ new; }
        self.rotations.fetch_add(1, Ordering::Release);
    }
    pub fn verify(&self, cpu: u32, value: u64) -> bool {
        value == self.get(cpu)
    }
}

/// Control Flow Integrity subsystem
pub struct CFI {
    enabled: AtomicBool,
    targets: RwLock<BTreeMap<u64, u32>>,
    violations: AtomicU64,
}
impl CFI {
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            targets: RwLock::new(BTreeMap::new()),
            violations: AtomicU64::new(0),
        }
    }
    pub fn add_target(&self, addr: u64, sig: u32) {
        self.targets.write().insert(addr, sig);
    }
    pub fn validate(&self, addr: u64) -> bool {
        if !self.enabled.load(Ordering::Relaxed) { return true; }
        let lock = self.targets.read();
        lock.contains_key(&addr)
    }
    pub fn enable(&self) { self.enabled.store(true, Ordering::Release); }
}

/// ASLR subsystem
pub struct ASLR {
    entropy_bits: u32,
    kaslr_slide: AtomicU64,
    enabled: AtomicBool,
}
impl ASLR {
    pub fn new(entropy: u32) -> Self {
        Self {
            entropy_bits: entropy,
            kaslr_slide: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
        }
    }
    pub fn randomize(&self, base: u64) -> u64 {
        if !self.enabled.load(Ordering::Relaxed) { return base; }
        let slide = crate::crypto::secure_random_u64() & ((1 << self.entropy_bits) - 1);
        (base + (slide << 12)) & 0xFFFF_FFFF_FFFF_F000
    }
}

/// Main security manager for kernel
pub struct AdvancedSecurityManager {
    pub config: SecurityConfig,
    pub stack_canary: StackCanary,
    pub cfi: CFI,
    pub aslr: ASLR,
    pub violations: AtomicU64,
}

impl AdvancedSecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            stack_canary: StackCanary::new(),
            cfi: CFI::new(),
            aslr: ASLR::new(28),
            config,
            violations: AtomicU64::new(0),
        }
    }
    pub fn init(&self) {
        if self.config.enable_stack_canaries { self.stack_canary.rotate(); }
        if self.config.enable_cfi { self.cfi.enable(); }
        if self.config.enable_aslr { self.aslr.enabled.store(true, Ordering::Release); }
    }
    pub fn report_violation(&self, msg: &str) {
        self.violations.fetch_add(1, Ordering::Release);
        crate::log::security_log!("SECURITY VIOLATION: {}", msg);
    }
    pub fn stats(&self) -> SecurityStats {
        SecurityStats {
            violations: self.violations.load(Ordering::Relaxed),
            canary_rotations: self.stack_canary.rotations.load(Ordering::Relaxed),
            cfi_violations: self.cfi.violations.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct SecurityStats {
    pub violations: u64,
    pub canary_rotations: u64,
    pub cfi_violations: u64,
}

/// Global singleton
static GLOBAL_MANAGER: spin::Once<AdvancedSecurityManager> = spin::Once::new();

pub fn init_advanced_security() -> Result<(), &'static str> {
    let manager = AdvancedSecurityManager::new(SecurityConfig::default());
    manager.init();
    GLOBAL_MANAGER.call_once(|| manager);
    Ok(())
}

pub fn security_manager() -> &'static AdvancedSecurityManager {
    GLOBAL_MANAGER.get().expect("AdvancedSecurityManager not initialized")
}
