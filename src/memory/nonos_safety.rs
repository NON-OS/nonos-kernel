#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::ptr;
use alloc::vec::Vec;
use spin::RwLock;
use crate::memory::nonos_layout as layout;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtectionLevel {
    None,
    Basic,
    Paranoid,
    Cryptographic,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub name: &'static str,
    pub protection: ProtectionLevel,
    pub read_allowed: bool,
    pub write_allowed: bool,
    pub execute_allowed: bool,
    pub user_accessible: bool,
}

impl MemoryRegion {
    pub const fn new(
        start: u64, 
        end: u64, 
        name: &'static str, 
        protection: ProtectionLevel,
        read: bool,
        write: bool,
        execute: bool,
        user: bool
    ) -> Self {
        Self {
            start,
            end,
            name,
            protection,
            read_allowed: read,
            write_allowed: write,
            execute_allowed: execute,
            user_accessible: user,
        }
    }

    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    pub const fn contains_range(&self, addr: u64, size: u64) -> bool {
        let end_addr = addr.saturating_add(size);
        addr >= self.start && end_addr <= self.end
    }
}

#[derive(Debug, Clone, Copy)]
struct AccessPattern {
    addr: u64,
    size: usize,
    timestamp: u64,
    access_type: AccessType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AccessType {
    Read,
    Write,
    Execute,
}

#[derive(Debug)]
struct CorruptionDetector {
    canary_base: u64,
    violations: AtomicUsize,
    last_check: AtomicU64,
}

pub struct MemorySafety {
    regions: RwLock<Vec<MemoryRegion>>,
    protection_level: RwLock<ProtectionLevel>,
    corruption_detector: CorruptionDetector,
    access_history: RwLock<Vec<AccessPattern>>,
    initialized: AtomicUsize,
}

pub const REGIONS: &[MemoryRegion] = &[
    MemoryRegion::new(
        layout::KERNEL_BASE,
        layout::KERNEL_BASE + 0x400000,
        "Kernel Text",
        ProtectionLevel::Cryptographic,
        true, false, true, false
    ),
    MemoryRegion::new(
        layout::KHEAP_BASE,
        layout::KHEAP_BASE + layout::KHEAP_SIZE,
        "Kernel Heap",
        ProtectionLevel::Paranoid,
        true, true, false, false
    ),
    MemoryRegion::new(
        layout::DIRECTMAP_BASE,
        layout::DIRECTMAP_BASE + layout::DIRECTMAP_SIZE,
        "Direct Map",
        ProtectionLevel::Basic,
        true, true, false, false
    ),
    MemoryRegion::new(
        layout::MMIO_BASE,
        layout::MMIO_BASE + layout::MMIO_SIZE,
        "MMIO Space",
        ProtectionLevel::Paranoid,
        true, true, false, false
    ),
    MemoryRegion::new(
        0xB8000,
        0xB8FA0,
        "VGA Buffer",
        ProtectionLevel::Basic,
        true, true, false, false
    ),
];

static MEMORY_SAFETY: MemorySafety = MemorySafety::new();

impl MemorySafety {
    const fn new() -> Self {
        Self {
            regions: RwLock::new(Vec::new()),
            protection_level: RwLock::new(ProtectionLevel::Basic),
            corruption_detector: CorruptionDetector {
                canary_base: 0xDEADBEEFCAFEBABE,
                violations: AtomicUsize::new(0),
                last_check: AtomicU64::new(0),
            },
            access_history: RwLock::new(Vec::new()),
            initialized: AtomicUsize::new(0),
        }
    }

    fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire) != 0
    }

    fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Ok(());
        }

        let mut regions = self.regions.write();
        for region in REGIONS {
            regions.push(region.clone());
        }

        *self.protection_level.write() = ProtectionLevel::Paranoid;
        Ok(())
    }

    fn validate_access(&self, addr: u64, size: usize, access_type: AccessType) -> Result<(), MemoryError> {
        if !self.is_initialized() {
            return Err(MemoryError::NotInitialized);
        }

        if addr == 0 {
            return Err(MemoryError::NullPointer);
        }

        let end_addr = addr.checked_add(size as u64)
            .ok_or(MemoryError::AddressOverflow)?;

        if size >= layout::PAGE_SIZE && addr % layout::PAGE_SIZE as u64 != 0 {
            return Err(MemoryError::BadAlignment);
        }

        let regions = self.regions.read();
        let region = regions.iter()
            .find(|r| r.contains_range(addr, size as u64))
            .ok_or(MemoryError::UnmappedAccess)?;

        match access_type {
            AccessType::Read if !region.read_allowed => {
                return Err(MemoryError::ReadViolation);
            }
            AccessType::Write if !region.write_allowed => {
                return Err(MemoryError::WriteViolation);
            }
            AccessType::Execute if !region.execute_allowed => {
                return Err(MemoryError::ExecuteViolation);
            }
            _ => {}
        }

        self.record_access(addr, size, access_type);

        if region.protection >= ProtectionLevel::Paranoid {
            self.check_corruption(addr, size)?;
        }

        Ok(())
    }

    fn record_access(&self, addr: u64, size: usize, access_type: AccessType) {
        let timestamp = self.get_timestamp();
        let pattern = AccessPattern { addr, size, timestamp, access_type };

        let mut history = self.access_history.write();
        history.push(pattern);

        if history.len() > 1000 {
            history.remove(0);
        }
    }

    fn check_corruption(&self, addr: u64, size: usize) -> Result<(), MemoryError> {
        let canary = self.generate_canary(addr);
        
        unsafe {
            let ptr = addr as *const u64;
            for i in 0..(size / 8) {
                let value = ptr.add(i).read_volatile();
                if value == canary || value == !canary {
                    self.corruption_detector.violations.fetch_add(1, Ordering::Relaxed);
                    return Err(MemoryError::CorruptionDetected);
                }
            }
        }

        Ok(())
    }

    fn generate_canary(&self, addr: u64) -> u64 {
        let base = self.corruption_detector.canary_base;
        base.wrapping_mul(addr).wrapping_add(0x9e3779b97f4a7c15)
    }

    fn get_timestamp(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    fn analyze_patterns(&self) -> Vec<MemoryAnomaly> {
        let history = self.access_history.read();
        let mut anomalies = Vec::new();

        if history.len() < 2 {
            return anomalies;
        }

        for window in history.windows(10) {
            if self.detect_buffer_overflow_pattern(window) {
                anomalies.push(MemoryAnomaly::BufferOverflow {
                    start_addr: window[0].addr,
                    pattern_length: window.len(),
                });
            }
        }

        for window in history.windows(50) {
            if self.detect_use_after_free_pattern(window) {
                anomalies.push(MemoryAnomaly::UseAfterFree {
                    addr: window[0].addr,
                    confidence: 0.8,
                });
            }
        }

        anomalies
    }

    fn detect_buffer_overflow_pattern(&self, window: &[AccessPattern]) -> bool {
        let mut sequential_writes = 0;
        let mut last_addr = 0;

        for pattern in window {
            if pattern.access_type == AccessType::Write {
                if pattern.addr > last_addr && pattern.addr - last_addr < 64 {
                    sequential_writes += 1;
                } else {
                    sequential_writes = 0;
                }
                last_addr = pattern.addr;
            }

            if sequential_writes >= 5 {
                return true;
            }
        }

        false
    }

    fn detect_use_after_free_pattern(&self, window: &[AccessPattern]) -> bool {
        if window.len() < 2 {
            return false;
        }

        let first = &window[0];
        let last = &window[window.len() - 1];

        first.addr == last.addr && 
        last.timestamp - first.timestamp > 1000000
    }
}

#[derive(Debug)]
pub enum MemoryError {
    NotInitialized,
    NullPointer,
    AddressOverflow,
    BadAlignment,
    UnmappedAccess,
    ReadViolation,
    WriteViolation,
    ExecuteViolation,
    CorruptionDetected,
}

#[derive(Debug)]
pub enum MemoryAnomaly {
    BufferOverflow {
        start_addr: u64,
        pattern_length: usize,
    },
    UseAfterFree {
        addr: u64,
        confidence: f32,
    },
}

pub fn init() -> Result<(), &'static str> {
    MEMORY_SAFETY.initialize()
}

pub fn set_protection_level(level: ProtectionLevel) -> Result<(), &'static str> {
    if !MEMORY_SAFETY.is_initialized() {
        return Err("Memory safety not initialized");
    }
    
    *MEMORY_SAFETY.protection_level.write() = level;
    Ok(())
}

pub fn validate_read(addr: u64, size: usize) -> Result<(), MemoryError> {
    MEMORY_SAFETY.validate_access(addr, size, AccessType::Read)
}

pub fn validate_write(addr: u64, size: usize) -> Result<(), MemoryError> {
    MEMORY_SAFETY.validate_access(addr, size, AccessType::Write)
}

pub fn validate_execute(addr: u64, size: usize) -> Result<(), MemoryError> {
    MEMORY_SAFETY.validate_access(addr, size, AccessType::Execute)
}

pub fn check_integrity() -> Result<Vec<MemoryAnomaly>, &'static str> {
    if !MEMORY_SAFETY.is_initialized() {
        return Err("Memory safety not initialized");
    }

    Ok(MEMORY_SAFETY.analyze_patterns())
}

pub fn get_stats() -> MemoryStats {
    MemoryStats {
        violations: MEMORY_SAFETY.corruption_detector.violations.load(Ordering::Relaxed),
        protection_level: *MEMORY_SAFETY.protection_level.read(),
        regions_count: MEMORY_SAFETY.regions.read().len(),
        access_patterns: MEMORY_SAFETY.access_history.read().len(),
    }
}

#[derive(Debug)]
pub struct MemoryStats {
    pub violations: usize,
    pub protection_level: ProtectionLevel,
    pub regions_count: usize,
    pub access_patterns: usize,
}

pub fn safe_copy(src: u64, dst: u64, size: usize) -> Result<(), MemoryError> {
    validate_read(src, size)?;
    validate_write(dst, size)?;
    
    unsafe {
        ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, size);
    }
    
    Ok(())
}

pub fn safe_zero(addr: u64, size: usize) -> Result<(), MemoryError> {
    validate_write(addr, size)?;
    
    unsafe {
        ptr::write_bytes(addr as *mut u8, 0, size);
    }
    
    Ok(())
}

#[derive(Debug, Clone)]
pub struct GuardRegion {
    pub start: u64,
    pub end: u64,
    pub region_type: GuardType,
}

#[derive(Debug, Clone, Copy)]
pub enum GuardType {
    StackGuard,
    HeapGuard,
    RedZone,
    Canary,
}

pub fn get_guard_regions() -> alloc::vec::Vec<GuardRegion> {
    let mut guards = alloc::vec::Vec::new();
    
    let stack_regions = crate::memory::layout::get_all_stack_regions();
    for region in stack_regions {
        guards.push(GuardRegion {
            start: region.base - region.guard_size as u64,
            end: region.base,
            region_type: GuardType::StackGuard,
        });
        
        guards.push(GuardRegion {
            start: region.base + region.size as u64,
            end: region.base + region.size as u64 + region.guard_size as u64,
            region_type: GuardType::StackGuard,
        });
    }
    
    guards.push(GuardRegion {
        start: crate::memory::layout::KHEAP_BASE - crate::memory::layout::PAGE_SIZE as u64,
        end: crate::memory::layout::KHEAP_BASE,
        region_type: GuardType::HeapGuard,
    });
    
    guards.push(GuardRegion {
        start: crate::memory::layout::KHEAP_BASE + crate::memory::layout::KHEAP_SIZE,
        end: crate::memory::layout::KHEAP_BASE + crate::memory::layout::KHEAP_SIZE + crate::memory::layout::PAGE_SIZE as u64,
        region_type: GuardType::HeapGuard,
    });
    
    guards
}

pub fn verify_stack_integrity() -> bool {
    let guards = get_guard_regions();
    for guard in guards {
        if matches!(guard.region_type, GuardType::StackGuard) {
            if is_guard_compromised(guard.start, guard.end - guard.start) {
                return false;
            }
        }
    }
    
    let current_rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp);
    }
    
    let stack_regions = crate::memory::layout::get_all_stack_regions();
    for region in stack_regions {
        if current_rsp >= region.base && current_rsp < region.base + region.size as u64 {
            let canary_addr = region.base + region.size as u64 - 8;
            unsafe {
                let canary = (canary_addr as *const u64).read_volatile();
                if canary != 0xDEADBEEFCAFEBABE {
                    return false;
                }
            }
        }
    }
    
    true
}

fn is_guard_compromised(addr: u64, size: u64) -> bool {
    if addr == 0 || size == 0 {
        return true;
    }
    
    let mut current_addr = addr;
    
    while current_addr < addr + size {
        match crate::memory::paging::translate_address(x86_64::VirtAddr::new(current_addr)) {
            Some(_) => {
                return true;
            }
            None => {}
        }
        current_addr += crate::memory::layout::PAGE_SIZE as u64;
    }
    
    false
}