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

use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;
use crate::memory::layout;
use super::constants::*;
use super::error::{MemoryError, SafetyResult};
use super::types::*;
struct CorruptionDetector {
    canary_base: u64,
    violations: AtomicUsize,
    last_check: AtomicUsize,
}

struct MemorySafety {
    regions: RwLock<Vec<MemoryRegion>>,
    protection_level: RwLock<ProtectionLevel>,
    corruption_detector: CorruptionDetector,
    access_history: RwLock<Vec<AccessPattern>>,
    initialized: AtomicUsize,
}

pub const REGIONS: &[MemoryRegion] = &[
    MemoryRegion::new(layout::KERNEL_BASE, layout::KERNEL_BASE + 0x400000, "Kernel Text", ProtectionLevel::Cryptographic, true, false, true, false),
    MemoryRegion::new(layout::KHEAP_BASE, layout::KHEAP_BASE + layout::KHEAP_SIZE, "Kernel Heap", ProtectionLevel::Paranoid, true, true, false, false),
    MemoryRegion::new(layout::DIRECTMAP_BASE, layout::DIRECTMAP_BASE + layout::DIRECTMAP_SIZE, "Direct Map", ProtectionLevel::Basic, true, true, false, false),
    MemoryRegion::new(layout::MMIO_BASE, layout::MMIO_BASE + layout::MMIO_SIZE, "MMIO Space", ProtectionLevel::Paranoid, true, true, false, false),
    MemoryRegion::new(VGA_BUFFER_START, VGA_BUFFER_END, "VGA Buffer", ProtectionLevel::Basic, true, true, false, false),
];

static MEMORY_SAFETY: MemorySafety = MemorySafety::new();
impl MemorySafety {
    const fn new() -> Self {
        Self {
            regions: RwLock::new(Vec::new()),
            protection_level: RwLock::new(ProtectionLevel::Basic),
            corruption_detector: CorruptionDetector { canary_base: CANARY_BASE, violations: AtomicUsize::new(0), last_check: AtomicUsize::new(0) },
            access_history: RwLock::new(Vec::new()),
            initialized: AtomicUsize::new(0),
        }
    }

    fn is_initialized(&self) -> bool { self.initialized.load(Ordering::Acquire) != 0 }
    fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() { return Ok(()); }
        let mut regions = self.regions.write();
        for region in REGIONS { regions.push(region.clone()); }
        *self.protection_level.write() = ProtectionLevel::Paranoid;
        Ok(())
    }

    fn validate_access(&self, addr: u64, size: usize, access_type: AccessType) -> SafetyResult<()> {
        if !self.is_initialized() { return Err(MemoryError::NotInitialized); }
        if addr == 0 { return Err(MemoryError::NullPointer); }
        let _end_addr = addr.checked_add(size as u64).ok_or(MemoryError::AddressOverflow)?;
        if size >= layout::PAGE_SIZE && addr % layout::PAGE_SIZE as u64 != 0 { return Err(MemoryError::BadAlignment); }
        let regions = self.regions.read();
        let region = regions.iter().find(|r| r.contains_range(addr, size as u64)).ok_or(MemoryError::UnmappedAccess)?;
        match access_type {
            AccessType::Read if !region.read_allowed => return Err(MemoryError::ReadViolation),
            AccessType::Write if !region.write_allowed => return Err(MemoryError::WriteViolation),
            AccessType::Execute if !region.execute_allowed => return Err(MemoryError::ExecuteViolation),
            _ => {}
        }

        self.record_access(addr, size, access_type);
        if region.protection >= ProtectionLevel::Paranoid { self.check_corruption(addr, size)?; }
        Ok(())
    }

    fn record_access(&self, addr: u64, size: usize, access_type: AccessType) {
        let timestamp = get_timestamp();
        let pattern = AccessPattern { addr, size, timestamp, access_type };
        let mut history = self.access_history.write();
        history.push(pattern);
        if history.len() > ACCESS_HISTORY_MAX { history.remove(0); }
    }

    fn check_corruption(&self, addr: u64, size: usize) -> SafetyResult<()> {
        let canary = self.generate_canary(addr);
        // SAFETY: Address range validated as mapped and accessible
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
        base.wrapping_mul(addr).wrapping_add(CANARY_MIX_CONSTANT)
    }

    fn analyze_patterns(&self) -> Vec<MemoryAnomaly> {
        let history = self.access_history.read();
        let mut anomalies = Vec::new();
        if history.len() < 2 { return anomalies; }
        for window in history.windows(OVERFLOW_DETECTION_WINDOW) {
            if self.detect_buffer_overflow_pattern(window) {
                anomalies.push(MemoryAnomaly::BufferOverflow { start_addr: window[0].addr, pattern_length: window.len() });
            }
        }

        for window in history.windows(UAF_DETECTION_WINDOW) {
            if self.detect_use_after_free_pattern(window) {
                anomalies.push(MemoryAnomaly::UseAfterFree { addr: window[0].addr, confidence: 0.8 });
            }
        }
        anomalies
    }

    fn detect_buffer_overflow_pattern(&self, window: &[AccessPattern]) -> bool {
        let mut sequential_writes = 0;
        let mut last_addr = 0;
        for pattern in window {
            if pattern.access_type == AccessType::Write {
                if pattern.addr > last_addr && pattern.addr - last_addr < SEQUENTIAL_WRITE_GAP {
                    sequential_writes += 1;
                } else { sequential_writes = 0; }
                last_addr = pattern.addr;
            }
            if sequential_writes >= SEQUENTIAL_WRITE_THRESHOLD { return true; }
        }
        false
    }

    fn detect_use_after_free_pattern(&self, window: &[AccessPattern]) -> bool {
        if window.len() < 2 { return false; }
        let first = &window[0];
        let last = &window[window.len() - 1];
        first.addr == last.addr && last.timestamp - first.timestamp > UAF_TIME_THRESHOLD
    }
}

fn get_timestamp() -> u64 {
    // SAFETY: rdtsc is always safe on x86_64
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn is_guard_compromised(addr: u64, size: u64) -> bool {
    if addr == 0 || size == 0 { return true; }
    let mut current_addr = addr;
    while current_addr < addr + size {
        if crate::memory::paging::translate_address(x86_64::VirtAddr::new(current_addr)).is_some() { return true; }
        current_addr += layout::PAGE_SIZE as u64;
    }
    false
}

pub fn init() -> Result<(), &'static str> {
    MEMORY_SAFETY.initialize()
}

pub fn set_protection_level(level: ProtectionLevel) -> Result<(), &'static str> {
    if !MEMORY_SAFETY.is_initialized() { return Err("Memory safety not initialized"); }
    *MEMORY_SAFETY.protection_level.write() = level;
    Ok(())
}

pub fn validate_read(addr: u64, size: usize) -> SafetyResult<()> {
    MEMORY_SAFETY.validate_access(addr, size, AccessType::Read)
}

pub fn validate_write(addr: u64, size: usize) -> SafetyResult<()> {
    MEMORY_SAFETY.validate_access(addr, size, AccessType::Write)
}

pub fn validate_execute(addr: u64, size: usize) -> SafetyResult<()> {
    MEMORY_SAFETY.validate_access(addr, size, AccessType::Execute)
}

pub fn check_integrity() -> Result<Vec<MemoryAnomaly>, &'static str> {
    if !MEMORY_SAFETY.is_initialized() { return Err("Memory safety not initialized"); }
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

pub fn safe_copy(src: u64, dst: u64, size: usize) -> SafetyResult<()> {
    validate_read(src, size)?;
    validate_write(dst, size)?;
    // SAFETY: Both source and destination validated as readable/writable
    unsafe { ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, size); }
    Ok(())
}

pub fn safe_zero(addr: u64, size: usize) -> SafetyResult<()> {
    validate_write(addr, size)?;
    // SAFETY: Address validated as writable
    unsafe { ptr::write_bytes(addr as *mut u8, 0, size); }
    Ok(())
}

pub fn get_guard_regions() -> Vec<GuardRegion> {
    let mut guards = Vec::new();
    for region in layout::get_all_stack_regions() {
        guards.push(GuardRegion { start: region.base - region.guard_size as u64, end: region.base, region_type: GuardType::StackGuard });
        guards.push(GuardRegion { start: region.base + region.size as u64, end: region.base + region.size as u64 + region.guard_size as u64, region_type: GuardType::StackGuard });
    }

    guards.push(GuardRegion { start: layout::KHEAP_BASE - layout::PAGE_SIZE as u64, end: layout::KHEAP_BASE, region_type: GuardType::HeapGuard });
    guards.push(GuardRegion { start: layout::KHEAP_BASE + layout::KHEAP_SIZE, end: layout::KHEAP_BASE + layout::KHEAP_SIZE + layout::PAGE_SIZE as u64, region_type: GuardType::HeapGuard });
    guards
}

pub fn verify_stack_integrity() -> bool {
    let guards = get_guard_regions();
    for guard in guards {
        if matches!(guard.region_type, GuardType::StackGuard) {
            if is_guard_compromised(guard.start, guard.end - guard.start) { return false; }
        }
    }
    // SAFETY: Reading RSP is always safe
    let current_rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) current_rsp); }
    for region in layout::get_all_stack_regions() {
        if current_rsp >= region.base && current_rsp < region.base + region.size as u64 {
            let canary_addr = region.base + region.size as u64 - 8;
            // SAFETY: Address is within valid stack region
            unsafe {
                let canary = (canary_addr as *const u64).read_volatile();
                if canary != CANARY_BASE { return false; }
            }
        }
    }
    true
}
