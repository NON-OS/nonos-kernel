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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use x86_64::PhysAddr;
use super::error::NvmeError;
use super::namespace::Namespace;
use super::constants::{KERNEL_PHYS_START, KERNEL_PHYS_END, MAX_DMA_SIZE, DEFAULT_RATE_LIMIT_PER_SEC, RATE_WINDOW_MS};

pub struct RateLimiter {
    commands_in_window: AtomicU32,
    window_start_ticks: AtomicU64,
    limit_per_second: AtomicU32,
    enabled: bool,
}

impl RateLimiter {
    pub const fn new(limit_per_second: u32) -> Self {
        Self {
            commands_in_window: AtomicU32::new(0),
            window_start_ticks: AtomicU64::new(0),
            limit_per_second: AtomicU32::new(limit_per_second),
            enabled: limit_per_second > 0,
        }
    }

    pub fn check(&self) -> Result<(), NvmeError> {
        if !self.enabled {
            return Ok(());
        }

        let limit = self.limit_per_second.load(Ordering::Relaxed);
        if limit == 0 {
            return Ok(());
        }

        let now_ticks = Self::current_ticks();
        let window_start = self.window_start_ticks.load(Ordering::Relaxed);
        let ticks_per_window = Self::ticks_per_ms() * RATE_WINDOW_MS;
        if now_ticks.saturating_sub(window_start) >= ticks_per_window {
            self.window_start_ticks.store(now_ticks, Ordering::Relaxed);
            self.commands_in_window.store(1, Ordering::Relaxed);
            return Ok(());
        }

        let current = self.commands_in_window.fetch_add(1, Ordering::Relaxed);
        if current >= limit {
            self.commands_in_window.fetch_sub(1, Ordering::Relaxed);
            return Err(NvmeError::RateLimitExceeded);
        }

        Ok(())
    }

    pub fn set_limit(&self, limit: u32) {
        self.limit_per_second.store(limit, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.commands_in_window.store(0, Ordering::Relaxed);
        self.window_start_ticks.store(0, Ordering::Relaxed);
    }

    pub fn current_rate(&self) -> u32 {
        self.commands_in_window.load(Ordering::Relaxed)
    }

    #[inline]
    fn current_ticks() -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: rdtsc is always available on x86_64
            unsafe { core::arch::x86_64::_rdtsc() }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            0
        }
    }

    #[inline]
    fn ticks_per_ms() -> u64 {
        2_000_000
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_RATE_LIMIT_PER_SEC)
    }
}

pub struct LbaValidator;

impl LbaValidator {
    pub fn validate(ns: &Namespace, start_lba: u64, block_count: u16) -> Result<(), NvmeError> {
        if block_count == 0 {
            return Err(NvmeError::InvalidBlockCount);
        }

        let end_lba = start_lba
            .checked_add(block_count as u64)
            .ok_or(NvmeError::LbaRangeOverflow)?;

        if end_lba > ns.block_count() {
            return Err(NvmeError::LbaExceedsCapacity);
        }

        Ok(())
    }

    pub fn validate_range(capacity: u64, start_lba: u64, block_count: u16) -> Result<(), NvmeError> {
        if block_count == 0 {
            return Err(NvmeError::InvalidBlockCount);
        }

        let end_lba = start_lba
            .checked_add(block_count as u64)
            .ok_or(NvmeError::LbaRangeOverflow)?;

        if end_lba > capacity {
            return Err(NvmeError::LbaExceedsCapacity);
        }

        Ok(())
    }
}

pub struct DmaValidator;

impl DmaValidator {
    pub fn validate_buffer(phys_addr: PhysAddr, size: usize) -> Result<(), NvmeError> {
        let start = phys_addr.as_u64();

        if size == 0 {
            return Err(NvmeError::DmaBufferSizeZero);
        }

        if size > MAX_DMA_SIZE {
            return Err(NvmeError::DmaBufferTooLarge);
        }

        let end = start
            .checked_add(size as u64)
            .ok_or(NvmeError::DmaBufferAddressOverflow)?;

        if Self::overlaps_kernel(start, end) {
            return Err(NvmeError::DmaBufferOverlapsKernel);
        }

        Ok(())
    }

    pub fn validate_prp(prp: u64, page_size: usize) -> Result<(), NvmeError> {
        if (prp as usize) & 0x3 != 0 {
            return Err(NvmeError::InvalidPrpAlignment);
        }

        let page_offset = prp as usize & (page_size - 1);
        if page_offset != 0 && page_offset < 4 {
            return Err(NvmeError::InvalidPrpAlignment);
        }

        Ok(())
    }

    #[inline]
    fn overlaps_kernel(start: u64, end: u64) -> bool {
        if start >= KERNEL_PHYS_START && start < KERNEL_PHYS_END {
            return true;
        }
        if end > KERNEL_PHYS_START && end <= KERNEL_PHYS_END {
            return true;
        }
        if start < KERNEL_PHYS_START && end > KERNEL_PHYS_END {
            return true;
        }
        false
    }
}

pub struct NamespaceValidator;

impl NamespaceValidator {
    pub fn validate_nsid(expected: u32, actual: u32) -> Result<(), NvmeError> {
        if actual == 0 {
            return Err(NvmeError::InvalidNamespaceId);
        }

        if expected != actual {
            return Err(NvmeError::InvalidNamespaceId);
        }

        Ok(())
    }

    pub fn validate_exists(ns: Option<&Namespace>) -> Result<&Namespace, NvmeError> {
        ns.ok_or(NvmeError::NamespaceNotReady)
    }
}

pub struct CommandValidator;

impl CommandValidator {
    pub fn validate_read(
        ns: &Namespace,
        start_lba: u64,
        block_count: u16,
        buffer_phys: PhysAddr,
    ) -> Result<(), NvmeError> {
        LbaValidator::validate(ns, start_lba, block_count)?;

        let transfer_size = (block_count as usize) * (ns.block_size() as usize);
        DmaValidator::validate_buffer(buffer_phys, transfer_size)?;

        Ok(())
    }

    pub fn validate_write(
        ns: &Namespace,
        start_lba: u64,
        block_count: u16,
        buffer_phys: PhysAddr,
    ) -> Result<(), NvmeError> {
        LbaValidator::validate(ns, start_lba, block_count)?;

        let transfer_size = (block_count as usize) * (ns.block_size() as usize);
        DmaValidator::validate_buffer(buffer_phys, transfer_size)?;

        Ok(())
    }
}

pub struct SecurityContext {
    rate_limiter: RateLimiter,
    validation_enabled: bool,
    strict_mode: bool,
}

impl SecurityContext {
    pub const fn new() -> Self {
        Self {
            rate_limiter: RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC),
            validation_enabled: true,
            strict_mode: true,
        }
    }

    pub fn check_rate_limit(&self) -> Result<(), NvmeError> {
        self.rate_limiter.check()
    }

    pub fn set_rate_limit(&self, limit: u32) {
        self.rate_limiter.set_limit(limit);
    }

    pub fn validate_read(
        &self,
        ns: &Namespace,
        start_lba: u64,
        block_count: u16,
        buffer_phys: PhysAddr,
    ) -> Result<(), NvmeError> {
        if !self.validation_enabled {
            return Ok(());
        }

        self.check_rate_limit()?;
        CommandValidator::validate_read(ns, start_lba, block_count, buffer_phys)
    }

    pub fn validate_write(
        &self,
        ns: &Namespace,
        start_lba: u64,
        block_count: u16,
        buffer_phys: PhysAddr,
    ) -> Result<(), NvmeError> {
        if !self.validation_enabled {
            return Ok(());
        }

        self.check_rate_limit()?;
        CommandValidator::validate_write(ns, start_lba, block_count, buffer_phys)
    }

    pub fn set_validation_enabled(&mut self, enabled: bool) {
        self.validation_enabled = enabled;
    }

    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    pub fn is_strict(&self) -> bool {
        self.strict_mode
    }

    pub fn reset(&self) {
        self.rate_limiter.reset();
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sanitize_identify_data(data: &mut [u8; 4096]) {
    for byte in &mut data[0xF00..0x1000] {
        *byte = 0;
    }
}

pub fn zero_sensitive_memory(ptr: *mut u8, len: usize) {
    // SAFETY: caller guarantees ptr is valid for len bytes
    unsafe {
        core::ptr::write_bytes(ptr, 0, len);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}
