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

use super::super::constants::DEFAULT_RATE_LIMIT_PER_SEC;
use super::super::error::NvmeError;
use super::super::namespace::Namespace;
use super::dma_validator::DmaValidator;
use super::lba_validator::LbaValidator;
use super::rate_limiter::RateLimiter;
use crate::memory::addr::PhysAddr;

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
        DmaValidator::validate_buffer(buffer_phys, transfer_size)
    }
    pub fn validate_write(
        ns: &Namespace,
        start_lba: u64,
        block_count: u16,
        buffer_phys: PhysAddr,
    ) -> Result<(), NvmeError> {
        LbaValidator::validate(ns, start_lba, block_count)?;
        let transfer_size = (block_count as usize) * (ns.block_size() as usize);
        DmaValidator::validate_buffer(buffer_phys, transfer_size)
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
