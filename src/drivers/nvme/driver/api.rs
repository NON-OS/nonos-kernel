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

use super::super::controller::SmartLog;
use super::super::error::NvmeError;
use super::super::interrupt::get_allocated_vector;
use super::super::stats::{NvmeStatsSnapshot, SecurityStatsSnapshot};
use super::init::get_controller;
use super::types::NamespaceInfo;
use x86_64::PhysAddr;

pub struct NvmeDriver;

impl NvmeDriver {
    pub fn read_blocks(lba: u64, count: u16, dst: PhysAddr) -> Result<(), NvmeError> {
        let result =
            get_controller().ok_or(NvmeError::ControllerNotInitialized)?.read(lba, count, dst);
        if result.is_ok() {
            let bytes_read = count as usize * 512;
            crate::drivers::block::record_read("nvme0", bytes_read);
        }
        result
    }
    pub fn write_blocks(lba: u64, count: u16, src: PhysAddr) -> Result<(), NvmeError> {
        let result =
            get_controller().ok_or(NvmeError::ControllerNotInitialized)?.write(lba, count, src);
        if result.is_ok() {
            let bytes_written = count as usize * 512;
            crate::drivers::block::record_write("nvme0", bytes_written);
        }
        result
    }
    pub fn flush() -> Result<(), NvmeError> {
        get_controller().ok_or(NvmeError::ControllerNotInitialized)?.flush()
    }
    pub fn trim(ranges: &[(u64, u32)]) -> Result<(), NvmeError> {
        get_controller().ok_or(NvmeError::ControllerNotInitialized)?.trim(ranges)
    }
    pub fn set_timeout(timeout_spins: u32) -> Result<(), NvmeError> {
        get_controller().ok_or(NvmeError::ControllerNotInitialized)?.set_timeout(timeout_spins);
        Ok(())
    }
    pub fn set_rate_limit(limit_per_sec: u32) -> Result<(), NvmeError> {
        get_controller().ok_or(NvmeError::ControllerNotInitialized)?.set_rate_limit(limit_per_sec);
        Ok(())
    }
    pub fn get_stats() -> Result<NvmeStatsSnapshot, NvmeError> {
        Ok(get_controller().ok_or(NvmeError::ControllerNotInitialized)?.get_stats())
    }
    pub fn get_security_stats() -> Result<SecurityStatsSnapshot, NvmeError> {
        Ok(get_controller().ok_or(NvmeError::ControllerNotInitialized)?.get_stats().security)
    }
    pub fn reset_stats() -> Result<(), NvmeError> {
        get_controller().ok_or(NvmeError::ControllerNotInitialized)?.reset_stats();
        Ok(())
    }
    pub fn get_smart_log(nsid: u32) -> Result<SmartLog, NvmeError> {
        get_controller().ok_or(NvmeError::ControllerNotInitialized)?.get_smart_log(nsid)
    }
    pub fn get_namespace_info() -> Result<NamespaceInfo, NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        let ns = ctrl.get_first_namespace().ok_or(NvmeError::NamespaceNotReady)?;
        Ok(NamespaceInfo {
            nsid: ns.nsid(),
            block_count: ns.block_count(),
            block_size: ns.block_size(),
            capacity_bytes: ns.capacity_bytes(),
        })
    }
    pub fn shutdown() -> Result<(), NvmeError> {
        get_controller().ok_or(NvmeError::ControllerNotInitialized)?.shutdown()
    }
    pub fn get_interrupt_vector() -> Option<u8> {
        get_allocated_vector()
    }
}
