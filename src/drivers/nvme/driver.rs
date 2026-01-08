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

use spin::Once;
use x86_64::PhysAddr;
use super::constants;
use super::controller::{NvmeController, SmartLog};
use super::error::NvmeError;
use super::stats::{NvmeStatsSnapshot, SecurityStatsSnapshot};

static NVME_CONTROLLER: Once<NvmeController> = Once::new();
pub fn init_nvme() -> Result<(), NvmeError> {
    if NVME_CONTROLLER.is_completed() {
        return Ok(());
    }

    let devices = crate::drivers::pci::scan_and_collect();
    let pci_device = devices
        .into_iter()
        .find(|d| {
            d.class == constants::NVME_CLASS
                && d.subclass == constants::NVME_SUBCLASS
                && d.progif == constants::NVME_PROGIF
        })
        .ok_or(NvmeError::NoControllerFound)?;

    let mut controller = NvmeController::new(pci_device)?;
    controller.init()?;
    NVME_CONTROLLER.call_once(|| controller);
    crate::log::logger::log_critical("NVMe subsystem initialized");
    Ok(())
}

#[inline]
pub fn get_controller() -> Option<&'static NvmeController> {
    NVME_CONTROLLER.get()
}

pub fn is_initialized() -> bool {
    NVME_CONTROLLER.is_completed()
}

pub struct NvmeDriver;
impl NvmeDriver {
    pub fn read_blocks(lba: u64, count: u16, dst_phys: PhysAddr) -> Result<(), NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        ctrl.read(lba, count, dst_phys)
    }

    pub fn write_blocks(lba: u64, count: u16, src_phys: PhysAddr) -> Result<(), NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        ctrl.write(lba, count, src_phys)
    }

    pub fn flush() -> Result<(), NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        ctrl.flush()
    }

    pub fn trim(ranges: &[(u64, u32)]) -> Result<(), NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        ctrl.trim(ranges)
    }

    pub fn set_timeout(timeout_spins: u32) -> Result<(), NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        ctrl.set_timeout(timeout_spins);
        Ok(())
    }

    pub fn set_rate_limit(limit_per_sec: u32) -> Result<(), NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        ctrl.set_rate_limit(limit_per_sec);
        Ok(())
    }

    pub fn get_stats() -> Result<NvmeStatsSnapshot, NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        Ok(ctrl.get_stats())
    }

    pub fn get_security_stats() -> Result<SecurityStatsSnapshot, NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        Ok(ctrl.get_stats().security)
    }

    pub fn reset_stats() -> Result<(), NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        ctrl.reset_stats();
        Ok(())
    }

    pub fn get_smart_log(nsid: u32) -> Result<SmartLog, NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        ctrl.get_smart_log(nsid)
    }

    pub fn get_namespace_info() -> Result<NamespaceInfo, NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        let ns = ctrl
            .get_first_namespace()
            .ok_or(NvmeError::NamespaceNotReady)?;
        Ok(NamespaceInfo {
            nsid: ns.nsid(),
            block_count: ns.block_count(),
            block_size: ns.block_size(),
            capacity_bytes: ns.capacity_bytes(),
        })
    }

    pub fn shutdown() -> Result<(), NvmeError> {
        let ctrl = get_controller().ok_or(NvmeError::ControllerNotInitialized)?;
        ctrl.shutdown()
    }
}

#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    pub nsid: u32,
    pub block_count: u64,
    pub block_size: u32,
    pub capacity_bytes: u64,
}

#[derive(Default, Clone)]
pub struct NvmeSecurityStats {
    pub timeouts: u64,
    pub rate_limit_hits: u64,
    pub lba_validation_failures: u64,
    pub dma_validation_failures: u64,
    pub cid_mismatches: u64,
    pub phase_errors: u64,
    pub command_errors: u64,
    pub namespace_errors: u64,
}

impl From<SecurityStatsSnapshot> for NvmeSecurityStats {
    fn from(s: SecurityStatsSnapshot) -> Self {
        Self {
            timeouts: 0,
            rate_limit_hits: s.rate_limit_hits,
            lba_validation_failures: s.lba_validation_failures,
            dma_validation_failures: s.dma_validation_failures,
            cid_mismatches: s.cid_mismatches,
            phase_errors: s.phase_errors,
            command_errors: s.command_errors,
            namespace_errors: s.namespace_errors,
        }
    }
}
