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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;

use super::constants::{
    amd_msr, smramc, LEGACY_SMRAM_BASE, LEGACY_SMRAM_SIZE, SMRAMC_REGISTER,
    SMI_EN_OFFSET, SMI_STS_OFFSET, SMM_ENTRY_OFFSET,
};
use super::error::SmmError;
use super::hw::{
    get_acpi_pm_base, read_msr, read_pci_byte, read_pci_dword, read_smram, write_msr,
    write_pci_byte,
};
use super::stats::SmmStats;
use super::types::{CpuVendor, SmiInfo, SmiSource, SmmHandler, SmmRegion, SmmRegionType};

pub static SMM_MANAGER: SmmManager = SmmManager::new();

pub struct SmmManager {
    initialized: AtomicBool,
    protection_enabled: AtomicBool,
    cpu_vendor: RwLock<CpuVendor>,
    regions: RwLock<Vec<SmmRegion>>,
    handlers: RwLock<Vec<SmmHandler>>,
    stats: SmmStats,
}

impl SmmManager {
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            protection_enabled: AtomicBool::new(false),
            cpu_vendor: RwLock::new(CpuVendor::Unknown),
            regions: RwLock::new(Vec::new()),
            handlers: RwLock::new(Vec::new()),
            stats: SmmStats::new(),
        }
    }

    pub fn initialize(&self) -> Result<(), SmmError> {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return Err(SmmError::AlreadyInitialized);
        }

        let vendor = CpuVendor::detect();
        *self.cpu_vendor.write() = vendor;

        crate::log::info!("SMM security: Detected {} CPU", vendor.name());

        self.detect_regions(vendor)?;
        self.enumerate_handlers()?;
        self.enable_protection(vendor)?;

        crate::log::info!(
            "SMM security initialized: {} regions, {} handlers",
            self.regions.read().len(),
            self.handlers.read().len()
        );

        Ok(())
    }

    fn detect_regions(&self, vendor: CpuVendor) -> Result<(), SmmError> {
        let mut regions = self.regions.write();

        match vendor {
            CpuVendor::Intel => {
                self.detect_intel_regions(&mut regions)?;
            }
            CpuVendor::Amd => {
                self.detect_amd_regions(&mut regions)?;
            }
            CpuVendor::Unknown => {
                regions.push(SmmRegion {
                    base: LEGACY_SMRAM_BASE,
                    size: LEGACY_SMRAM_SIZE,
                    region_type: SmmRegionType::Aseg,
                    protected: false,
                    open: true,
                });
            }
        }

        self.stats.regions_protected.store(
            regions.iter().filter(|r| r.protected).count() as u64,
            Ordering::SeqCst,
        );

        Ok(())
    }

    fn detect_intel_regions(&self, regions: &mut Vec<SmmRegion>) -> Result<(), SmmError> {
        let smramc = read_pci_byte(0, 0, 0, SMRAMC_REGISTER);

        let smram_enabled = (smramc & smramc::G_SMRAME) != 0;
        let d_open = (smramc & smramc::D_OPEN) != 0;
        let d_locked = (smramc & smramc::D_LCK) != 0;

        crate::log::info!(
            "Intel SMRAMC: enabled={}, open={}, locked={}",
            smram_enabled,
            d_open,
            d_locked
        );

        if smram_enabled {
            regions.push(SmmRegion {
                base: LEGACY_SMRAM_BASE,
                size: LEGACY_SMRAM_SIZE,
                region_type: SmmRegionType::Aseg,
                protected: d_locked && !d_open,
                open: d_open,
            });
        }

        if let Some(tseg) = self.detect_intel_tseg() {
            regions.push(tseg);
        }

        Ok(())
    }

    fn detect_intel_tseg(&self) -> Option<SmmRegion> {
        let tseg_base = read_pci_dword(0, 0, 0, 0xB8) as u64;

        if tseg_base > 0 && tseg_base < 0xFFFF_FFFF {
            let tseg_size = 0x800000u64;

            Some(SmmRegion {
                base: tseg_base & 0xFFF0_0000,
                size: tseg_size,
                region_type: SmmRegionType::Tseg,
                protected: true,
                open: false,
            })
        } else {
            None
        }
    }

    fn detect_amd_regions(&self, regions: &mut Vec<SmmRegion>) -> Result<(), SmmError> {
        let smm_base = unsafe { read_msr(amd_msr::SMM_BASE) };
        let smm_addr = unsafe { read_msr(amd_msr::SMM_ADDR) };
        let smm_mask = unsafe { read_msr(amd_msr::SMM_MASK) };

        let smm_enabled = (smm_mask & 1) != 0;
        let smm_locked = (smm_mask & amd_msr::LOCK_BIT) != 0;

        crate::log::info!(
            "AMD SMM: enabled={}, locked={}, base=0x{:x}",
            smm_enabled,
            smm_locked,
            smm_base
        );

        if smm_enabled && smm_base > 0 {
            regions.push(SmmRegion {
                base: LEGACY_SMRAM_BASE,
                size: 0x10000,
                region_type: SmmRegionType::Aseg,
                protected: smm_locked,
                open: !smm_locked,
            });

            if smm_addr > 0 {
                let size = self.calculate_amd_smm_size(smm_mask);
                regions.push(SmmRegion {
                    base: smm_addr,
                    size,
                    region_type: SmmRegionType::Tseg,
                    protected: smm_locked,
                    open: !smm_locked,
                });
            }
        }

        Ok(())
    }

    fn calculate_amd_smm_size(&self, mask: u64) -> u64 {
        let addr_mask = mask & 0xFFFF_F000;
        if addr_mask == 0 {
            0x100000
        } else {
            (!addr_mask + 1) & 0xFFFF_FFFF
        }
    }

    fn enumerate_handlers(&self) -> Result<(), SmmError> {
        let regions = self.regions.read();
        let mut handlers = self.handlers.write();

        for region in regions.iter() {
            let handler_entry = region.base + SMM_ENTRY_OFFSET;
            let handler_code = read_smram(handler_entry, 4096);
            let hash = crate::crypto::hash::sha256(&handler_code);

            handlers.push(SmmHandler {
                entry_point: handler_entry,
                size: 4096,
                hash,
                verified: false,
                region_type: region.region_type,
            });
        }

        for handler in handlers.iter_mut() {
            handler.verified = self.verify_handler_code(handler);
            if handler.verified {
                self.stats.handlers_verified.fetch_add(1, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    fn verify_handler_code(&self, handler: &SmmHandler) -> bool {
        if handler.entry_point == 0 || handler.size == 0 {
            return false;
        }

        let current_code = read_smram(handler.entry_point, handler.size as usize);
        let current_hash = crate::crypto::hash::sha256(&current_code);

        let mut matches = true;
        for i in 0..32 {
            if current_hash[i] != handler.hash[i] {
                matches = false;
            }
        }

        matches
    }

    fn enable_protection(&self, vendor: CpuVendor) -> Result<(), SmmError> {
        match vendor {
            CpuVendor::Intel => self.enable_intel_protection()?,
            CpuVendor::Amd => self.enable_amd_protection()?,
            CpuVendor::Unknown => {
                crate::log::info!("Unknown CPU, skipping SMM protection");
            }
        }

        self.protection_enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn enable_intel_protection(&self) -> Result<(), SmmError> {
        let mut smramc = read_pci_byte(0, 0, 0, SMRAMC_REGISTER);

        if (smramc & smramc::D_LCK) == 0 {
            smramc |= smramc::D_LCK;
            write_pci_byte(0, 0, 0, SMRAMC_REGISTER, smramc);
            crate::log::info!("Intel SMRAM: D_LCK set");
        }

        if (smramc & smramc::D_OPEN) != 0 {
            smramc &= !smramc::D_OPEN;
            write_pci_byte(0, 0, 0, SMRAMC_REGISTER, smramc);
            crate::log::info!("Intel SMRAM: D_OPEN cleared");
        }

        let mut regions = self.regions.write();
        for region in regions.iter_mut() {
            region.protected = true;
            region.open = false;
        }

        Ok(())
    }

    fn enable_amd_protection(&self) -> Result<(), SmmError> {
        let mut smm_mask = unsafe { read_msr(amd_msr::SMM_MASK) };

        if (smm_mask & amd_msr::LOCK_BIT) == 0 {
            smm_mask |= amd_msr::LOCK_BIT;
            unsafe { write_msr(amd_msr::SMM_MASK, smm_mask) };
            crate::log::info!("AMD SMM: lock bit set");
        }

        let mut regions = self.regions.write();
        for region in regions.iter_mut() {
            region.protected = true;
            region.open = false;
        }

        Ok(())
    }

    pub fn verify_integrity(&self) -> Result<bool, SmmError> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(SmmError::NotInitialized);
        }

        self.stats.integrity_checks.fetch_add(1, Ordering::SeqCst);

        let handlers = self.handlers.read();
        let regions = self.regions.read();

        for handler in handlers.iter() {
            let current_code = read_smram(handler.entry_point, handler.size as usize);
            let current_hash = crate::crypto::hash::sha256(&current_code);

            let mut matches = true;
            for i in 0..32 {
                if current_hash[i] != handler.hash[i] {
                    matches = false;
                }
            }

            if !matches {
                self.stats.integrity_failures.fetch_add(1, Ordering::SeqCst);
                crate::log::info!(
                    "SMM integrity FAILED: handler at 0x{:x}",
                    handler.entry_point
                );
                return Ok(false);
            }

            let in_valid_region = regions
                .iter()
                .any(|r| r.contains_range(handler.entry_point, handler.size as u64));

            if !in_valid_region {
                let in_legacy = handler.entry_point >= LEGACY_SMRAM_BASE
                    && handler.entry_point + handler.size as u64
                        <= LEGACY_SMRAM_BASE + LEGACY_SMRAM_SIZE;

                if !in_legacy {
                    self.stats.integrity_failures.fetch_add(1, Ordering::SeqCst);
                    crate::log::info!(
                        "SMM integrity FAILED: handler at 0x{:x} outside valid region",
                        handler.entry_point
                    );
                    return Ok(false);
                }
            }
        }

        for region in regions.iter() {
            if !region.protected {
                crate::log::info!(
                    "SMM integrity FAILED: region at 0x{:x} not protected",
                    region.base
                );
                return Ok(false);
            }
        }

        crate::log::info!("SMM integrity verified: {} handlers", handlers.len());
        Ok(true)
    }

    pub fn monitor_smi(&self) -> Result<SmiInfo, SmmError> {
        let pm_base = get_acpi_pm_base().ok_or(SmmError::AcpiPmBaseNotFound)?;

        let smi_en = unsafe {
            x86_64::instructions::port::Port::<u32>::new(pm_base + SMI_EN_OFFSET).read()
        };

        let smi_sts = unsafe {
            x86_64::instructions::port::Port::<u32>::new(pm_base + SMI_STS_OFFSET).read()
        };

        let last_source = SmiSource::from_smi_sts(smi_sts);

        self.stats.smi_count.fetch_add(1, Ordering::Relaxed);
        match last_source {
            SmiSource::Software => {
                self.stats.sw_smi_count.fetch_add(1, Ordering::Relaxed);
            }
            SmiSource::Timer => {
                self.stats.timer_smi_count.fetch_add(1, Ordering::Relaxed);
            }
            SmiSource::IoTrap => {
                self.stats.io_trap_smi_count.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        let handlers = self.handlers.read();
        let active_handlers: Vec<u64> = handlers
            .iter()
            .filter(|h| h.verified)
            .map(|h| h.entry_point)
            .collect();

        Ok(SmiInfo {
            smi_count: self.stats.smi_count.load(Ordering::Relaxed),
            last_source,
            smi_en,
            smi_sts,
            active_handlers,
        })
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn is_protection_enabled(&self) -> bool {
        self.protection_enabled.load(Ordering::SeqCst)
    }

    pub fn cpu_vendor(&self) -> CpuVendor {
        *self.cpu_vendor.read()
    }

    pub fn regions(&self) -> Vec<SmmRegion> {
        self.regions.read().clone()
    }

    pub fn handlers(&self) -> Vec<SmmHandler> {
        self.handlers.read().clone()
    }

    pub fn stats(&self) -> &SmmStats {
        &self.stats
    }
}
