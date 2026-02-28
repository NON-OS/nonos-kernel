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
use core::sync::atomic::Ordering;

use crate::arch::x86_64::smm::constants::{SMI_EN_OFFSET, SMI_STS_OFFSET};
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::get_acpi_pm_base;
use crate::arch::x86_64::smm::types::{SmiInfo, SmiSource};
use super::state::SmmManager;

impl SmmManager {
    pub fn monitor_smi(&self) -> Result<SmiInfo, SmmError> {
        let pm_base = get_acpi_pm_base().ok_or(SmmError::AcpiPmBaseNotFound)?;

        // SAFETY: Reading SMI enable/status ports at ACPI PM base
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
}
