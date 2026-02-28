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

use core::sync::atomic::Ordering;

use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::types::CpuVendor;
use super::state::SmmManager;

impl SmmManager {
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
}
