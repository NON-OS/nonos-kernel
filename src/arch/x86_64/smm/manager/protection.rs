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

use super::state::SmmManager;
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::types::CpuVendor;

impl SmmManager {
    pub(crate) fn enable_protection(&self, vendor: CpuVendor) -> Result<(), SmmError> {
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
}
