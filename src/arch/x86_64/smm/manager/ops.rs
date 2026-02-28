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

use crate::arch::x86_64::smm::stats::SmmStats;
use crate::arch::x86_64::smm::types::{CpuVendor, SmmHandler, SmmRegion};
use super::state::SmmManager;

impl SmmManager {
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
