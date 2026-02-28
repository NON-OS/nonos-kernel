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

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::RwLock;

use crate::arch::x86_64::uefi::stats::InternalStats;
use crate::arch::x86_64::uefi::tables::RuntimeServices;
use crate::arch::x86_64::uefi::types::Guid;
use crate::arch::x86_64::uefi::variable::{FirmwareInfo, UefiVariable};

pub struct UefiManager {
    pub(crate) runtime_services: RwLock<Option<*const RuntimeServices>>,
    pub(crate) firmware_info: RwLock<FirmwareInfo>,
    pub(crate) variables_cache: RwLock<BTreeMap<(String, Guid), UefiVariable>>,
    pub(crate) stats: InternalStats,
}

// SAFETY: RuntimeServices pointer is only accessed through synchronized methods
unsafe impl Send for UefiManager {}
unsafe impl Sync for UefiManager {}

impl UefiManager {
    pub const fn new() -> Self {
        Self {
            runtime_services: RwLock::new(None),
            firmware_info: RwLock::new(FirmwareInfo {
                vendor: String::new(),
                version: String::new(),
                revision: 0,
                firmware_revision: 0,
                secure_boot_enabled: false,
                setup_mode: true,
                variable_support: false,
                runtime_services_supported: false,
            }),
            variables_cache: RwLock::new(BTreeMap::new()),
            stats: InternalStats::new(),
        }
    }
}

impl Default for UefiManager {
    fn default() -> Self {
        Self::new()
    }
}
