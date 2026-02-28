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
use core::sync::atomic::AtomicBool;
use spin::RwLock;

use crate::arch::x86_64::smm::stats::SmmStats;
use crate::arch::x86_64::smm::types::{CpuVendor, SmmHandler, SmmRegion};

pub static SMM_MANAGER: SmmManager = SmmManager::new();

pub struct SmmManager {
    pub(crate) initialized: AtomicBool,
    pub(crate) protection_enabled: AtomicBool,
    pub(crate) cpu_vendor: RwLock<CpuVendor>,
    pub(crate) regions: RwLock<Vec<SmmRegion>>,
    pub(crate) handlers: RwLock<Vec<SmmHandler>>,
    pub(crate) stats: SmmStats,
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
}
