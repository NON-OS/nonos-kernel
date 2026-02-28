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

use super::error::SmmError;
use super::manager::SMM_MANAGER;
use super::stats::SmmStats;
use super::types::{SmiInfo, SmmHandler, SmmRegion};

#[inline]
pub fn init() -> Result<(), SmmError> {
    SMM_MANAGER.initialize()
}

#[inline]
pub fn verify_integrity() -> Result<bool, SmmError> {
    SMM_MANAGER.verify_integrity()
}

#[inline]
pub fn monitor_smi() -> Result<SmiInfo, SmmError> {
    SMM_MANAGER.monitor_smi()
}

#[inline]
pub fn regions() -> alloc::vec::Vec<SmmRegion> {
    SMM_MANAGER.regions()
}

#[inline]
pub fn handlers() -> alloc::vec::Vec<SmmHandler> {
    SMM_MANAGER.handlers()
}

#[inline]
pub fn is_protection_enabled() -> bool {
    SMM_MANAGER.is_protection_enabled()
}

#[inline]
pub fn stats() -> &'static SmmStats {
    SMM_MANAGER.stats()
}
