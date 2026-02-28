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

use core::sync::atomic::{AtomicBool, AtomicU64};
use spin::RwLock;

use super::types::MultibootManager;
use super::super::platform::Platform;
use super::super::stats::MultibootStats;

impl MultibootManager {
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            bootloader_magic: AtomicU64::new(0),
            parsed_info: RwLock::new(None),
            platform: RwLock::new(Platform::BareMetal),
            stats: MultibootStats::new(),
        }
    }
}
