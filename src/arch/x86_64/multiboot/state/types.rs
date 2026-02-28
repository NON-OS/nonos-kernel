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

use super::super::info::ParsedMultibootInfo;
use super::super::platform::Platform;
use super::super::stats::MultibootStats;

pub struct MultibootManager {
    pub(super) initialized: AtomicBool,
    pub(super) bootloader_magic: AtomicU64,
    pub(super) parsed_info: RwLock<Option<ParsedMultibootInfo>>,
    pub(super) platform: RwLock<Platform>,
    pub(super) stats: MultibootStats,
}
