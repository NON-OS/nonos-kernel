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

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use super::types::SanitizationLevel;

pub static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static SANITIZATION_LEVEL: AtomicU64 = AtomicU64::new(SanitizationLevel::Standard as u64);
pub static STACK_CANARY: AtomicU64 = AtomicU64::new(0xDEAD_BEEF_CAFE_BABE);
pub static BYTES_SANITIZED: AtomicUsize = AtomicUsize::new(0);
pub static SANITIZATION_CALLS: AtomicUsize = AtomicUsize::new(0);
