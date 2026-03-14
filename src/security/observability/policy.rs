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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static PRODUCTION_MODE: AtomicBool = AtomicBool::new(true);
static OUTPUT_MODE: AtomicU8 = AtomicU8::new(OutputMode::Minimal as u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputMode {
    Minimal = 0,
    Standard = 1,
    Verbose = 2,
    Debug = 3,
}

impl From<u8> for OutputMode {
    fn from(v: u8) -> Self {
        match v {
            0 => OutputMode::Minimal,
            1 => OutputMode::Standard,
            2 => OutputMode::Verbose,
            3 => OutputMode::Debug,
            _ => OutputMode::Minimal,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ObservabilityPolicy {
    pub production: bool,
    pub output_mode: OutputMode,
    pub serial_enabled: bool,
    pub vga_enabled: bool,
}

impl Default for ObservabilityPolicy {
    fn default() -> Self {
        Self {
            production: true,
            output_mode: OutputMode::Minimal,
            serial_enabled: false,
            vga_enabled: true,
        }
    }
}

pub fn is_production_mode() -> bool {
    PRODUCTION_MODE.load(Ordering::Acquire)
}

pub fn set_production_mode(enabled: bool) {
    PRODUCTION_MODE.store(enabled, Ordering::Release);
    if enabled {
        OUTPUT_MODE.store(OutputMode::Minimal as u8, Ordering::Release);
    }
}

pub fn should_log_debug() -> bool {
    !is_production_mode() && OUTPUT_MODE.load(Ordering::Acquire) >= OutputMode::Debug as u8
}

pub fn should_emit_serial() -> bool {
    !is_production_mode() || OUTPUT_MODE.load(Ordering::Acquire) >= OutputMode::Standard as u8
}
