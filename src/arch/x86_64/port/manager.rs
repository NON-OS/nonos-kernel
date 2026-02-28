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

use core::sync::atomic::{AtomicBool, Ordering};

use spin::RwLock;

use super::constants::{CMOS_ADDRESS, PIC1_COMMAND, PIC2_COMMAND, PIT_CHANNEL0, PS2_COMMAND, PS2_DATA};
use super::error::PortError;
use super::stats::{PortStats, PORT_STATS};
use super::types::PortRange;

const MAX_RESERVED_RANGES: usize = 32;

pub struct PortManager {
    initialized: AtomicBool,
    reserved_ranges: RwLock<[Option<PortRange>; MAX_RESERVED_RANGES]>,
}

impl PortManager {
    pub const fn new() -> Self {
        const NONE: Option<PortRange> = None;
        Self {
            initialized: AtomicBool::new(false),
            reserved_ranges: RwLock::new([NONE; MAX_RESERVED_RANGES]),
        }
    }

    pub fn initialize(&self) -> Result<(), PortError> {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        self.reserve_range(PortRange::new(PIC1_COMMAND, 2))?;
        self.reserve_range(PortRange::new(PIC2_COMMAND, 2))?;
        self.reserve_range(PortRange::new(PIT_CHANNEL0, 4))?;
        self.reserve_range(PortRange::new(PS2_DATA, 1))?;
        self.reserve_range(PortRange::new(PS2_COMMAND, 1))?;
        self.reserve_range(PortRange::new(CMOS_ADDRESS, 2))?;

        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn reserve_range(&self, range: PortRange) -> Result<(), PortError> {
        let mut ranges = self.reserved_ranges.write();

        for existing in ranges.iter().flatten() {
            if existing.overlaps(&range) {
                return Err(PortError::PortReserved { port: range.start() });
            }
        }

        for slot in ranges.iter_mut() {
            if slot.is_none() {
                *slot = Some(range);
                return Ok(());
            }
        }

        Err(PortError::InvalidRange {
            start: range.start(),
            end: range.end(),
        })
    }

    pub fn release_range(&self, range: PortRange) {
        let mut ranges = self.reserved_ranges.write();
        for slot in ranges.iter_mut() {
            if let Some(existing) = slot {
                if existing.start() == range.start() && existing.count() == range.count() {
                    *slot = None;
                    return;
                }
            }
        }
    }

    pub fn is_reserved(&self, port: u16) -> bool {
        let ranges = self.reserved_ranges.read();
        for range in ranges.iter().flatten() {
            if range.contains(port) {
                return true;
            }
        }
        false
    }

    pub fn stats(&self) -> &'static PortStats {
        &PORT_STATS
    }

    pub fn total_ops(&self) -> u64 {
        PORT_STATS.total_ops()
    }
}

impl Default for PortManager {
    fn default() -> Self {
        Self::new()
    }
}

pub static PORT_MANAGER: PortManager = PortManager::new();

pub fn init() -> Result<(), PortError> {
    PORT_MANAGER.initialize()
}

pub fn is_initialized() -> bool {
    PORT_MANAGER.is_initialized()
}

pub fn reserve_range(start: u16, count: u16) -> Result<(), PortError> {
    PORT_MANAGER.reserve_range(PortRange::new(start, count))
}

pub fn release_range(start: u16, count: u16) {
    PORT_MANAGER.release_range(PortRange::new(start, count));
}

pub fn is_reserved(port: u16) -> bool {
    PORT_MANAGER.is_reserved(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_manager_new() {
        let manager = PortManager::new();
        assert!(!manager.is_initialized());
    }
}
