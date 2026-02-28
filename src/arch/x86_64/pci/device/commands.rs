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

use crate::arch::x86_64::pci::constants::command;
use crate::arch::x86_64::pci::error::{PciError, PciResult};
use crate::arch::x86_64::pci::stats::ERROR_COUNTER;
use super::device::PciDevice;

impl PciDevice {
    pub fn enable_bus_mastering(&self) -> PciResult<()> {
        let mut cmd = self.read_command();
        cmd |= command::BUS_MASTER;
        self.write_command(cmd);

        if (self.read_command() & command::BUS_MASTER) == 0 {
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            return Err(PciError::BusMasteringDisabled);
        }
        Ok(())
    }

    pub fn enable_memory_space(&self) -> PciResult<()> {
        let mut cmd = self.read_command();
        cmd |= command::MEMORY_SPACE;
        self.write_command(cmd);

        if (self.read_command() & command::MEMORY_SPACE) == 0 {
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            return Err(PciError::MemorySpaceDisabled);
        }
        Ok(())
    }

    pub fn enable_io_space(&self) -> PciResult<()> {
        let mut cmd = self.read_command();
        cmd |= command::IO_SPACE;
        self.write_command(cmd);

        if (self.read_command() & command::IO_SPACE) == 0 {
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            return Err(PciError::IoSpaceDisabled);
        }
        Ok(())
    }

    pub fn disable_interrupts(&self) {
        let mut cmd = self.read_command();
        cmd |= command::INTERRUPT_DISABLE;
        self.write_command(cmd);
    }

    pub fn enable_interrupts(&self) {
        let mut cmd = self.read_command();
        cmd &= !command::INTERRUPT_DISABLE;
        self.write_command(cmd);
    }
}
