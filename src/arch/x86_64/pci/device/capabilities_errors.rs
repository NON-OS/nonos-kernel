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

use super::device_struct::PciDevice;
use crate::arch::x86_64::pci::config::pci_config_write_word;
use crate::arch::x86_64::pci::constants::{config, status};
use crate::arch::x86_64::pci::stats::ERROR_COUNTER;
use core::sync::atomic::Ordering;

impl PciDevice {
    pub fn check_and_clear_errors(&self) -> Option<u16> {
        let stat = self.read_status();
        let error_bits = stat
            & (status::MASTER_DATA_PARITY_ERROR
                | status::SIGNALED_TARGET_ABORT
                | status::RECEIVED_TARGET_ABORT
                | status::RECEIVED_MASTER_ABORT
                | status::SIGNALED_SYSTEM_ERROR
                | status::DETECTED_PARITY_ERROR);
        if error_bits != 0 {
            pci_config_write_word(self.bus, self.slot, self.function, config::STATUS, error_bits);
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            Some(error_bits)
        } else {
            None
        }
    }
}
