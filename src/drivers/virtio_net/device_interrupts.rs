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

use core::ptr;

use crate::drivers::pci::PciBar;
use crate::interrupts::register_interrupt_handler;

use super::constants::*;
use super::device::VirtioNetDevice;

impl VirtioNetDevice {
    pub fn setup_interrupts(&mut self) -> Result<(), &'static str> {
        let vector = crate::interrupts::allocate_vector()
            .ok_or("Failed to allocate interrupt vector")?;

        fn isr_wrapper(_frame: crate::arch::x86_64::InterruptStackFrame) {
            super::super_virtio_isr();
        }

        register_interrupt_handler(vector, isr_wrapper)?;
        self.pci_device
            .configure_msix(vector)
            .map_err(|_| "MSI-X configuration failed")?;
        self.interrupt_vector = vector;

        Ok(())
    }

    pub fn ack_interrupt(&self) {
        if let Some(ref regs) = self.modern {
            let _ = regs.read_isr();
        } else if let Some(PciBar::Memory { address, .. }) = &self.legacy_bar {
            // SAFETY: address points to valid MMIO memory from BAR
            unsafe {
                let _ = ptr::read_volatile((address.as_u64() as usize + LEG_ISR) as *const u8);
            }
        }
    }
}
