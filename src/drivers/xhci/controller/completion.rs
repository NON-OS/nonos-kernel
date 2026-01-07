// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use x86_64::VirtAddr;
use crate::memory::mmio::{mmio_r32, mmio_w32, mmio_w64};
use super::super::constants::*;
use super::super::error::XhciError;
use super::super::trb::Trb;
use super::XhciController;

pub fn spin_wait<F: Fn() -> bool>(cond: F, mut spins: u32) -> bool {
    while spins > 0 {
        if cond() {
            return true;
        }
        spins -= 1;
        core::hint::spin_loop();
    }
    false
}

impl XhciController {
    pub fn wait_command_completion(&mut self, cmd_trb_ptr: u64) -> Result<(), &'static str> {
        Trb::validate_pointer_alignment(cmd_trb_ptr).map_err(|e| e.as_str())?;

        let mut spins = self.config.command_timeout_spins;
        loop {
            self.process_pending_interrupts();

            if self.evt_ring.has_event() {
                let trb = self.evt_ring.current_trb();

                match trb.validate_completion(cmd_trb_ptr) {
                    Ok(ccode) => {
                        self.advance_event_ring();

                        if ccode != CC_SUCCESS {
                            self.stats.command_errors.fetch_add(1, Ordering::Relaxed);
                            self.log_security_event(&alloc::format!(
                                "Command completion error: code {}", ccode
                            ));
                            return Err("xHCI: command completion with error");
                        }
                        self.stats.inc_commands();
                        return Ok(());
                    }
                    Err(XhciError::InvalidCompletion) => {
                        self.advance_event_ring();
                    }
                    Err(e) => {
                        self.stats.trb_validation_errors.fetch_add(1, Ordering::Relaxed);
                        return Err(e.as_str());
                    }
                }
            }

            if spins == 0 {
                self.stats.inc_timeouts();
                self.log_security_event("Command completion timeout");
                return Err("xHCI: command completion timeout");
            }
            spins -= 1;
            core::hint::spin_loop();
        }
    }

    pub fn wait_transfer_completion(&mut self, trb_ptr_match: u64) -> Result<(), &'static str> {
        Trb::validate_pointer_alignment(trb_ptr_match).map_err(|e| e.as_str())?;

        let mut spins = self.config.transfer_timeout_spins;
        loop {
            self.process_pending_interrupts();

            if self.evt_ring.has_event() {
                let trb = self.evt_ring.current_trb();

                match trb.validate_completion(trb_ptr_match) {
                    Ok(ccode) => {
                        let transfer_len = trb.transfer_length_remaining() as u64;

                        self.advance_event_ring();

                        if ccode != CC_SUCCESS && ccode != CC_SHORT_PACKET {
                            self.stats.transfer_errors.fetch_add(1, Ordering::Relaxed);
                            self.log_security_event(&alloc::format!(
                                "Transfer completion error: code {}", ccode
                            ));
                            return Err("xHCI: transfer completion error");
                        }

                        self.stats.add_bytes(transfer_len);
                        self.stats.inc_transfers();
                        return Ok(());
                    }
                    Err(XhciError::InvalidCompletion) => {
                        self.advance_event_ring();
                    }
                    Err(e) => {
                        self.stats.trb_validation_errors.fetch_add(1, Ordering::Relaxed);
                        return Err(e.as_str());
                    }
                }
            }

            if spins == 0 {
                self.stats.inc_timeouts();
                self.log_security_event("Transfer completion timeout");
                return Err("xHCI: transfer completion timeout");
            }
            spins -= 1;
            core::hint::spin_loop();
        }
    }

    fn process_pending_interrupts(&mut self) {
        // SAFETY: reading from valid runtime register
        let iman = unsafe { mmio_r32(VirtAddr::new((self.rt_base + RT_IR0_IMAN) as u64)) };
        if (iman & IMAN_IP) != 0 {
            self.stats.inc_interrupts();
            // SAFETY: writing to valid runtime register
            unsafe {
                mmio_w32(VirtAddr::new((self.rt_base + RT_IR0_IMAN) as u64), iman | IMAN_IP);
            }
        }
    }

    fn advance_event_ring(&mut self) {
        self.evt_ring.advance();
        // SAFETY: writing to valid runtime register
        unsafe {
            mmio_w64(
                VirtAddr::new((self.rt_base + RT_IR0_ERDP) as u64),
                self.evt_ring.current_dequeue_phys() | ERDP_EHB,
            );
        }
    }
}
