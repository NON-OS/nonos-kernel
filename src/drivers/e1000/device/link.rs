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

use super::core::E1000Device;
use crate::drivers::e1000::constants::{ctrl, int, reg, status};

impl E1000Device {
    pub(super) fn enable_interrupts(&self) {
        self.write_reg(reg::IMS, int::TXDW | int::LSC | int::RXT0 | int::RXDMT0);
    }

    pub fn update_link_status(&mut self) {
        let status_val = self.read_reg(reg::STATUS);
        self.link_up = (status_val & status::LU) != 0;
        self.full_duplex = (status_val & status::FD) != 0;
        self.link_speed = match status_val & status::SPEED_MASK {
            status::SPEED_10 => 10,
            status::SPEED_100 => 100,
            status::SPEED_1000 => 1000,
            _ => 0,
        };

        let ctrl_val = self.read_reg(reg::CTRL);
        self.write_reg(reg::CTRL, ctrl_val | ctrl::SLU | ctrl::ASDE);
    }

    pub fn handle_interrupt(&mut self) {
        let icr = self.read_reg(reg::ICR);

        if icr & int::LSC != 0 {
            self.update_link_status();
            if self.link_up {
                crate::log::info!("e1000: Link UP {}Mbps", self.link_speed);
            } else {
                crate::log::info!("e1000: Link DOWN");
            }
        }

        if icr & int::RXT0 != 0 {
            let _packets = self.receive();
        }

        if icr & int::RXDMT0 != 0 {
            let _packets = self.receive();
        }

        if icr & int::TXDW != 0 {
            self.reclaim_tx();
        }
    }
}
