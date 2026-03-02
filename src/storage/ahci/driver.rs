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

use super::types::{AhciPortRegs, PORT_CMD_ST, PORT_CMD_CR, PORT_CMD_FRE, PORT_CMD_FR};

pub unsafe fn stop_port_cmd(port: &mut AhciPortRegs) {
    // SAFETY: Port registers are properly mapped
    unsafe {
        let cmd = core::ptr::read_volatile(&port.cmd);

        core::ptr::write_volatile(&mut port.cmd, cmd & !PORT_CMD_ST);

        for _ in 0..1000 {
            let cmd = core::ptr::read_volatile(&port.cmd);
            if (cmd & PORT_CMD_CR) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        let cmd = core::ptr::read_volatile(&port.cmd);
        core::ptr::write_volatile(&mut port.cmd, cmd & !PORT_CMD_FRE);

        for _ in 0..1000 {
            let cmd = core::ptr::read_volatile(&port.cmd);
            if (cmd & PORT_CMD_FR) == 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

pub unsafe fn start_port_cmd(port: &mut AhciPortRegs) {
    // SAFETY: Port registers are properly mapped
    unsafe {
        for _ in 0..1000 {
            let cmd = core::ptr::read_volatile(&port.cmd);
            if (cmd & PORT_CMD_CR) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        let cmd = core::ptr::read_volatile(&port.cmd);
        core::ptr::write_volatile(&mut port.cmd, cmd | PORT_CMD_FRE | PORT_CMD_ST);
    }
}
