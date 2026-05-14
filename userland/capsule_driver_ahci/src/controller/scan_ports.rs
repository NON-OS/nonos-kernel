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

use crate::constants::regs::{
    PORT_BASE, PORT_CI, PORT_CMD, PORT_IS, PORT_SACT, PORT_SERR, PORT_SIG, PORT_SSTS, PORT_STRIDE,
    PORT_TFD,
};
use crate::constants::{MAX_PORTS, PORT_KIND_NONE};
use crate::controller::signature;
use crate::controller::PortInfo;
use crate::regs::Regs;

pub fn scan_ports(regs: Regs, pi: u32, max_ports: u8) -> [PortInfo; MAX_PORTS] {
    let mut out = empty_ports();
    let count = core::cmp::min(max_ports as usize, MAX_PORTS);
    for (i, slot) in out.iter_mut().enumerate().take(count) {
        if (pi & (1u32 << i)) == 0 {
            continue;
        }
        let base = PORT_BASE + (i as u32 * PORT_STRIDE);
        let ssts = unsafe { regs.r32(base + PORT_SSTS) };
        let sig = unsafe { regs.r32(base + PORT_SIG) };
        let present = device_present(ssts);
        *slot = PortInfo {
            index: i as u8,
            implemented: 1,
            present,
            kind: if present == 0 { PORT_KIND_NONE } else { signature::classify(sig) },
            ssts,
            sig,
            interrupt_status: unsafe { regs.r32(base + PORT_IS) },
            command_status: unsafe { regs.r32(base + PORT_CMD) },
            task_file_data: unsafe { regs.r32(base + PORT_TFD) },
            sata_error: unsafe { regs.r32(base + PORT_SERR) },
            active_commands: unsafe { regs.r32(base + PORT_SACT) },
            issued_commands: unsafe { regs.r32(base + PORT_CI) },
        };
    }
    out
}

fn empty_ports() -> [PortInfo; MAX_PORTS] {
    let mut ports = [PortInfo::empty(0); MAX_PORTS];
    let mut i = 0usize;
    while i < MAX_PORTS {
        ports[i] = PortInfo::empty(i as u8);
        i += 1;
    }
    ports
}

fn device_present(ssts: u32) -> u8 {
    let det = ssts & 0x0f;
    let ipm = (ssts >> 8) & 0x0f;
    if det == 3 && (ipm == 1 || ipm == 6) {
        1
    } else {
        0
    }
}
