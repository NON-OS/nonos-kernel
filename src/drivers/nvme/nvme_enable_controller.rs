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

use crate::arch::x86_64::pci::mmio::{read_u32, write_u32};
use super::types::NvmeController;

pub fn nvme_enable_controller(controller: &NvmeController) -> Result<(), &'static str> {
    let mut cc = 0u32;
    cc |= 1 << 0;
    cc |= 6 << 4;
    cc |= 4 << 7;
    cc |= 0 << 11;
    cc |= 1 << 14;
    cc |= 4 << 16;
    cc |= 6 << 20;

    write_u32(controller.bar0_base + 0x14, cc);

    let mut timeout = 1000;
    loop {
        let csts = read_u32(controller.bar0_base + 0x1C);
        if csts & 1 == 1 {
            break;
        }
        if timeout == 0 {
            return Err("NVMe controller enable timeout");
        }
        timeout -= 1;
        crate::arch::x86_64::asm::sleep_ms(1);
    }
    Ok(())
}