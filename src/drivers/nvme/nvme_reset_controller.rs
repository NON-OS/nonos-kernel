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

pub fn nvme_reset_controller(controller: &NvmeController) -> Result<(), &'static str> {
    let cc_addr = controller.bar0_base + 0x14;
    write_u32(cc_addr, 0);

    let mut timeout = 1000;
    loop {
        let csts = read_u32(controller.bar0_base + 0x1C);
        if csts & 1 == 0 {
            break;
        }
        if timeout == 0 {
            return Err("NVMe controller reset timeout");
        }
        timeout -= 1;
        crate::arch::x86_64::asm::sleep_ms(1);
    }
    Ok(())
}