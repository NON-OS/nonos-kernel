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

use crate::constants::PARAM_VENDOR_ID;
use crate::controller::immediate;
use crate::regs::Regs;

pub const MAX_CODECS: usize = 15;

#[derive(Clone, Copy)]
pub struct CodecProbe {
    pub address: u8,
    pub present: u8,
    pub ok: u8,
    pub vendor_id: u16,
    pub device_id: u16,
}

pub fn probe(regs: Regs, statests: u16) -> [CodecProbe; MAX_CODECS] {
    let mut out = [empty(); MAX_CODECS];
    let mut address = 0u8;
    while (address as usize) < MAX_CODECS {
        let present = ((statests >> address) & 1) as u8;
        out[address as usize] = if present == 0 {
            CodecProbe { address, present, ok: 0, vendor_id: 0, device_id: 0 }
        } else {
            read_vendor(regs, address)
        };
        address = address.wrapping_add(1);
    }
    out
}

fn read_vendor(regs: Regs, address: u8) -> CodecProbe {
    match immediate::get_parameter(regs, address, 0, PARAM_VENDOR_ID) {
        Ok(id) => CodecProbe {
            address,
            present: 1,
            ok: 1,
            vendor_id: (id >> 16) as u16,
            device_id: id as u16,
        },
        Err(_) => CodecProbe { address, present: 1, ok: 0, vendor_id: 0, device_id: 0 },
    }
}

const fn empty() -> CodecProbe {
    CodecProbe { address: 0, present: 0, ok: 0, vendor_id: 0, device_id: 0 }
}
