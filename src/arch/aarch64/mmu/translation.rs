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

use core::arch::asm;

const PHYS_OFFSET: u64 = 0xFFFF_0000_0000_0000;
const KERNEL_OFFSET: u64 = 0xFFFF_8000_0000_0000;

pub fn virt_to_phys(virt: u64) -> Option<u64> {
    if virt >= KERNEL_OFFSET {
        return Some(virt - KERNEL_OFFSET);
    }

    if virt >= PHYS_OFFSET {
        return Some(virt - PHYS_OFFSET);
    }

    translate_address(virt)
}

pub fn phys_to_virt(phys: u64) -> u64 {
    PHYS_OFFSET + phys
}

pub fn kernel_phys_to_virt(phys: u64) -> u64 {
    KERNEL_OFFSET + phys
}

fn translate_address(virt: u64) -> Option<u64> {
    let par: u64;

    unsafe {
        asm!(
            "at s1e1r, {0}",
            "isb",
            "mrs {1}, par_el1",
            in(reg) virt,
            out(reg) par,
        );
    }

    if par & 1 != 0 {
        return None;
    }

    let phys_page = par & 0x0000_FFFF_FFFF_F000;
    let offset = virt & 0xFFF;

    Some(phys_page | offset)
}

pub fn translate_stage1_read(virt: u64) -> Result<u64, TranslationFault> {
    let par: u64;

    unsafe {
        asm!(
            "at s1e1r, {0}",
            "isb",
            "mrs {1}, par_el1",
            in(reg) virt,
            out(reg) par,
        );
    }

    parse_par(par, virt)
}

pub fn translate_stage1_write(virt: u64) -> Result<u64, TranslationFault> {
    let par: u64;

    unsafe {
        asm!(
            "at s1e1w, {0}",
            "isb",
            "mrs {1}, par_el1",
            in(reg) virt,
            out(reg) par,
        );
    }

    parse_par(par, virt)
}

pub fn translate_user_read(virt: u64) -> Result<u64, TranslationFault> {
    let par: u64;

    unsafe {
        asm!(
            "at s1e0r, {0}",
            "isb",
            "mrs {1}, par_el1",
            in(reg) virt,
            out(reg) par,
        );
    }

    parse_par(par, virt)
}

pub fn translate_user_write(virt: u64) -> Result<u64, TranslationFault> {
    let par: u64;

    unsafe {
        asm!(
            "at s1e0w, {0}",
            "isb",
            "mrs {1}, par_el1",
            in(reg) virt,
            out(reg) par,
        );
    }

    parse_par(par, virt)
}

fn parse_par(par: u64, virt: u64) -> Result<u64, TranslationFault> {
    if par & 1 != 0 {
        let fst = ((par >> 1) & 0x3F) as u8;
        let ptw = (par >> 8) & 1 != 0;
        let s = (par >> 9) & 1 != 0;

        return Err(TranslationFault {
            fault_status: fst,
            stage2: s,
            ptw_fault: ptw,
        });
    }

    let phys_page = par & 0x0000_FFFF_FFFF_F000;
    let offset = virt & 0xFFF;

    Ok(phys_page | offset)
}

#[derive(Debug, Clone, Copy)]
pub struct TranslationFault {
    pub fault_status: u8,
    pub stage2: bool,
    pub ptw_fault: bool,
}

impl TranslationFault {
    pub fn is_translation_fault(&self) -> bool {
        (self.fault_status & 0x3C) == 0x04
    }

    pub fn is_access_fault(&self) -> bool {
        (self.fault_status & 0x3C) == 0x08
    }

    pub fn is_permission_fault(&self) -> bool {
        (self.fault_status & 0x3C) == 0x0C
    }

    pub fn level(&self) -> u8 {
        self.fault_status & 0x03
    }
}

pub fn current_asid() -> u16 {
    let ttbr: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr);
    }
    (ttbr >> 48) as u16
}

pub fn set_asid(asid: u16) {
    let mut ttbr: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr);
    }

    ttbr = (ttbr & 0x0000_FFFF_FFFF_FFFF) | ((asid as u64) << 48);

    unsafe {
        asm!(
            "msr ttbr0_el1, {}",
            "isb",
            in(reg) ttbr,
        );
    }
}
