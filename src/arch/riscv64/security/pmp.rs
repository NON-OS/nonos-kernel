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

const PMP_R: u8 = 1 << 0;
const PMP_W: u8 = 1 << 1;
const PMP_X: u8 = 1 << 2;

const PMP_A_OFF: u8 = 0 << 3;
const PMP_A_TOR: u8 = 1 << 3;
const PMP_A_NA4: u8 = 2 << 3;
const PMP_A_NAPOT: u8 = 3 << 3;

const PMP_L: u8 = 1 << 7;

#[derive(Debug, Clone, Copy)]
pub struct PmpConfig {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub address_mode: PmpAddressMode,
    pub locked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmpAddressMode {
    Off,
    Tor,
    Na4,
    Napot,
}

impl PmpConfig {
    pub const fn new() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
            address_mode: PmpAddressMode::Off,
            locked: false,
        }
    }

    pub const fn rwx() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            address_mode: PmpAddressMode::Napot,
            locked: false,
        }
    }

    pub const fn ro() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
            address_mode: PmpAddressMode::Napot,
            locked: false,
        }
    }

    pub const fn rx() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
            address_mode: PmpAddressMode::Napot,
            locked: false,
        }
    }

    pub const fn rw() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            address_mode: PmpAddressMode::Napot,
            locked: false,
        }
    }

    pub fn to_cfg_byte(&self) -> u8 {
        let mut cfg = 0u8;

        if self.read {
            cfg |= PMP_R;
        }
        if self.write {
            cfg |= PMP_W;
        }
        if self.execute {
            cfg |= PMP_X;
        }

        cfg |= match self.address_mode {
            PmpAddressMode::Off => PMP_A_OFF,
            PmpAddressMode::Tor => PMP_A_TOR,
            PmpAddressMode::Na4 => PMP_A_NA4,
            PmpAddressMode::Napot => PMP_A_NAPOT,
        };

        if self.locked {
            cfg |= PMP_L;
        }

        cfg
    }
}

impl Default for PmpConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PmpEntry {
    pub addr: u64,
    pub config: PmpConfig,
}

impl PmpEntry {
    pub fn new(addr: u64, config: PmpConfig) -> Self {
        Self { addr, config }
    }

    pub fn napot(base: u64, size: u64, config: PmpConfig) -> Self {
        let napot_addr = (base | (size / 2 - 1)) >> 2;
        Self {
            addr: napot_addr,
            config,
        }
    }
}

pub fn init_pmp() {
    let all_memory = PmpEntry::napot(0, u64::MAX, PmpConfig::rwx());
    set_pmp_entry(0, &all_memory);
}

pub fn set_pmp_entry(index: usize, entry: &PmpEntry) {
    if index >= 16 {
        return;
    }

    set_pmpaddr(index, entry.addr);
    set_pmpcfg(index, entry.config.to_cfg_byte());
}

fn set_pmpaddr(index: usize, addr: u64) {
    match index {
        0 => unsafe { asm!("csrw pmpaddr0, {}", in(reg) addr) },
        1 => unsafe { asm!("csrw pmpaddr1, {}", in(reg) addr) },
        2 => unsafe { asm!("csrw pmpaddr2, {}", in(reg) addr) },
        3 => unsafe { asm!("csrw pmpaddr3, {}", in(reg) addr) },
        4 => unsafe { asm!("csrw pmpaddr4, {}", in(reg) addr) },
        5 => unsafe { asm!("csrw pmpaddr5, {}", in(reg) addr) },
        6 => unsafe { asm!("csrw pmpaddr6, {}", in(reg) addr) },
        7 => unsafe { asm!("csrw pmpaddr7, {}", in(reg) addr) },
        _ => {}
    }
}

fn set_pmpcfg(index: usize, cfg: u8) {
    let shift = (index % 8) * 8;
    let reg_index = index / 8;

    let mask = !(0xFFu64 << shift);
    let new_cfg = (cfg as u64) << shift;

    match reg_index {
        0 => unsafe {
            let mut pmpcfg0: u64;
            asm!("csrr {}, pmpcfg0", out(reg) pmpcfg0);
            pmpcfg0 = (pmpcfg0 & mask) | new_cfg;
            asm!("csrw pmpcfg0, {}", in(reg) pmpcfg0);
        },
        1 => unsafe {
            let mut pmpcfg2: u64;
            asm!("csrr {}, pmpcfg2", out(reg) pmpcfg2);
            pmpcfg2 = (pmpcfg2 & mask) | new_cfg;
            asm!("csrw pmpcfg2, {}", in(reg) pmpcfg2);
        },
        _ => {}
    }
}

pub fn clear_pmp_entry(index: usize) {
    set_pmpaddr(index, 0);
    set_pmpcfg(index, 0);
}
