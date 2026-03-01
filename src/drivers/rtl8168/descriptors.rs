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

use core::sync::atomic::{AtomicU32, Ordering};

#[repr(C, align(256))]
pub struct Rtl8168RxDesc {
    pub opts1: AtomicU32,
    pub opts2: AtomicU32,
    pub addr_low: AtomicU32,
    pub addr_high: AtomicU32,
}

impl Rtl8168RxDesc {
    pub const fn new() -> Self {
        Self {
            opts1: AtomicU32::new(0),
            opts2: AtomicU32::new(0),
            addr_low: AtomicU32::new(0),
            addr_high: AtomicU32::new(0),
        }
    }

    pub fn init(&self, buffer_addr: u64, buffer_size: u16, is_last: bool) {
        let mut opts1 = (buffer_size as u32) & 0x3FFF;
        opts1 |= super::constants::desc_status::OWN;
        if is_last {
            opts1 |= super::constants::desc_status::EOR;
        }

        self.addr_low.store(buffer_addr as u32, Ordering::Release);
        self.addr_high.store((buffer_addr >> 32) as u32, Ordering::Release);
        self.opts2.store(0, Ordering::Release);
        self.opts1.store(opts1, Ordering::Release);
    }

    pub fn is_owned_by_hardware(&self) -> bool {
        (self.opts1.load(Ordering::Acquire) & super::constants::desc_status::OWN) != 0
    }

    pub fn frame_length(&self) -> u16 {
        (self.opts1.load(Ordering::Acquire) & 0x3FFF) as u16
    }

    pub fn is_first(&self) -> bool {
        (self.opts1.load(Ordering::Acquire) & super::constants::desc_status::FS) != 0
    }

    pub fn is_last(&self) -> bool {
        (self.opts1.load(Ordering::Acquire) & super::constants::desc_status::LS) != 0
    }

    pub fn has_error(&self) -> bool {
        let opts1 = self.opts1.load(Ordering::Acquire);
        (opts1 & 0x00200000) != 0
    }

    pub fn reset(&self, buffer_size: u16, is_last: bool) {
        let mut opts1 = (buffer_size as u32) & 0x3FFF;
        opts1 |= super::constants::desc_status::OWN;
        if is_last {
            opts1 |= super::constants::desc_status::EOR;
        }
        self.opts2.store(0, Ordering::Release);
        self.opts1.store(opts1, Ordering::Release);
    }
}

#[repr(C, align(256))]
pub struct Rtl8168TxDesc {
    pub opts1: AtomicU32,
    pub opts2: AtomicU32,
    pub addr_low: AtomicU32,
    pub addr_high: AtomicU32,
}

impl Rtl8168TxDesc {
    pub const fn new() -> Self {
        Self {
            opts1: AtomicU32::new(0),
            opts2: AtomicU32::new(0),
            addr_low: AtomicU32::new(0),
            addr_high: AtomicU32::new(0),
        }
    }

    pub fn init(&self, buffer_addr: u64, is_last: bool) {
        self.addr_low.store(buffer_addr as u32, Ordering::Release);
        self.addr_high.store((buffer_addr >> 32) as u32, Ordering::Release);
        let mut opts1 = 0u32;
        if is_last {
            opts1 |= super::constants::tx_desc::EOR;
        }
        self.opts2.store(0, Ordering::Release);
        self.opts1.store(opts1, Ordering::Release);
    }

    pub fn is_owned_by_hardware(&self) -> bool {
        (self.opts1.load(Ordering::Acquire) & super::constants::tx_desc::OWN) != 0
    }

    pub fn set_packet(&self, length: u16, is_last_desc: bool, is_last_ring: bool) {
        let mut opts1 = (length as u32) & 0xFFFF;
        opts1 |= super::constants::tx_desc::OWN;
        opts1 |= super::constants::tx_desc::FS;
        opts1 |= super::constants::tx_desc::LS;
        if is_last_ring {
            opts1 |= super::constants::tx_desc::EOR;
        }
        self.opts2.store(0, Ordering::Release);
        self.opts1.store(opts1, Ordering::Release);
    }

    pub fn clear(&self, is_last: bool) {
        let opts1 = if is_last {
            super::constants::tx_desc::EOR
        } else {
            0
        };
        self.opts1.store(opts1, Ordering::Release);
        self.opts2.store(0, Ordering::Release);
    }
}
