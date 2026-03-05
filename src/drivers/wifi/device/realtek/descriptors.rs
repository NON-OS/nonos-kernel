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
pub(super) struct RtlTxDesc {
    pub word0: AtomicU32,
    pub word1: AtomicU32,
    pub word2: AtomicU32,
    pub word3: AtomicU32,
    pub word4: AtomicU32,
    pub word5: AtomicU32,
    pub word6: AtomicU32,
    pub word7: AtomicU32,
    pub word8: AtomicU32,
    pub word9: AtomicU32,
    pub word10: AtomicU32,
    pub word11: AtomicU32,
}

impl RtlTxDesc {
    pub(super) const fn new() -> Self {
        Self {
            word0: AtomicU32::new(0),
            word1: AtomicU32::new(0),
            word2: AtomicU32::new(0),
            word3: AtomicU32::new(0),
            word4: AtomicU32::new(0),
            word5: AtomicU32::new(0),
            word6: AtomicU32::new(0),
            word7: AtomicU32::new(0),
            word8: AtomicU32::new(0),
            word9: AtomicU32::new(0),
            word10: AtomicU32::new(0),
            word11: AtomicU32::new(0),
        }
    }

    pub(super) fn set_own(&self, own: bool) {
        let val = self.word0.load(Ordering::Acquire);
        if own {
            self.word0.store(val | (1 << 31), Ordering::Release);
        } else {
            self.word0.store(val & !(1 << 31), Ordering::Release);
        }
    }

    pub(super) fn is_own(&self) -> bool {
        self.word0.load(Ordering::Acquire) & (1 << 31) != 0
    }

    pub(super) fn set_pkt_size(&self, size: u16) {
        let val = self.word0.load(Ordering::Acquire);
        let new_val = (val & 0xFFFF0000) | (size as u32);
        self.word0.store(new_val, Ordering::Release);
    }

    pub(super) fn set_buffer_addr(&self, addr: u64) {
        self.word10.store(addr as u32, Ordering::Release);
        self.word11.store((addr >> 32) as u32, Ordering::Release);
    }

    pub(super) fn set_first_seg(&self, first: bool) {
        let val = self.word0.load(Ordering::Acquire);
        if first {
            self.word0.store(val | (1 << 26), Ordering::Release);
        } else {
            self.word0.store(val & !(1 << 26), Ordering::Release);
        }
    }

    pub(super) fn set_last_seg(&self, last: bool) {
        let val = self.word0.load(Ordering::Acquire);
        if last {
            self.word0.store(val | (1 << 27), Ordering::Release);
        } else {
            self.word0.store(val & !(1 << 27), Ordering::Release);
        }
    }

    pub(super) fn set_offset(&self, offset: u8) {
        let val = self.word0.load(Ordering::Acquire);
        let new_val = (val & 0xFF00FFFF) | ((offset as u32) << 16);
        self.word0.store(new_val, Ordering::Release);
    }

    pub(super) fn configure_tx(&self, size: u16, addr: u64) {
        self.word0.store(0, Ordering::Release);
        self.word1.store(0, Ordering::Release);
        self.word2.store(0, Ordering::Release);
        self.word3.store(0, Ordering::Release);
        self.word4.store(0, Ordering::Release);
        self.word5.store(0, Ordering::Release);
        self.word6.store(0, Ordering::Release);
        self.word7.store(0, Ordering::Release);
        self.word8.store(0, Ordering::Release);
        self.word9.store(0, Ordering::Release);

        self.set_buffer_addr(addr);
        self.set_pkt_size(size);
        self.set_offset(48);
        self.set_first_seg(true);
        self.set_last_seg(true);
        self.set_own(true);
    }
}

#[repr(C, align(256))]
pub(super) struct RtlRxDesc {
    pub word0: AtomicU32,
    pub word1: AtomicU32,
    pub word2: AtomicU32,
    pub word3: AtomicU32,
    pub word4: AtomicU32,
    pub word5: AtomicU32,
}

impl RtlRxDesc {
    pub(super) const fn new() -> Self {
        Self {
            word0: AtomicU32::new(0),
            word1: AtomicU32::new(0),
            word2: AtomicU32::new(0),
            word3: AtomicU32::new(0),
            word4: AtomicU32::new(0),
            word5: AtomicU32::new(0),
        }
    }

    pub(super) fn is_own(&self) -> bool {
        self.word0.load(Ordering::Acquire) & (1 << 31) != 0
    }

    pub(super) fn set_own(&self) {
        let val = self.word0.load(Ordering::Acquire);
        self.word0.store(val | (1 << 31), Ordering::Release);
    }

    pub(super) fn clear_own(&self) {
        let val = self.word0.load(Ordering::Acquire);
        self.word0.store(val & !(1 << 31), Ordering::Release);
    }

    pub(super) fn pkt_len(&self) -> u16 {
        (self.word0.load(Ordering::Acquire) & 0x3FFF) as u16
    }

    pub(super) fn is_first_seg(&self) -> bool {
        self.word0.load(Ordering::Acquire) & (1 << 26) != 0
    }

    pub(super) fn is_last_seg(&self) -> bool {
        self.word0.load(Ordering::Acquire) & (1 << 27) != 0
    }

    pub(super) fn is_crc_err(&self) -> bool {
        self.word0.load(Ordering::Acquire) & (1 << 14) != 0
    }

    pub(super) fn is_icv_err(&self) -> bool {
        self.word0.load(Ordering::Acquire) & (1 << 15) != 0
    }

    pub(super) fn set_buffer_addr(&self, addr: u64) {
        self.word4.store(addr as u32, Ordering::Release);
        self.word5.store((addr >> 32) as u32, Ordering::Release);
    }

    pub(super) fn set_buffer_size(&self, size: u16) {
        let val = self.word0.load(Ordering::Acquire);
        let new_val = (val & 0xFFFF0000) | (size as u32);
        self.word0.store(new_val, Ordering::Release);
    }

    pub(super) fn configure_rx(&self, size: u16, addr: u64) {
        self.word0.store(0, Ordering::Release);
        self.word1.store(0, Ordering::Release);
        self.word2.store(0, Ordering::Release);
        self.word3.store(0, Ordering::Release);
        self.set_buffer_addr(addr);
        self.set_buffer_size(size);
        self.set_own();
    }
}
