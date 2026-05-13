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

use nonos_libc::{mk_device_release, mk_dma_unmap, mk_irq_unbind, mk_pio_release};

use crate::constants::MAC_LEN;
use crate::pio::Pio;

pub struct Driver {
    pub device_id: u64,
    pub pio_grant: u64,
    pub irq_grant: u64,
    pub rx_grant: u64,
    pub tx_grant: u64,
    pub rx_user_va: u64,
    pub rx_device_addr: u64,
    pub tx_user_va: u64,
    pub tx_device_addr: u64,
    pub rx_offset: usize,
    pub tx_cur: usize,
    pub pio: Pio,
    pub mac: [u8; MAC_LEN],
}

impl Driver {
    pub fn release(&self) {
        let _ = mk_dma_unmap(self.tx_grant);
        let _ = mk_dma_unmap(self.rx_grant);
        let _ = mk_irq_unbind(self.irq_grant);
        let _ = mk_pio_release(self.pio_grant);
        let _ = mk_device_release(self.device_id);
    }
}
