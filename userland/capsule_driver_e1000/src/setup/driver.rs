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

//! `Driver` is the live state the server loop holds. It owns one
//! grant per broker primitive plus the RX/TX ring states. Drop on
//! shutdown releases the grants in reverse order so the broker
//! sees a clean teardown even when the capsule exits voluntarily.

use nonos_libc::{mk_device_release, mk_dma_unmap, mk_irq_unbind, mk_mmio_unmap};

use crate::constants::MAC_LEN;
use crate::queue::{RxRing, TxRing};
use crate::regs::Regs;

pub struct Driver {
    pub device_id: u64,
    pub mmio_grant: u64,
    pub irq_grant: u64,
    pub rx_ring_grant: u64,
    pub rx_buffer_grant: u64,
    pub tx_ring_grant: u64,
    pub tx_buffer_grant: u64,
    pub rx_ring_device_addr: u64,
    pub tx_ring_device_addr: u64,
    pub regs: Regs,
    pub mac: [u8; MAC_LEN],
    pub rx: RxRing,
    pub tx: TxRing,
}

impl Driver {
    /// Drop every grant the driver holds, in the reverse order
    /// the setup sequence took them. Each broker call is best-
    /// effort: an `EINVAL` from a doubly-dropped grant is harmless
    /// because the broker has already revoked it.
    pub fn release(&self) {
        let _ = mk_dma_unmap(self.tx_buffer_grant);
        let _ = mk_dma_unmap(self.tx_ring_grant);
        let _ = mk_dma_unmap(self.rx_buffer_grant);
        let _ = mk_dma_unmap(self.rx_ring_grant);
        let _ = mk_irq_unbind(self.irq_grant);
        let _ = mk_mmio_unmap(self.mmio_grant);
        let _ = mk_device_release(self.device_id);
    }
}
