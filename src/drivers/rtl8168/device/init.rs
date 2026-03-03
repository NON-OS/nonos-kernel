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

use core::sync::atomic::Ordering;

use super::super::constants::{cmd, desc_status, int, rcr, reg, tcr, tx_desc};
use super::super::constants::{RX_BUFFER_SIZE, RX_DESC_COUNT, TX_BUFFER_SIZE, TX_DESC_COUNT};
use super::super::descriptors::{Rtl8168RxDesc, Rtl8168TxDesc};
use super::core::Rtl8168Device;

impl Rtl8168Device {
    pub(super) fn software_reset(&mut self) -> Result<(), &'static str> {
        self.write8(reg::CR, cmd::RST);

        for _ in 0..1000 {
            if (self.read8(reg::CR) & cmd::RST) == 0 {
                return Ok(());
            }
            self.spin_delay(10);
        }

        Err("RTL8168: Reset timeout")
    }

    pub(super) fn read_mac_address(&mut self) {
        let mac0 = self.read32(reg::MAC0);
        let mac4 = self.read32(reg::MAC4);

        self.mac_address[0] = mac0 as u8;
        self.mac_address[1] = (mac0 >> 8) as u8;
        self.mac_address[2] = (mac0 >> 16) as u8;
        self.mac_address[3] = (mac0 >> 24) as u8;
        self.mac_address[4] = mac4 as u8;
        self.mac_address[5] = (mac4 >> 8) as u8;
    }

    pub(super) fn init_rx(&mut self) {
        let descs = self.rx_descs_virt.as_mut_ptr::<Rtl8168RxDesc>();

        for i in 0..RX_DESC_COUNT {
            let phys = self.rx_buffers_phys[i];
            let is_last = i == RX_DESC_COUNT - 1;

            unsafe {
                let desc = &*descs.add(i);
                let mut opts1 = (RX_BUFFER_SIZE as u32) & 0x3FFF;
                opts1 |= desc_status::OWN;
                if is_last {
                    opts1 |= desc_status::EOR;
                }
                desc.addr_low.store(phys.as_u64() as u32, Ordering::Release);
                desc.addr_high.store((phys.as_u64() >> 32) as u32, Ordering::Release);
                desc.opts2.store(0, Ordering::Release);
                desc.opts1.store(opts1, Ordering::Release);
            }
        }

        self.write32(reg::RDSAR_LOW, self.rx_descs_phys.as_u64() as u32);
        self.write32(reg::RDSAR_HIGH, (self.rx_descs_phys.as_u64() >> 32) as u32);

        self.write32(
            reg::RCR,
            rcr::AAP | rcr::APM | rcr::AM | rcr::AB | rcr::RXFTH_NONE | rcr::MXDMA_UNLIM,
        );

        self.write16(reg::RMS, RX_BUFFER_SIZE as u16);
    }

    pub(super) fn init_tx(&mut self) {
        let descs = self.tx_descs_virt.as_mut_ptr::<Rtl8168TxDesc>();

        for i in 0..TX_DESC_COUNT {
            let phys = self.tx_buffers_phys[i];
            let is_last = i == TX_DESC_COUNT - 1;

            unsafe {
                let desc = &*descs.add(i);
                desc.addr_low.store(phys.as_u64() as u32, Ordering::Release);
                desc.addr_high.store((phys.as_u64() >> 32) as u32, Ordering::Release);
                desc.opts2.store(0, Ordering::Release);
                let opts1 = if is_last { tx_desc::EOR } else { 0 };
                desc.opts1.store(opts1, Ordering::Release);
            }
        }

        self.write32(reg::TNPDS_LOW, self.tx_descs_phys.as_u64() as u32);
        self.write32(reg::TNPDS_HIGH, (self.tx_descs_phys.as_u64() >> 32) as u32);

        self.write32(reg::TCR, tcr::IFG_STD | tcr::MXDMA_UNLIM);

        self.write8(reg::MTPS, (TX_BUFFER_SIZE / 128) as u8);
    }

    pub(super) fn enable_interrupts(&mut self) {
        self.write16(
            reg::IMR,
            int::ROK | int::RER | int::TOK | int::TER | int::RDU | int::LINK_CHG | int::TDU,
        );
    }

    pub(super) fn enable_rx_tx(&mut self) {
        let cr = self.read8(reg::CR);
        self.write8(reg::CR, cr | cmd::RE | cmd::TE);
    }
}
