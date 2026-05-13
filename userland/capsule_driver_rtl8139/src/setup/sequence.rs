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

use crate::constants::MAC_LEN;
use crate::discover::find_rtl8139;
use crate::pio::Pio;

use super::driver::Driver;
use super::{claim, dma, irq, pci, pio_grant};

pub fn run() -> Result<Driver, &'static str> {
    let dev = find_rtl8139().ok_or("no rtl8139 device")?;
    let epoch = claim::claim(dev.device_id)?;
    pci::enable(dev, epoch)?;
    let pio = pio_grant::grant(dev, epoch)?;
    let irq = irq::bind(dev, epoch, &pio)?;
    let (rx, tx) = dma::map_all(dev.device_id, epoch, &pio, &irq)?;
    Ok(Driver {
        device_id: dev.device_id,
        pio_grant: pio.grant_id,
        irq_grant: irq.grant_id,
        rx_grant: rx.grant_id,
        tx_grant: tx.grant_id,
        rx_user_va: rx.user_va,
        rx_device_addr: rx.device_addr,
        tx_user_va: tx.user_va,
        tx_device_addr: tx.device_addr,
        rx_offset: 0,
        tx_cur: 0,
        pio: Pio::new(pio.grant_id),
        mac: [0u8; MAC_LEN],
    })
}
