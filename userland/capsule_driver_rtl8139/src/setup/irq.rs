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

use nonos_libc::{mk_device_release, mk_irq_bind, mk_pio_release, IrqBindOut, PioGrantOut};

use crate::discover::Found;

pub fn bind(dev: Found, claim_epoch: u64, pio: &PioGrantOut) -> Result<IrqBindOut, &'static str> {
    let mut out = IrqBindOut { grant_id: 0, vector: 0 };
    let r = mk_irq_bind(dev.device_id, claim_epoch, dev.irq_line as u32, 0, 0, &mut out);
    if r < 0 {
        after_pio(dev.device_id, pio);
        return Err("irq bind failed");
    }
    Ok(out)
}

pub fn after_pio(device_id: u64, pio: &PioGrantOut) {
    let _ = mk_pio_release(pio.grant_id);
    let _ = mk_device_release(device_id);
}
