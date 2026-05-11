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

//! IRQ-bind phase. Binds the IBM-compatible PS/2 keyboard's
//! legacy line (GSI 1) to a broker IRQ slot. On failure, the
//! prior PIO grant and device claim are unwound so the broker is
//! left clean.

use nonos_libc::{mk_device_release, mk_irq_bind, mk_pio_release, IrqBindOut};

use crate::discover::Found;

pub fn bind(
    dev: Found,
    claim_epoch: u64,
    pio_grant_id: u64,
) -> Result<IrqBindOut, &'static str> {
    let mut out = IrqBindOut { grant_id: 0, vector: 0 };
    let r = mk_irq_bind(dev.device_id, claim_epoch, dev.irq_line as u32, 0, 0, &mut out);
    if r < 0 {
        let _ = mk_pio_release(pio_grant_id);
        let _ = mk_device_release(dev.device_id);
        return Err("irq bind failed");
    }
    Ok(out)
}
