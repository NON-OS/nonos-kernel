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

//! Top-level setup sequence: discover -> claim -> pio grant ->
//! irq bind -> flush stale bytes -> enable scanning. Returns the
//! driver binding the server loop runs against.

use super::claim::claim;
use super::driver::Driver;
use super::irq::bind as irq_bind;
use super::pio::grant as pio_grant;
use crate::discover::find_ps2_kbd;
use crate::init::{enable_scanning, flush_output};

pub fn run() -> Result<Driver, &'static str> {
    let dev = find_ps2_kbd().ok_or("ps2 keyboard not present in device list")?;
    let claim_epoch = claim(dev.device_id)?;
    let pio = pio_grant(dev.device_id, claim_epoch)?;
    let irq = irq_bind(dev, claim_epoch, pio.grant_id)?;

    flush_output(pio.grant_id);
    enable_scanning(pio.grant_id)?;

    Ok(Driver { pio_grant_id: pio.grant_id, irq_grant_id: irq.grant_id })
}
