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

//! MMIO phase: map the legacy register window in BAR0 into the
//! capsule's address space. Length is rounded up to the broker's
//! 4 KiB page granularity from the BAR size the broker reported.

use nonos_libc::{mk_device_release, mk_mmio_map, MmioMapOut};

use crate::constants::{BAR_INDEX, BAR_OFFSET};
use crate::discover::Found;

const PAGE_MASK: u64 = 0xFFF;

pub fn map(dev: Found, claim_epoch: u64) -> Result<MmioMapOut, &'static str> {
    let mut out = MmioMapOut { user_va: 0, length: 0, grant_id: 0 };
    let length = (dev.bar0_size + PAGE_MASK) & !PAGE_MASK;
    let r = mk_mmio_map(dev.device_id, claim_epoch, BAR_INDEX, 0, BAR_OFFSET, length, &mut out);
    if r < 0 {
        let _ = mk_device_release(dev.device_id);
        return Err("mmio map failed");
    }
    Ok(out)
}
