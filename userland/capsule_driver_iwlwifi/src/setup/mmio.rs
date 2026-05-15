// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use nonos_libc::{mk_device_release, mk_mmio_map, MmioMapOut};

use crate::constants::{BAR_INDEX, BAR_OFFSET, PAGE_MASK};
use crate::discover::Found;

pub fn map(dev: Found, claim_epoch: u64) -> Result<MmioMapOut, &'static str> {
    let mut out = MmioMapOut { user_va: 0, length: 0, grant_id: 0 };
    let length = (dev.bar0_size + PAGE_MASK) & !PAGE_MASK;
    let r = mk_mmio_map(dev.device_id, claim_epoch, BAR_INDEX, 0, BAR_OFFSET, length, &mut out);
    if r < 0 {
        let _ = mk_device_release(dev.device_id);
        Err("iwlwifi: mmio map failed")
    } else {
        Ok(out)
    }
}
