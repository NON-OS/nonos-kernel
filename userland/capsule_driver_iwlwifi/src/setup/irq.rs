// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use nonos_libc::{mk_device_release, mk_irq_bind, mk_mmio_unmap, IrqBindOut, MmioMapOut};

use crate::discover::Found;

pub fn bind(dev: Found, claim_epoch: u64, mmio: &MmioMapOut) -> Result<IrqBindOut, &'static str> {
    let mut out = IrqBindOut { grant_id: 0, vector: 0 };
    let r = mk_irq_bind(dev.device_id, claim_epoch, dev.irq_line as u32, 0, 0, &mut out);
    if r < 0 {
        let _ = mk_mmio_unmap(mmio.grant_id);
        let _ = mk_device_release(dev.device_id);
        Err("iwlwifi: irq bind failed")
    } else {
        Ok(out)
    }
}
