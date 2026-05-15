// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use nonos_libc::{
    mk_device_release, mk_dma_map, mk_irq_unbind, mk_mmio_unmap, DmaMapOut, IrqBindOut, MmioMapOut,
};

use crate::constants::FW_STAGING_SIZE;

pub fn map_staging(
    device_id: u64,
    claim_epoch: u64,
    mmio: &MmioMapOut,
    irq: &IrqBindOut,
) -> Result<DmaMapOut, &'static str> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let r = mk_dma_map(device_id, claim_epoch, FW_STAGING_SIZE, 0, &mut out);
    if r < 0 {
        let _ = mk_irq_unbind(irq.grant_id);
        let _ = mk_mmio_unmap(mmio.grant_id);
        let _ = mk_device_release(device_id);
        Err("iwlwifi: dma staging failed")
    } else {
        Ok(out)
    }
}
