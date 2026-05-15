// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use crate::driver::Driver;
use crate::protocol::{Request, E_OK};
use crate::server::respond;

pub fn handle(driver: &Driver, sender_pid: u32, req: &Request, out: &mut [u8]) {
    let mut body = [0u8; 56];
    body[0..8].copy_from_slice(&driver.dma_grant.to_le_bytes());
    body[8..16].copy_from_slice(&driver.dma_user_va.to_le_bytes());
    body[16..24].copy_from_slice(&driver.dma_device_addr.to_le_bytes());
    body[24..32].copy_from_slice(&driver.dma_len.to_le_bytes());
    body[32..40].copy_from_slice(&driver.claim_epoch.to_le_bytes());
    body[40..48].copy_from_slice(&driver.mmio_grant.to_le_bytes());
    body[48..56].copy_from_slice(&driver.irq_grant.to_le_bytes());
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}
