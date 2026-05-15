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
    let mut body = [0u8; 32];
    body[0..8].copy_from_slice(&driver.device_id.to_le_bytes());
    body[8..10].copy_from_slice(&driver.pci_device.to_le_bytes());
    body[12..16].copy_from_slice(&driver.hw_rev.to_le_bytes());
    body[16..20].copy_from_slice(&(driver.family as u32).to_le_bytes());
    body[20..24].copy_from_slice(&driver.gp_cntrl.to_le_bytes());
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}
