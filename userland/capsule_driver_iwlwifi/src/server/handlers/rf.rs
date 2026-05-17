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
    let mut body = [0u8; 8];
    body[0..4].copy_from_slice(&(driver.rf_kill as u32).to_le_bytes());
    body[4..8].copy_from_slice(&driver.regs.read32(crate::constants::CSR_GP_CNTRL).to_le_bytes());
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}
