// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use crate::driver::Driver;
use crate::protocol::{Request, FW_NAME_MAX, E_OK};
use crate::server::respond;

pub fn handle(driver: &Driver, sender_pid: u32, req: &Request, out: &mut [u8]) {
    let fw = driver.firmware();
    let name = fw.name.as_bytes();
    let n = core::cmp::min(name.len(), FW_NAME_MAX);
    let mut body = [0u8; 80];
    body[0..4].copy_from_slice(&(n as u32).to_le_bytes());
    body[4..12].copy_from_slice(&(fw.bytes.len() as u64).to_le_bytes());
    body[16..16 + n].copy_from_slice(&name[..n]);
    let _ = respond::send(sender_pid, req, E_OK, &body[..16 + n], out);
}
