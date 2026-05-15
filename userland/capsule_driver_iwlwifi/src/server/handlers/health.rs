// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use crate::protocol::{Request, E_OK};
use crate::server::respond;

pub fn handle(sender_pid: u32, req: &Request, out: &mut [u8]) {
    let _ = respond::send(sender_pid, req, E_OK, &[], out);
}
