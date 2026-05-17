// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

pub const MAGIC: u32 = 0x4E49_5746;
pub const VERSION: u16 = 1;
pub const HDR_LEN: usize = 20;

#[derive(Clone, Copy)]
pub struct Request {
    pub op: u16,
    pub request_id: u32,
}
