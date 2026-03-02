// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.


pub const CBW_SIGNATURE: u32 = 0x43425355; // "USBC"

pub const CSW_SIGNATURE: u32 = 0x53425355; // "USBS"

pub(super) const CBW_FLAG_DATA_IN: u8 = 0x80;

pub const CBW_SIZE: usize = 31;

pub const CSW_SIZE: usize = 13;

pub const MAX_MSC_DEVICES: usize = 8;
