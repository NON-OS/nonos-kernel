// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Family {
    F7265 = 1,
    F8265 = 2,
    F9260 = 3,
    Ax200 = 4,
    Ax210 = 5,
}

pub fn family_for_device(id: u16) -> Option<Family> {
    match id {
        0x08B1..=0x08B4 | 0x095A | 0x095B => Some(Family::F7265),
        0x24F3..=0x24FD => Some(Family::F8265),
        0x2526 | 0x9DF0 | 0xA370 | 0x31DC | 0x30DC | 0x271B | 0x271C => Some(Family::F9260),
        0x2723 | 0x34F0 | 0x3DF0 | 0x4DF0 | 0x02F0 | 0x06F0 | 0x43F0 => Some(Family::Ax200),
        0x2725 | 0x2729 | 0x272B | 0x51F0 | 0x51F1 | 0x54F0 | 0xA74F | 0x272F => Some(Family::Ax210),
        _ => None,
    }
}
