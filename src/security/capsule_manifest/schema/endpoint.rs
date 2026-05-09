// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::constants::MAX_ENDPOINT_NAME_LEN;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Service = 1,
    Reply = 2,
}

impl EndpointKind {
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Service),
            2 => Some(Self::Reply),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone)]
pub struct EndpointDecl {
    pub kind: EndpointKind,
    pub port: u32,
    pub name: [u8; MAX_ENDPOINT_NAME_LEN],
    pub name_len: u8,
}

impl EndpointDecl {
    pub fn name_str(&self) -> &str {
        let n = self.name_len as usize;
        core::str::from_utf8(&self.name[..n]).unwrap_or("")
    }
}
