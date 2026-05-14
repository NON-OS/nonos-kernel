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

//! IANA IP protocol numbers used by this capsule. The dispatch
//! path matches on these exact constants; an unrecognised number
//! drops the packet rather than guessing.

pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Icmp,
    Tcp,
    Udp,
}

impl Proto {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            ICMP => Some(Self::Icmp),
            TCP => Some(Self::Tcp),
            UDP => Some(Self::Udp),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Icmp => ICMP,
            Self::Tcp => TCP,
            Self::Udp => UDP,
        }
    }
}
