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

extern crate alloc;

use super::address::NymAddress;
use super::constants::NYM_MIX_LAYERS;
use super::ids::{MixNodeId, SurbId};
use super::nodes::{Gateway, MixNode};
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct NymRoute {
    pub gateway: Gateway,
    pub mixnodes: [MixNode; NYM_MIX_LAYERS],
    pub destination: NymAddress,
}

#[derive(Clone, Debug)]
pub struct Surb {
    pub id: SurbId,
    pub first_hop: MixNodeId,
    pub header: Vec<u8>,
    pub payload_key: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    Regular,
    Cover,
    Ack,
    Fragment,
}

impl PacketType {
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::Regular => 0,
            Self::Cover => 1,
            Self::Ack => 2,
            Self::Fragment => 3,
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Regular),
            1 => Some(Self::Cover),
            2 => Some(Self::Ack),
            3 => Some(Self::Fragment),
            _ => None,
        }
    }
}
