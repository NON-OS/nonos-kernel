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


use crate::network::onion::OnionError;

pub const CELL_SIZE: usize = 514;
pub const CELL_HEADER_SIZE: usize = 5;
pub const CELL_PAYLOAD_SIZE: usize = 509;

pub const VAR_CELL_HEADER_SIZE: usize = 7;
pub const MAX_VAR_CELL_PAYLOAD_SIZE: usize = 65535;

pub const RELAY_HEADER_SIZE: usize = 11;
pub const RELAY_PAYLOAD_SIZE: usize = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE;

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum CellType {
    Padding = 0,
    Create = 1,
    Created = 2,
    Relay = 3,
    Destroy = 4,
    CreateFast = 5,
    CreatedFast = 6,

    Versions = 7,
    NetInfo = 8,
    RelayEarly = 9,
    Create2 = 10,
    Created2 = 11,

    VPadding = 128,
    Certs = 129,
    AuthChallenge = 130,
    Authenticate = 131,
    Authorize = 132,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum RelayCommand {
    RelayBegin = 1,
    RelayData = 2,
    RelayEnd = 3,
    RelayConnected = 4,
    RelaySendme = 5,
    RelayExtend = 6,
    RelayExtended = 7,
    RelayTruncate = 8,
    RelayTruncated = 9,
    RelayDrop = 10,
    RelayResolve = 11,
    RelayResolved = 12,
    RelayBeginDir = 13,
    RelayExtend2 = 14,
    RelayExtended2 = 15,

    RelayEstablishIntro = 32,
    RelayEstablishRendezvous = 33,
    RelayIntroduce1 = 34,
    RelayIntroduce2 = 35,
    RelayRendezvous1 = 36,
    RelayRendezvous2 = 37,
    RelayIntroEstablished = 38,
    RelayRendezvousEstablished = 39,
    RelayIntroduceAck = 40,
}

impl RelayCommand {
    pub fn from_u8(value: u8) -> Result<Self, OnionError> {
        match value {
            1 => Ok(RelayCommand::RelayBegin),
            2 => Ok(RelayCommand::RelayData),
            3 => Ok(RelayCommand::RelayEnd),
            4 => Ok(RelayCommand::RelayConnected),
            5 => Ok(RelayCommand::RelaySendme),
            6 => Ok(RelayCommand::RelayExtend),
            7 => Ok(RelayCommand::RelayExtended),
            8 => Ok(RelayCommand::RelayTruncate),
            9 => Ok(RelayCommand::RelayTruncated),
            10 => Ok(RelayCommand::RelayDrop),
            11 => Ok(RelayCommand::RelayResolve),
            12 => Ok(RelayCommand::RelayResolved),
            13 => Ok(RelayCommand::RelayBeginDir),
            14 => Ok(RelayCommand::RelayExtend2),
            15 => Ok(RelayCommand::RelayExtended2),
            32 => Ok(RelayCommand::RelayEstablishIntro),
            33 => Ok(RelayCommand::RelayEstablishRendezvous),
            34 => Ok(RelayCommand::RelayIntroduce1),
            35 => Ok(RelayCommand::RelayIntroduce2),
            36 => Ok(RelayCommand::RelayRendezvous1),
            37 => Ok(RelayCommand::RelayRendezvous2),
            38 => Ok(RelayCommand::RelayIntroEstablished),
            39 => Ok(RelayCommand::RelayRendezvousEstablished),
            40 => Ok(RelayCommand::RelayIntroduceAck),
            _ => Err(OnionError::InvalidCell),
        }
    }
}
