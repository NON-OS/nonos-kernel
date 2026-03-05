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

//! Circuit building state tracking

use alloc::vec::Vec;
use crate::network::onion::directory::RelayDescriptor;
use crate::network::onion::crypto::HopCrypto;
use super::types::CircuitId;

#[derive(Debug)]
pub(super) struct BuildingCircuit {
    pub id: CircuitId,
    pub target_hops: Vec<RelayDescriptor>,
    pub current_hop: usize,
    pub state: BuildState,
    pub crypto_state: Vec<HopCrypto>,
    pub start_time: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, PartialEq)]
pub(super) enum BuildState {
    SendingCreate,
    WaitingCreated,
    SendingExtend(usize),
    WaitingExtended(usize),
    Complete,
    Failed,
}
