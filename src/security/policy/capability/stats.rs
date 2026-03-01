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

use super::isolation::IsolationLevel;

#[derive(Debug)]
pub struct ChamberStats {
    pub id: u64,
    pub level: IsolationLevel,
    pub access_count: u64,
    pub violation_count: u32,
    pub sealed_regions_count: usize,
    pub attestation_chain_length: usize,
    pub ephemeral_keys_count: usize,
    pub creation_timestamp: u64,
    pub last_access: u64,
}
