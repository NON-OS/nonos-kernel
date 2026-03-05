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

//! Directory service for Tor network consensus and relay information

mod authorities;
mod consensus;
mod encoding;
mod microdesc;
mod path;
mod service;
mod types;

pub use service::DirectoryService;
pub use types::{
    BandwidthWeights, ConsensusEntry, ConsensusSignature, DirectoryAuthority,
    DirectoryAuthorityHeader, DirectoryStats, ExitPolicy, ExitRule, MicroParsed,
    NetworkConsensus, PathBiasStats, PortRange, RelayDescriptor, RelayFlags, RouterStatus, SigAlg,
};
