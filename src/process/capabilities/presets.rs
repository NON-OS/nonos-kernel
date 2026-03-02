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

use super::types::{Capability, CapabilitySet};

pub fn standard_user_capabilities() -> CapabilitySet {
    let mut caps = CapabilitySet::new();
    caps.grant(Capability::Exit);
    caps.grant(Capability::Read);
    caps.grant(Capability::Write);
    caps.grant(Capability::OpenFiles);
    caps.grant(Capability::CloseFiles);
    caps.grant(Capability::AllocateMemory);
    caps.grant(Capability::DeallocateMemory);
    caps.grant(Capability::Stat);
    caps.grant(Capability::Seek);
    caps.grant(Capability::SendIpc);
    caps.grant(Capability::ReceiveIpc);
    caps
}

pub fn privileged_capabilities() -> CapabilitySet {
    let mut caps = standard_user_capabilities();
    caps.grant(Capability::Fork);
    caps.grant(Capability::Exec);
    caps.grant(Capability::Signal);
    caps.grant(Capability::Network);
    caps
}

pub fn system_capabilities() -> CapabilitySet {
    let mut caps = privileged_capabilities();
    caps.grant(Capability::LoadModules);
    caps.grant(Capability::UseCrypto);
    caps.grant(Capability::RawIO);
    caps.grant(Capability::ModifyDirs);
    caps.grant(Capability::Unlink);
    caps
}

pub fn full_capabilities() -> CapabilitySet {
    CapabilitySet::from_bits(u64::MAX)
}

pub fn sandboxed_capabilities() -> CapabilitySet {
    let mut caps = CapabilitySet::new();
    caps.grant(Capability::Exit);
    caps.grant(Capability::Read);
    caps.grant(Capability::Write);
    caps
}

pub fn network_service_capabilities() -> CapabilitySet {
    let mut caps = standard_user_capabilities();
    caps.grant(Capability::Network);
    caps
}
