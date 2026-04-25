// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CircuitPermission {
    BootAuthority = 1 << 0,
    UpdateAuthority = 1 << 1,
    RecoveryKey = 1 << 2,
    CommunityKey = 1 << 3,
    UserCircuit = 1 << 4,
    Attestation = 1 << 5,
    CircuitAdmin = 1 << 6,
    NetworkAccess = 1 << 7,
    FilesystemAccess = 1 << 8,
    HardwareAccess = 1 << 9,
}
