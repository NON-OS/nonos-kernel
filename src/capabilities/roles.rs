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

use super::types::Capability;
use Capability::*;

pub const KERNEL: &[Capability] = &[
    CoreExec, IO, Network, IPC, Memory, Crypto, FileSystem, Hardware, Debug, Admin,
];

pub const SYSTEM_SERVICE: &[Capability] = &[CoreExec, IPC, Memory, FileSystem];

pub const SANDBOXED_MOD: &[Capability] = &[CoreExec, IPC, Memory];

pub const NETWORK_SERVICE: &[Capability] = &[CoreExec, IPC, Memory, Network];

pub const USER_APP: &[Capability] = &[CoreExec, IPC];

pub const CRYPTO_SERVICE: &[Capability] = &[CoreExec, IPC, Memory, Crypto];

pub const DRIVER: &[Capability] = &[CoreExec, IPC, Memory, Hardware, IO];

pub const DEBUGGER: &[Capability] = &[CoreExec, IPC, Memory, Debug];
