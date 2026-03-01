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

use crate::capabilities::{Capability, CapabilityToken};

impl CapabilityToken {
    #[inline] pub fn can_exit(&self)   -> bool { self.grants(Capability::CoreExec) && self.is_valid() }
    #[inline] pub fn can_getpid(&self) -> bool { self.grants(Capability::CoreExec) && self.is_valid() }
    #[inline] pub fn can_fork(&self)   -> bool { self.grants(Capability::CoreExec) && self.is_valid() }
    #[inline] pub fn can_exec(&self)   -> bool { self.grants(Capability::CoreExec) && self.is_valid() }
    #[inline] pub fn can_wait(&self)   -> bool { self.grants(Capability::CoreExec) && self.is_valid() }
    #[inline] pub fn can_signal(&self) -> bool { self.grants(Capability::CoreExec) && self.is_valid() }
    #[inline] pub fn can_read(&self)   -> bool { self.grants(Capability::IO) && self.is_valid() }
    #[inline] pub fn can_write(&self)  -> bool { self.grants(Capability::IO) && self.is_valid() }
    #[inline] pub fn can_open_files(&self) -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_close_files(&self) -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_stat(&self)   -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_seek(&self)   -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_modify_dirs(&self) -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_unlink(&self) -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_allocate_memory(&self) -> bool { self.grants(Capability::Memory) && self.is_valid() }
    #[inline] pub fn can_deallocate_memory(&self) -> bool { self.grants(Capability::Memory) && self.is_valid() }
    #[inline] pub fn can_network(&self) -> bool { self.grants(Capability::Network) && self.is_valid() }
    #[inline] pub fn can_ipc(&self) -> bool { self.grants(Capability::IPC) && self.is_valid() }
    #[inline] pub fn can_crypto(&self) -> bool { self.grants(Capability::Crypto) && self.is_valid() }
    #[inline] pub fn can_hardware(&self) -> bool { self.grants(Capability::Hardware) && self.is_valid() }
    #[inline] pub fn can_debug(&self) -> bool { self.grants(Capability::Debug) && self.is_valid() }
    #[inline] pub fn can_admin(&self) -> bool { self.grants(Capability::Admin) && self.is_valid() }
}
