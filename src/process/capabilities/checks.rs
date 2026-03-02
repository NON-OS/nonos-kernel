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

impl CapabilitySet {
    #[inline]
    pub fn can_exit(&self) -> bool {
        self.has(Capability::Exit)
    }

    #[inline]
    pub fn can_read(&self) -> bool {
        self.has(Capability::Read)
    }

    #[inline]
    pub fn can_write(&self) -> bool {
        self.has(Capability::Write)
    }

    #[inline]
    pub fn can_open_files(&self) -> bool {
        self.has(Capability::OpenFiles)
    }

    #[inline]
    pub fn can_close_files(&self) -> bool {
        self.has(Capability::CloseFiles)
    }

    #[inline]
    pub fn can_allocate_memory(&self) -> bool {
        self.has(Capability::AllocateMemory)
    }

    #[inline]
    pub fn can_deallocate_memory(&self) -> bool {
        self.has(Capability::DeallocateMemory)
    }

    #[inline]
    pub fn can_load_modules(&self) -> bool {
        self.has(Capability::LoadModules)
    }

    #[inline]
    pub fn can_use_crypto(&self) -> bool {
        self.has(Capability::UseCrypto)
    }

    #[inline]
    pub fn can_send_ipc(&self) -> bool {
        self.has(Capability::SendIpc)
    }

    #[inline]
    pub fn can_receive_ipc(&self) -> bool {
        self.has(Capability::ReceiveIpc)
    }

    #[inline]
    pub fn can_stat(&self) -> bool {
        self.has(Capability::Stat) || self.can_read() || self.can_open_files()
    }

    #[inline]
    pub fn can_seek(&self) -> bool {
        self.has(Capability::Seek) || self.can_read() || self.can_write()
    }

    #[inline]
    pub fn can_modify_dirs(&self) -> bool {
        self.has(Capability::ModifyDirs) || (self.can_open_files() && self.can_write())
    }

    #[inline]
    pub fn can_unlink(&self) -> bool {
        self.has(Capability::Unlink) || self.can_write()
    }

    #[inline]
    pub fn can_fork(&self) -> bool {
        self.has(Capability::Fork)
    }

    #[inline]
    pub fn can_exec(&self) -> bool {
        self.has(Capability::Exec)
    }

    #[inline]
    pub fn is_admin(&self) -> bool {
        self.has(Capability::Admin)
    }

    #[inline]
    pub fn can_network(&self) -> bool {
        self.has(Capability::Network)
    }

    #[inline]
    pub fn can_raw_io(&self) -> bool {
        self.has(Capability::RawIO)
    }

    #[inline]
    pub fn can_setuid(&self) -> bool {
        self.has(Capability::SetUID) || self.is_admin()
    }

    #[inline]
    pub fn can_setgid(&self) -> bool {
        self.has(Capability::SetGID) || self.is_admin()
    }

    #[inline]
    pub fn can_chroot(&self) -> bool {
        self.has(Capability::Chroot) || self.is_admin()
    }

    #[inline]
    pub fn can_signal(&self) -> bool {
        self.has(Capability::Signal)
    }
}
