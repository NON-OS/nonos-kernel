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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilitySet {
    pub(crate) bits: u64,
}

impl CapabilitySet {
    #[inline]
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    #[inline]
    pub const fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    #[inline]
    pub const fn bits(&self) -> u64 {
        self.bits
    }

    #[inline]
    pub fn insert(&mut self, bit: u8) {
        if bit < 64 {
            self.bits |= 1u64 << bit;
        }
    }

    #[inline]
    pub fn grant(&mut self, cap: Capability) {
        self.insert(cap.bit());
    }

    #[inline]
    pub fn remove(&mut self, bit: u8) {
        if bit < 64 {
            self.bits &= !(1u64 << bit);
        }
    }

    #[inline]
    pub fn revoke(&mut self, cap: Capability) {
        self.remove(cap.bit());
    }

    #[inline]
    pub fn clear(&mut self) {
        self.bits = 0;
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    #[inline]
    pub fn is_superset_of(&self, other: &CapabilitySet) -> bool {
        (self.bits & other.bits) == other.bits
    }

    #[inline]
    pub fn has(&self, cap: Capability) -> bool {
        (self.bits & (1u64 << cap.bit())) != 0
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Capability {
    Exit = 0,
    Read = 1,
    Write = 2,
    OpenFiles = 3,
    CloseFiles = 4,
    AllocateMemory = 5,
    DeallocateMemory = 6,
    LoadModules = 7,
    UseCrypto = 8,
    SendIpc = 9,
    ReceiveIpc = 10,
    Stat = 11,
    Seek = 12,
    ModifyDirs = 13,
    Unlink = 14,
    Fork = 15,
    Exec = 16,
    Admin = 17,
    Network = 18,
    RawIO = 19,
    SetUID = 20,
    SetGID = 21,
    Chroot = 22,
    Signal = 23,
    CoreExec = 24,
    IO = 25,
}

impl Capability {
    #[inline]
    pub const fn bit(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            Capability::Exit => "exit",
            Capability::Read => "read",
            Capability::Write => "write",
            Capability::OpenFiles => "open_files",
            Capability::CloseFiles => "close_files",
            Capability::AllocateMemory => "alloc_mem",
            Capability::DeallocateMemory => "dealloc_mem",
            Capability::LoadModules => "load_modules",
            Capability::UseCrypto => "crypto",
            Capability::SendIpc => "send_ipc",
            Capability::ReceiveIpc => "recv_ipc",
            Capability::Stat => "stat",
            Capability::Seek => "seek",
            Capability::ModifyDirs => "modify_dirs",
            Capability::Unlink => "unlink",
            Capability::Fork => "fork",
            Capability::Exec => "exec",
            Capability::Admin => "admin",
            Capability::Network => "network",
            Capability::RawIO => "raw_io",
            Capability::SetUID => "setuid",
            Capability::SetGID => "setgid",
            Capability::Chroot => "chroot",
            Capability::Signal => "signal",
            Capability::CoreExec => "core_exec",
            Capability::IO => "io",
        }
    }
}
