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

pub const CLONE_NEWNS: u64 = 0x00020000;
pub const CLONE_NEWUTS: u64 = 0x04000000;
pub const CLONE_NEWIPC: u64 = 0x08000000;
pub const CLONE_NEWUSER: u64 = 0x10000000;
pub const CLONE_NEWPID: u64 = 0x20000000;
pub const CLONE_NEWNET: u64 = 0x40000000;
pub const CLONE_NEWCGROUP: u64 = 0x02000000;

pub const NS_ALL: u64 = CLONE_NEWNS
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWCGROUP;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    Mount,
    Uts,
    Ipc,
    User,
    Pid,
    Net,
    Cgroup,
}

impl NamespaceType {
    pub fn from_flag(flag: u64) -> Option<Self> {
        match flag {
            CLONE_NEWNS => Some(Self::Mount),
            CLONE_NEWUTS => Some(Self::Uts),
            CLONE_NEWIPC => Some(Self::Ipc),
            CLONE_NEWUSER => Some(Self::User),
            CLONE_NEWPID => Some(Self::Pid),
            CLONE_NEWNET => Some(Self::Net),
            CLONE_NEWCGROUP => Some(Self::Cgroup),
            _ => None,
        }
    }

    pub fn to_flag(&self) -> u64 {
        match self {
            Self::Mount => CLONE_NEWNS,
            Self::Uts => CLONE_NEWUTS,
            Self::Ipc => CLONE_NEWIPC,
            Self::User => CLONE_NEWUSER,
            Self::Pid => CLONE_NEWPID,
            Self::Net => CLONE_NEWNET,
            Self::Cgroup => CLONE_NEWCGROUP,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Mount => "mnt",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::User => "user",
            Self::Pid => "pid",
            Self::Net => "net",
            Self::Cgroup => "cgroup",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NamespaceFlags(pub u64);

impl NamespaceFlags {
    pub fn has(&self, ns_type: NamespaceType) -> bool {
        self.0 & ns_type.to_flag() != 0
    }

    pub fn is_valid(&self) -> bool {
        self.0 & !NS_ALL == 0
    }
}
