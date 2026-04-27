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

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub fn read_mounts() -> String {
    let mounts = crate::fs::vfs::get_mounts();
    let mut output = String::new();
    let default_opts = [MountOption::ReadWrite, MountOption::Relatime];
    for mount in mounts {
        let opts = format_mount_options(&default_opts);
        output.push_str(&format!("{} {} tmpfs {} 0 0\n", mount, mount, opts));
    }
    output
}

fn format_mount_options(options: &[MountOption]) -> String {
    if options.is_empty() {
        return String::from("rw");
    }
    let mut opts = Vec::new();
    for opt in options {
        opts.push(opt.to_string());
    }
    opts.join(",")
}

#[derive(Debug, Clone)]
pub enum MountOption {
    ReadWrite,
    ReadOnly,
    NoExec,
    NoSuid,
    NoDev,
    Sync,
    Async,
    Relatime,
    NoAtime,
    Defaults,
}

impl MountOption {
    pub fn to_string(&self) -> &'static str {
        match self {
            Self::ReadWrite => "rw",
            Self::ReadOnly => "ro",
            Self::NoExec => "noexec",
            Self::NoSuid => "nosuid",
            Self::NoDev => "nodev",
            Self::Sync => "sync",
            Self::Async => "async",
            Self::Relatime => "relatime",
            Self::NoAtime => "noatime",
            Self::Defaults => "defaults",
        }
    }
}
