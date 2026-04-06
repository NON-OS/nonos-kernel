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

use alloc::string::String;
use alloc::vec::Vec;

pub fn read_filesystems() -> String {
    let mut output = String::new();
    for fs in get_registered_filesystems() {
        if fs.requires_device {
            output.push_str(&alloc::format!("\t{}\n", fs.name));
        } else {
            output.push_str(&alloc::format!("nodev\t{}\n", fs.name));
        }
    }
    output
}

#[derive(Debug, Clone)]
pub struct FilesystemType {
    pub name: &'static str,
    pub requires_device: bool,
}

pub fn get_registered_filesystems() -> Vec<FilesystemType> {
    alloc::vec![
        FilesystemType { name: "sysfs", requires_device: false },
        FilesystemType { name: "tmpfs", requires_device: false },
        FilesystemType { name: "proc", requires_device: false },
        FilesystemType { name: "devtmpfs", requires_device: false },
        FilesystemType { name: "devpts", requires_device: false },
        FilesystemType { name: "securityfs", requires_device: false },
        FilesystemType { name: "cgroup", requires_device: false },
        FilesystemType { name: "cgroup2", requires_device: false },
        FilesystemType { name: "pstore", requires_device: false },
        FilesystemType { name: "bpf", requires_device: false },
        FilesystemType { name: "tracefs", requires_device: false },
        FilesystemType { name: "debugfs", requires_device: false },
        FilesystemType { name: "hugetlbfs", requires_device: false },
        FilesystemType { name: "mqueue", requires_device: false },
        FilesystemType { name: "ramfs", requires_device: false },
        FilesystemType { name: "ext4", requires_device: true },
        FilesystemType { name: "vfat", requires_device: true },
        FilesystemType { name: "iso9660", requires_device: true },
    ]
}

pub fn is_filesystem_registered(name: &str) -> bool {
    get_registered_filesystems().iter().any(|fs| fs.name == name)
}
