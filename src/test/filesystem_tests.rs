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

use super::framework::{TestCase, TestResult, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Filesystem");

    suite.add(TestCase::new("path_parsing", test_path_parsing, "fs"));
    suite.add(TestCase::new("path_components", test_path_components, "fs"));
    suite.add(TestCase::new("file_descriptor_allocation", test_file_descriptor_allocation, "fs"));
    suite.add(TestCase::new("ramfs_create_file", test_ramfs_create_file, "fs"));
    suite.add(TestCase::new("ramfs_read_write", test_ramfs_read_write, "fs"));
    suite.add(TestCase::new("ramfs_directory_ops", test_ramfs_directory_ops, "fs"));
    suite.add(TestCase::new("vfs_mount_unmount", test_vfs_mount_unmount, "fs"));
    suite.add(TestCase::new("file_permissions", test_file_permissions, "fs"));

    let (_, failed, _) = suite.run_all();
    failed == 0
}

pub(crate) fn test_path_parsing() -> TestResult {
    use crate::fs::path::Path;

    let path = Path::new(b"/home/user/file.txt");
    if !path.is_absolute() {
        return TestResult::Fail;
    }

    let rel = Path::new(b"relative/path");
    if rel.is_absolute() {
        return TestResult::Fail;
    }

    let root = Path::new(b"/");
    if !root.is_root() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_path_components() -> TestResult {
    use crate::fs::path::Path;

    let path = Path::new(b"/home/user/docs");

    let filename = path.file_name();
    if filename != Some(b"docs".as_slice()) {
        return TestResult::Fail;
    }

    let parent = path.parent();
    if parent.is_none() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_file_descriptor_allocation() -> TestResult {
    use crate::fs::fd::{allocate_fd, is_valid_fd, release_fd};

    let fd = allocate_fd();
    if fd < 0 {
        return TestResult::Fail;
    }

    if !is_valid_fd(fd) {
        return TestResult::Fail;
    }

    release_fd(fd);

    TestResult::Pass
}

pub(crate) fn test_ramfs_create_file() -> TestResult {
    use crate::fs::ramfs::{FileType, RamFs};

    let mut fs = RamFs::new();

    let result = fs.create(b"/test.txt", FileType::Regular);
    if result.is_err() {
        return TestResult::Fail;
    }

    let exists = fs.exists(b"/test.txt");
    if !exists {
        return TestResult::Fail;
    }

    let not_exists = fs.exists(b"/nonexistent.txt");
    if not_exists {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_ramfs_read_write() -> TestResult {
    use crate::fs::ramfs::{FileType, RamFs};

    let mut fs = RamFs::new();

    let _ = fs.create(b"/data.bin", FileType::Regular);

    let write_data = b"Hello, NONOS!";
    let written = fs.write(b"/data.bin", write_data, 0);
    if written.is_err() {
        return TestResult::Fail;
    }
    if written.unwrap() != write_data.len() {
        return TestResult::Fail;
    }

    let mut read_buf = [0u8; 64];
    let read = fs.read(b"/data.bin", &mut read_buf, 0);
    if read.is_err() {
        return TestResult::Fail;
    }
    if &read_buf[..write_data.len()] != write_data {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_ramfs_directory_ops() -> TestResult {
    use crate::fs::ramfs::{FileType, RamFs};

    let mut fs = RamFs::new();

    let result = fs.create(b"/mydir", FileType::Directory);
    if result.is_err() {
        return TestResult::Fail;
    }

    let _ = fs.create(b"/mydir/file1.txt", FileType::Regular);
    let _ = fs.create(b"/mydir/file2.txt", FileType::Regular);

    let entries = fs.readdir(b"/mydir");
    if entries.is_err() {
        return TestResult::Fail;
    }
    if entries.unwrap().len() < 2 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_vfs_mount_unmount() -> TestResult {
    use crate::fs::vfs::{is_mounted, mount, unmount};

    let mount_point = b"/mnt/test";

    if is_mounted(mount_point) {
        return TestResult::Fail;
    }

    let result = mount(mount_point, b"ramfs", 0);
    if result.is_err() {
        return TestResult::Skip;
    }

    if !is_mounted(mount_point) {
        return TestResult::Fail;
    }

    let _ = unmount(mount_point);

    TestResult::Pass
}

pub(crate) fn test_file_permissions() -> TestResult {
    use crate::fs::types::{FileMode, Permission};

    let mode = FileMode::new(Permission::ReadWrite, Permission::Read, Permission::None);

    if !mode.owner_can_read() {
        return TestResult::Fail;
    }
    if !mode.owner_can_write() {
        return TestResult::Fail;
    }
    if mode.owner_can_execute() {
        return TestResult::Fail;
    }

    if !mode.group_can_read() {
        return TestResult::Fail;
    }
    if mode.group_can_write() {
        return TestResult::Fail;
    }

    if mode.other_can_read() {
        return TestResult::Fail;
    }

    TestResult::Pass
}
