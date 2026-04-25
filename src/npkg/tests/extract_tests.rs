// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::npkg::extract::types::{
    ArchiveEntry, ENTRY_DIR, ENTRY_FILE, ENTRY_SYMLINK, NPKG_MAGIC, NPKG_VERSION,
};
use crate::test::framework::TestResult;
use alloc::string::String;

pub(crate) fn test_npkg_magic_constant() -> TestResult {
    if NPKG_MAGIC != 0x4E504B47 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_npkg_magic_is_npkg_ascii() -> TestResult {
    let bytes = NPKG_MAGIC.to_le_bytes();
    if bytes[0] != b'G' {
        return TestResult::Fail;
    }
    if bytes[1] != b'K' {
        return TestResult::Fail;
    }
    if bytes[2] != b'P' {
        return TestResult::Fail;
    }
    if bytes[3] != b'N' {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_npkg_version_constant() -> TestResult {
    if NPKG_VERSION != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_file_constant() -> TestResult {
    if ENTRY_FILE != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_dir_constant() -> TestResult {
    if ENTRY_DIR != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_symlink_constant() -> TestResult {
    if ENTRY_SYMLINK != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_types_unique() -> TestResult {
    if ENTRY_FILE == ENTRY_DIR {
        return TestResult::Fail;
    }
    if ENTRY_FILE == ENTRY_SYMLINK {
        return TestResult::Fail;
    }
    if ENTRY_DIR == ENTRY_SYMLINK {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_file() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/app"),
        entry_type: ENTRY_FILE,
        size: 4096,
        mode: 0o755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.entry_type != ENTRY_FILE {
        return TestResult::Fail;
    }
    if entry.link_target.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_dir() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/share/app"),
        entry_type: ENTRY_DIR,
        size: 0,
        mode: 0o755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.entry_type != ENTRY_DIR {
        return TestResult::Fail;
    }
    if entry.size != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_symlink() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/link"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("/usr/bin/target")),
    };
    if entry.entry_type != ENTRY_SYMLINK {
        return TestResult::Fail;
    }
    if entry.link_target.is_none() {
        return TestResult::Fail;
    }
    if entry.link_target.unwrap() != "/usr/bin/target" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_path() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/etc/config.conf"),
        entry_type: ENTRY_FILE,
        size: 256,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 100,
        link_target: None,
    };
    if entry.path != "/etc/config.conf" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_size() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("test"),
        entry_type: ENTRY_FILE,
        size: 1_000_000,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.size != 1_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_large_size() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("large"),
        entry_type: ENTRY_FILE,
        size: u64::MAX,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.size != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_mode_executable() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("bin"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.mode != 0o755 {
        return TestResult::Fail;
    }
    if (entry.mode & 0o111) == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_mode_readonly() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("data"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o444,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.mode != 0o444 {
        return TestResult::Fail;
    }
    if (entry.mode & 0o222) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_checksum() -> TestResult {
    let checksum = [0xABu8; 32];
    let entry = ArchiveEntry {
        path: String::from("file"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o644,
        checksum,
        data_offset: 0,
        link_target: None,
    };
    if entry.checksum != [0xABu8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_checksum_unique() -> TestResult {
    let mut checksum = [0u8; 32];
    for i in 0..32 {
        checksum[i] = i as u8;
    }
    let entry = ArchiveEntry {
        path: String::from("file"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o644,
        checksum,
        data_offset: 0,
        link_target: None,
    };
    if entry.checksum[0] != 0 {
        return TestResult::Fail;
    }
    if entry.checksum[31] != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_data_offset() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("file"),
        entry_type: ENTRY_FILE,
        size: 1024,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 4096,
        link_target: None,
    };
    if entry.data_offset != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_data_offset_large() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("file"),
        entry_type: ENTRY_FILE,
        size: 1024,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: u64::MAX,
        link_target: None,
    };
    if entry.data_offset != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_clone() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/test"),
        entry_type: ENTRY_FILE,
        size: 512,
        mode: 0o755,
        checksum: [1u8; 32],
        data_offset: 100,
        link_target: None,
    };
    let cloned = entry.clone();
    if entry.path != cloned.path {
        return TestResult::Fail;
    }
    if entry.entry_type != cloned.entry_type {
        return TestResult::Fail;
    }
    if entry.size != cloned.size {
        return TestResult::Fail;
    }
    if entry.mode != cloned.mode {
        return TestResult::Fail;
    }
    if entry.checksum != cloned.checksum {
        return TestResult::Fail;
    }
    if entry.data_offset != cloned.data_offset {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_clone_with_symlink() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/link"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("/usr/bin/target")),
    };
    let cloned = entry.clone();
    if entry.link_target != cloned.link_target {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_debug() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("test"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    let debug_str = alloc::format!("{:?}", entry);
    if !debug_str.contains("ArchiveEntry") {
        return TestResult::Fail;
    }
    if !debug_str.contains("test") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_empty_path() -> TestResult {
    let entry = ArchiveEntry {
        path: String::new(),
        entry_type: ENTRY_FILE,
        size: 0,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if !entry.path.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_deep_path() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/very/deep/nested/directory/structure/file.txt"),
        entry_type: ENTRY_FILE,
        size: 10,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if !entry.path.contains("nested") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_unicode_path() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/share/文档/readme.txt"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if !entry.path.contains("文档") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_zero_size_file() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/empty"),
        entry_type: ENTRY_FILE,
        size: 0,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.size != 0 {
        return TestResult::Fail;
    }
    if entry.entry_type != ENTRY_FILE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_mode_all_permissions() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/test"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.mode & 0o777 != 0o777 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_mode_no_permissions() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/test"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o000,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.mode & 0o777 != 0o000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_setuid_mode() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/sudo"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o4755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if (entry.mode & 0o4000) == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_setgid_mode() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/wall"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o2755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if (entry.mode & 0o2000) == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_sticky_bit() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/tmp"),
        entry_type: ENTRY_DIR,
        size: 0,
        mode: 0o1777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if (entry.mode & 0o1000) == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_relative_symlink() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/lib/libfoo.so"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("libfoo.so.1")),
    };
    if entry.link_target.as_ref().unwrap().starts_with('/') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_absolute_symlink() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/python"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("/usr/bin/python3")),
    };
    if !entry.link_target.as_ref().unwrap().starts_with('/') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_empty_symlink_target() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/link"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::new()),
    };
    if !entry.link_target.as_ref().unwrap().is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_type_is_file() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("test"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.entry_type != ENTRY_FILE {
        return TestResult::Fail;
    }
    if entry.entry_type == ENTRY_DIR {
        return TestResult::Fail;
    }
    if entry.entry_type == ENTRY_SYMLINK {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_type_is_dir() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("testdir"),
        entry_type: ENTRY_DIR,
        size: 0,
        mode: 0o755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    if entry.entry_type != ENTRY_DIR {
        return TestResult::Fail;
    }
    if entry.entry_type == ENTRY_FILE {
        return TestResult::Fail;
    }
    if entry.entry_type == ENTRY_SYMLINK {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_type_is_symlink() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("testlink"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("target")),
    };
    if entry.entry_type != ENTRY_SYMLINK {
        return TestResult::Fail;
    }
    if entry.entry_type == ENTRY_FILE {
        return TestResult::Fail;
    }
    if entry.entry_type == ENTRY_DIR {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_typical_binary() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/myapp"),
        entry_type: ENTRY_FILE,
        size: 1_048_576,
        mode: 0o755,
        checksum: [0x42u8; 32],
        data_offset: 8192,
        link_target: None,
    };
    if entry.path != "/usr/bin/myapp" {
        return TestResult::Fail;
    }
    if entry.size != 1_048_576 {
        return TestResult::Fail;
    }
    if entry.mode != 0o755 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_typical_config() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/etc/myapp/config.toml"),
        entry_type: ENTRY_FILE,
        size: 1024,
        mode: 0o644,
        checksum: [0xFFu8; 32],
        data_offset: 0,
        link_target: None,
    };
    if !entry.path.contains("config") {
        return TestResult::Fail;
    }
    if entry.mode != 0o644 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_typical_library() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/lib/libmylib.so.1.0.0"),
        entry_type: ENTRY_FILE,
        size: 524288,
        mode: 0o755,
        checksum: [0x11u8; 32],
        data_offset: 1024,
        link_target: None,
    };
    if !entry.path.contains("lib") {
        return TestResult::Fail;
    }
    if !entry.path.contains(".so") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_archive_entry_library_symlink() -> TestResult {
    let entry = ArchiveEntry {
        path: String::from("/usr/lib/libmylib.so"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("libmylib.so.1.0.0")),
    };
    if entry.entry_type != ENTRY_SYMLINK {
        return TestResult::Fail;
    }
    if !entry.link_target.as_ref().unwrap().contains("1.0.0") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_npkg_magic_nonzero() -> TestResult {
    if NPKG_MAGIC == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_npkg_version_positive() -> TestResult {
    if NPKG_VERSION <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_constants_fit_in_u8() -> TestResult {
    if ENTRY_FILE > u8::MAX {
        return TestResult::Fail;
    }
    if ENTRY_DIR > u8::MAX {
        return TestResult::Fail;
    }
    if ENTRY_SYMLINK > u8::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}
