// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::npkg::extract::types::{
    ArchiveEntry, NPKG_MAGIC, NPKG_VERSION, ENTRY_FILE, ENTRY_DIR, ENTRY_SYMLINK,
};
use alloc::string::String;

#[test]
fn test_npkg_magic_constant() {
    assert_eq!(NPKG_MAGIC, 0x4E504B47);
}

#[test]
fn test_npkg_magic_is_npkg_ascii() {
    let bytes = NPKG_MAGIC.to_le_bytes();
    assert_eq!(bytes[0], b'G');
    assert_eq!(bytes[1], b'K');
    assert_eq!(bytes[2], b'P');
    assert_eq!(bytes[3], b'N');
}

#[test]
fn test_npkg_version_constant() {
    assert_eq!(NPKG_VERSION, 1);
}

#[test]
fn test_entry_file_constant() {
    assert_eq!(ENTRY_FILE, 0);
}

#[test]
fn test_entry_dir_constant() {
    assert_eq!(ENTRY_DIR, 1);
}

#[test]
fn test_entry_symlink_constant() {
    assert_eq!(ENTRY_SYMLINK, 2);
}

#[test]
fn test_entry_types_unique() {
    assert_ne!(ENTRY_FILE, ENTRY_DIR);
    assert_ne!(ENTRY_FILE, ENTRY_SYMLINK);
    assert_ne!(ENTRY_DIR, ENTRY_SYMLINK);
}

#[test]
fn test_archive_entry_file() {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/app"),
        entry_type: ENTRY_FILE,
        size: 4096,
        mode: 0o755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.entry_type, ENTRY_FILE);
    assert!(entry.link_target.is_none());
}

#[test]
fn test_archive_entry_dir() {
    let entry = ArchiveEntry {
        path: String::from("/usr/share/app"),
        entry_type: ENTRY_DIR,
        size: 0,
        mode: 0o755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.entry_type, ENTRY_DIR);
    assert_eq!(entry.size, 0);
}

#[test]
fn test_archive_entry_symlink() {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/link"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("/usr/bin/target")),
    };
    assert_eq!(entry.entry_type, ENTRY_SYMLINK);
    assert!(entry.link_target.is_some());
    assert_eq!(entry.link_target.unwrap(), "/usr/bin/target");
}

#[test]
fn test_archive_entry_path() {
    let entry = ArchiveEntry {
        path: String::from("/etc/config.conf"),
        entry_type: ENTRY_FILE,
        size: 256,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 100,
        link_target: None,
    };
    assert_eq!(entry.path, "/etc/config.conf");
}

#[test]
fn test_archive_entry_size() {
    let entry = ArchiveEntry {
        path: String::from("test"),
        entry_type: ENTRY_FILE,
        size: 1_000_000,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.size, 1_000_000);
}

#[test]
fn test_archive_entry_large_size() {
    let entry = ArchiveEntry {
        path: String::from("large"),
        entry_type: ENTRY_FILE,
        size: u64::MAX,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.size, u64::MAX);
}

#[test]
fn test_archive_entry_mode_executable() {
    let entry = ArchiveEntry {
        path: String::from("bin"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.mode, 0o755);
    assert!((entry.mode & 0o111) != 0);
}

#[test]
fn test_archive_entry_mode_readonly() {
    let entry = ArchiveEntry {
        path: String::from("data"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o444,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.mode, 0o444);
    assert!((entry.mode & 0o222) == 0);
}

#[test]
fn test_archive_entry_checksum() {
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
    assert_eq!(entry.checksum, [0xABu8; 32]);
}

#[test]
fn test_archive_entry_checksum_unique() {
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
    assert_eq!(entry.checksum[0], 0);
    assert_eq!(entry.checksum[31], 31);
}

#[test]
fn test_archive_entry_data_offset() {
    let entry = ArchiveEntry {
        path: String::from("file"),
        entry_type: ENTRY_FILE,
        size: 1024,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 4096,
        link_target: None,
    };
    assert_eq!(entry.data_offset, 4096);
}

#[test]
fn test_archive_entry_data_offset_large() {
    let entry = ArchiveEntry {
        path: String::from("file"),
        entry_type: ENTRY_FILE,
        size: 1024,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: u64::MAX,
        link_target: None,
    };
    assert_eq!(entry.data_offset, u64::MAX);
}

#[test]
fn test_archive_entry_clone() {
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
    assert_eq!(entry.path, cloned.path);
    assert_eq!(entry.entry_type, cloned.entry_type);
    assert_eq!(entry.size, cloned.size);
    assert_eq!(entry.mode, cloned.mode);
    assert_eq!(entry.checksum, cloned.checksum);
    assert_eq!(entry.data_offset, cloned.data_offset);
}

#[test]
fn test_archive_entry_clone_with_symlink() {
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
    assert_eq!(entry.link_target, cloned.link_target);
}

#[test]
fn test_archive_entry_debug() {
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
    assert!(debug_str.contains("ArchiveEntry"));
    assert!(debug_str.contains("test"));
}

#[test]
fn test_archive_entry_empty_path() {
    let entry = ArchiveEntry {
        path: String::new(),
        entry_type: ENTRY_FILE,
        size: 0,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert!(entry.path.is_empty());
}

#[test]
fn test_archive_entry_deep_path() {
    let entry = ArchiveEntry {
        path: String::from("/very/deep/nested/directory/structure/file.txt"),
        entry_type: ENTRY_FILE,
        size: 10,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert!(entry.path.contains("nested"));
}

#[test]
fn test_archive_entry_unicode_path() {
    let entry = ArchiveEntry {
        path: String::from("/usr/share/文档/readme.txt"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert!(entry.path.contains("文档"));
}

#[test]
fn test_archive_entry_zero_size_file() {
    let entry = ArchiveEntry {
        path: String::from("/empty"),
        entry_type: ENTRY_FILE,
        size: 0,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.size, 0);
    assert_eq!(entry.entry_type, ENTRY_FILE);
}

#[test]
fn test_archive_entry_mode_all_permissions() {
    let entry = ArchiveEntry {
        path: String::from("/test"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.mode & 0o777, 0o777);
}

#[test]
fn test_archive_entry_mode_no_permissions() {
    let entry = ArchiveEntry {
        path: String::from("/test"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o000,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.mode & 0o777, 0o000);
}

#[test]
fn test_archive_entry_setuid_mode() {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/sudo"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o4755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert!((entry.mode & 0o4000) != 0);
}

#[test]
fn test_archive_entry_setgid_mode() {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/wall"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o2755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert!((entry.mode & 0o2000) != 0);
}

#[test]
fn test_archive_entry_sticky_bit() {
    let entry = ArchiveEntry {
        path: String::from("/tmp"),
        entry_type: ENTRY_DIR,
        size: 0,
        mode: 0o1777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert!((entry.mode & 0o1000) != 0);
}

#[test]
fn test_archive_entry_relative_symlink() {
    let entry = ArchiveEntry {
        path: String::from("/usr/lib/libfoo.so"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("libfoo.so.1")),
    };
    assert!(!entry.link_target.as_ref().unwrap().starts_with('/'));
}

#[test]
fn test_archive_entry_absolute_symlink() {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/python"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("/usr/bin/python3")),
    };
    assert!(entry.link_target.as_ref().unwrap().starts_with('/'));
}

#[test]
fn test_archive_entry_empty_symlink_target() {
    let entry = ArchiveEntry {
        path: String::from("/link"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::new()),
    };
    assert!(entry.link_target.as_ref().unwrap().is_empty());
}

#[test]
fn test_entry_type_is_file() {
    let entry = ArchiveEntry {
        path: String::from("test"),
        entry_type: ENTRY_FILE,
        size: 100,
        mode: 0o644,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.entry_type, ENTRY_FILE);
    assert_ne!(entry.entry_type, ENTRY_DIR);
    assert_ne!(entry.entry_type, ENTRY_SYMLINK);
}

#[test]
fn test_entry_type_is_dir() {
    let entry = ArchiveEntry {
        path: String::from("testdir"),
        entry_type: ENTRY_DIR,
        size: 0,
        mode: 0o755,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert_eq!(entry.entry_type, ENTRY_DIR);
    assert_ne!(entry.entry_type, ENTRY_FILE);
    assert_ne!(entry.entry_type, ENTRY_SYMLINK);
}

#[test]
fn test_entry_type_is_symlink() {
    let entry = ArchiveEntry {
        path: String::from("testlink"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("target")),
    };
    assert_eq!(entry.entry_type, ENTRY_SYMLINK);
    assert_ne!(entry.entry_type, ENTRY_FILE);
    assert_ne!(entry.entry_type, ENTRY_DIR);
}

#[test]
fn test_archive_entry_typical_binary() {
    let entry = ArchiveEntry {
        path: String::from("/usr/bin/myapp"),
        entry_type: ENTRY_FILE,
        size: 1_048_576,
        mode: 0o755,
        checksum: [0x42u8; 32],
        data_offset: 8192,
        link_target: None,
    };
    assert_eq!(entry.path, "/usr/bin/myapp");
    assert_eq!(entry.size, 1_048_576);
    assert_eq!(entry.mode, 0o755);
}

#[test]
fn test_archive_entry_typical_config() {
    let entry = ArchiveEntry {
        path: String::from("/etc/myapp/config.toml"),
        entry_type: ENTRY_FILE,
        size: 1024,
        mode: 0o644,
        checksum: [0xFFu8; 32],
        data_offset: 0,
        link_target: None,
    };
    assert!(entry.path.contains("config"));
    assert_eq!(entry.mode, 0o644);
}

#[test]
fn test_archive_entry_typical_library() {
    let entry = ArchiveEntry {
        path: String::from("/usr/lib/libmylib.so.1.0.0"),
        entry_type: ENTRY_FILE,
        size: 524288,
        mode: 0o755,
        checksum: [0x11u8; 32],
        data_offset: 1024,
        link_target: None,
    };
    assert!(entry.path.contains("lib"));
    assert!(entry.path.contains(".so"));
}

#[test]
fn test_archive_entry_library_symlink() {
    let entry = ArchiveEntry {
        path: String::from("/usr/lib/libmylib.so"),
        entry_type: ENTRY_SYMLINK,
        size: 0,
        mode: 0o777,
        checksum: [0u8; 32],
        data_offset: 0,
        link_target: Some(String::from("libmylib.so.1.0.0")),
    };
    assert_eq!(entry.entry_type, ENTRY_SYMLINK);
    assert!(entry.link_target.as_ref().unwrap().contains("1.0.0"));
}

#[test]
fn test_npkg_magic_nonzero() {
    assert_ne!(NPKG_MAGIC, 0);
}

#[test]
fn test_npkg_version_positive() {
    assert!(NPKG_VERSION > 0);
}

#[test]
fn test_entry_constants_fit_in_u8() {
    assert!(ENTRY_FILE <= u8::MAX);
    assert!(ENTRY_DIR <= u8::MAX);
    assert!(ENTRY_SYMLINK <= u8::MAX);
}

