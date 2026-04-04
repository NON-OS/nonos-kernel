use crate::fs::ramfs::*;
use crate::fs::ramfs::error::*;
use crate::fs::ramfs::types::*;

#[test]
fn test_fs_error_not_initialized_errno() {
    assert_eq!(FsError::NotInitialized.to_errno(), -5);
}

#[test]
fn test_fs_error_not_found_errno() {
    assert_eq!(FsError::NotFound.to_errno(), -2);
}

#[test]
fn test_fs_error_already_exists_errno() {
    assert_eq!(FsError::AlreadyExists.to_errno(), -17);
}

#[test]
fn test_fs_error_path_too_long_errno() {
    assert_eq!(FsError::PathTooLong.to_errno(), -36);
}

#[test]
fn test_fs_error_invalid_path_errno() {
    assert_eq!(FsError::InvalidPath.to_errno(), -22);
}

#[test]
fn test_fs_error_file_too_large_errno() {
    assert_eq!(FsError::FileTooLarge.to_errno(), -27);
}

#[test]
fn test_fs_error_too_many_files_errno() {
    assert_eq!(FsError::TooManyFiles.to_errno(), -28);
}

#[test]
fn test_fs_error_no_encryption_key_errno() {
    assert_eq!(FsError::NoEncryptionKey.to_errno(), -5);
}

#[test]
fn test_fs_error_data_too_short_errno() {
    assert_eq!(FsError::DataTooShort.to_errno(), -5);
}

#[test]
fn test_fs_error_decryption_failed_errno() {
    assert_eq!(FsError::DecryptionFailed.to_errno(), -5);
}

#[test]
fn test_fs_error_encryption_failed_errno() {
    assert_eq!(FsError::EncryptionFailed.to_errno(), -5);
}

#[test]
fn test_fs_error_directory_not_found_errno() {
    assert_eq!(FsError::DirectoryNotFound.to_errno(), -2);
}

#[test]
fn test_fs_error_not_a_directory_errno() {
    assert_eq!(FsError::NotADirectory.to_errno(), -20);
}

#[test]
fn test_fs_error_directory_not_empty_errno() {
    assert_eq!(FsError::DirectoryNotEmpty.to_errno(), -39);
}

#[test]
fn test_fs_error_permission_denied_errno() {
    assert_eq!(FsError::PermissionDenied.to_errno(), -13);
}

#[test]
fn test_fs_error_as_str_not_found() {
    assert_eq!(FsError::NotFound.as_str(), "File not found");
}

#[test]
fn test_fs_error_as_str_already_exists() {
    assert_eq!(FsError::AlreadyExists.as_str(), "File already exists");
}

#[test]
fn test_fs_error_as_str_path_too_long() {
    assert_eq!(FsError::PathTooLong.as_str(), "Path too long");
}

#[test]
fn test_fs_error_as_str_invalid_path() {
    assert_eq!(FsError::InvalidPath.as_str(), "Invalid path");
}

#[test]
fn test_fs_error_as_str_file_too_large() {
    assert_eq!(FsError::FileTooLarge.as_str(), "File too large");
}

#[test]
fn test_fs_error_as_bytes() {
    let err = FsError::NotFound;
    assert!(!err.as_bytes().is_empty());
}

#[test]
fn test_fs_error_len() {
    let err = FsError::NotFound;
    assert!(err.len() > 0);
}

#[test]
fn test_fs_error_is_empty() {
    let err = FsError::NotFound;
    assert!(!err.is_empty());
}

#[test]
fn test_fs_error_into_str() {
    let err = FsError::NotFound;
    let s: &'static str = err.into();
    assert_eq!(s, "File not found");
}

#[test]
fn test_fs_constants_nonce_size() {
    assert_eq!(NONCE_SIZE, 12);
}

#[test]
fn test_fs_constants_tag_size() {
    assert_eq!(TAG_SIZE, 16);
}

#[test]
fn test_fs_constants_key_size() {
    assert_eq!(KEY_SIZE, 32);
}

#[test]
fn test_fs_constants_salt_size() {
    assert_eq!(SALT_SIZE, 16);
}

#[test]
fn test_fs_constants_max_file_size() {
    assert_eq!(MAX_FILE_SIZE, 256 * 1024 * 1024);
}

#[test]
fn test_fs_constants_max_path_len() {
    assert_eq!(MAX_PATH_LEN, 4096);
}

#[test]
fn test_fs_constants_max_files() {
    assert_eq!(MAX_FILES, 65536);
}

#[test]
fn test_nonos_file_system_type_variants() {
    assert_eq!(NonosFileSystemType::QuantumSafe as u8, 0);
    assert_eq!(NonosFileSystemType::Encrypted as u8, 1);
    assert_eq!(NonosFileSystemType::Ephemeral as u8, 2);
}

#[test]
fn test_fs_statistics_default() {
    let stats = FsStatistics::default();
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes_stored, 0);
    assert_eq!(stats.reads, 0);
    assert_eq!(stats.writes, 0);
    assert_eq!(stats.deletes, 0);
    assert_eq!(stats.encryptions, 0);
    assert_eq!(stats.decryptions, 0);
    assert_eq!(stats.decryption_failures, 0);
}

#[test]
fn test_fs_statistics_clone() {
    let stats = FsStatistics {
        files: 10,
        bytes_stored: 1024,
        reads: 100,
        writes: 50,
        deletes: 5,
        encryptions: 20,
        decryptions: 15,
        decryption_failures: 1,
    };
    let cloned = stats.clone();
    assert_eq!(cloned.files, 10);
    assert_eq!(cloned.bytes_stored, 1024);
}

#[test]
fn test_dir_entry_file() {
    let entry = DirEntry {
        name: alloc::string::String::from("test.txt"),
        is_dir: false,
        size: 1024,
    };
    assert_eq!(entry.name, "test.txt");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, 1024);
}

#[test]
fn test_dir_entry_directory() {
    let entry = DirEntry {
        name: alloc::string::String::from("subdir"),
        is_dir: true,
        size: 0,
    };
    assert_eq!(entry.name, "subdir");
    assert!(entry.is_dir);
    assert_eq!(entry.size, 0);
}

#[test]
fn test_secure_zeroize() {
    let mut data = [0xFFu8; 32];
    secure_zeroize(&mut data);
    assert!(data.iter().all(|&b| b == 0));
}

#[test]
fn test_secure_zeroize_array() {
    let mut data: [u8; 16] = [0xAA; 16];
    secure_zeroize_array(&mut data);
    assert!(data.iter().all(|&b| b == 0));
}

#[test]
fn test_secure_zeroize_empty() {
    let mut data: [u8; 0] = [];
    secure_zeroize(&mut data);
    assert!(data.is_empty());
}

#[test]
fn test_secure_zeroize_single_byte() {
    let mut data = [0xFF];
    secure_zeroize(&mut data);
    assert_eq!(data[0], 0);
}

#[test]
fn test_normalize_path_absolute() {
    assert_eq!(normalize_path("/a/b/c"), "/a/b/c");
}

#[test]
fn test_normalize_path_double_slash() {
    assert_eq!(normalize_path("/a//b/c"), "/a/b/c");
}

#[test]
fn test_normalize_path_dot() {
    assert_eq!(normalize_path("/a/./b"), "/a/b");
}

#[test]
fn test_normalize_path_dotdot() {
    assert_eq!(normalize_path("/a/b/../c"), "/a/c");
}

#[test]
fn test_normalize_path_relative() {
    assert_eq!(normalize_path("a/b/c"), "a/b/c");
}

#[test]
fn test_normalize_path_empty_result() {
    assert_eq!(normalize_path("/"), "/");
}

#[test]
fn test_nonos_file_info_clone() {
    let info = NonosFileInfo {
        name: alloc::string::String::from("test"),
        size: 512,
        created: 1000,
        modified: 2000,
        encrypted: true,
        quantum_protected: false,
    };
    let cloned = info.clone();
    assert_eq!(cloned.name, "test");
    assert_eq!(cloned.size, 512);
    assert!(cloned.encrypted);
    assert!(!cloned.quantum_protected);
}

#[test]
fn test_nonos_file_clone() {
    let file = NonosFile {
        name: alloc::string::String::from("data.bin"),
        data: alloc::vec![1, 2, 3, 4],
        size: 4,
        created: 100,
        modified: 200,
        encrypted: false,
        quantum_protected: false,
    };
    let cloned = file.clone();
    assert_eq!(cloned.name, "data.bin");
    assert_eq!(cloned.data, &[1, 2, 3, 4]);
    assert_eq!(cloned.size, 4);
}

#[test]
fn test_dir_entry_clone() {
    let entry = DirEntry {
        name: alloc::string::String::from("file.txt"),
        is_dir: false,
        size: 256,
    };
    let cloned = entry.clone();
    assert_eq!(cloned.name, "file.txt");
    assert!(!cloned.is_dir);
}

#[test]
fn test_fs_statistics_with_values() {
    let stats = FsStatistics {
        files: 100,
        bytes_stored: 1024 * 1024,
        reads: 500,
        writes: 200,
        deletes: 50,
        encryptions: 100,
        decryptions: 400,
        decryption_failures: 2,
    };
    assert_eq!(stats.files, 100);
    assert_eq!(stats.bytes_stored, 1024 * 1024);
    assert_eq!(stats.decryption_failures, 2);
}

#[test]
fn test_nonos_file_system_type_equality() {
    assert_eq!(NonosFileSystemType::QuantumSafe, NonosFileSystemType::QuantumSafe);
    assert_ne!(NonosFileSystemType::Encrypted, NonosFileSystemType::Ephemeral);
}

#[test]
fn test_fs_error_io_error() {
    let err = FsError::IoError("custom error");
    assert_eq!(err.to_errno(), -5);
    assert_eq!(err.as_str(), "custom error");
}
