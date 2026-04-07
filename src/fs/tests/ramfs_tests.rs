use crate::fs::ramfs::*;
use crate::fs::ramfs::error::*;
use crate::fs::ramfs::types::*;
use crate::test::framework::TestResult;

pub(crate) fn test_fs_error_not_initialized_errno() -> TestResult {
    if FsError::NotInitialized.to_errno() != -5 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_not_found_errno() -> TestResult {
    if FsError::NotFound.to_errno() != -2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_already_exists_errno() -> TestResult {
    if FsError::AlreadyExists.to_errno() != -17 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_path_too_long_errno() -> TestResult {
    if FsError::PathTooLong.to_errno() != -36 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_invalid_path_errno() -> TestResult {
    if FsError::InvalidPath.to_errno() != -22 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_file_too_large_errno() -> TestResult {
    if FsError::FileTooLarge.to_errno() != -27 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_too_many_files_errno() -> TestResult {
    if FsError::TooManyFiles.to_errno() != -28 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_no_encryption_key_errno() -> TestResult {
    if FsError::NoEncryptionKey.to_errno() != -5 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_data_too_short_errno() -> TestResult {
    if FsError::DataTooShort.to_errno() != -5 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_decryption_failed_errno() -> TestResult {
    if FsError::DecryptionFailed.to_errno() != -5 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_encryption_failed_errno() -> TestResult {
    if FsError::EncryptionFailed.to_errno() != -5 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_directory_not_found_errno() -> TestResult {
    if FsError::DirectoryNotFound.to_errno() != -2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_not_a_directory_errno() -> TestResult {
    if FsError::NotADirectory.to_errno() != -20 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_directory_not_empty_errno() -> TestResult {
    if FsError::DirectoryNotEmpty.to_errno() != -39 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_permission_denied_errno() -> TestResult {
    if FsError::PermissionDenied.to_errno() != -13 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_as_str_not_found() -> TestResult {
    if FsError::NotFound.as_str() != "File not found" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_as_str_already_exists() -> TestResult {
    if FsError::AlreadyExists.as_str() != "File already exists" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_as_str_path_too_long() -> TestResult {
    if FsError::PathTooLong.as_str() != "Path too long" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_as_str_invalid_path() -> TestResult {
    if FsError::InvalidPath.as_str() != "Invalid path" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_as_str_file_too_large() -> TestResult {
    if FsError::FileTooLarge.as_str() != "File too large" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_as_bytes() -> TestResult {
    let err = FsError::NotFound;
    if err.as_bytes().is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_len() -> TestResult {
    let err = FsError::NotFound;
    if !(err.len() > 0) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_is_empty() -> TestResult {
    let err = FsError::NotFound;
    if err.is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_into_str() -> TestResult {
    let err = FsError::NotFound;
    let s: &'static str = err.into();
    if s != "File not found" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_constants_nonce_size() -> TestResult {
    if NONCE_SIZE != 12 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_constants_tag_size() -> TestResult {
    if TAG_SIZE != 16 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_constants_key_size() -> TestResult {
    if KEY_SIZE != 32 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_constants_salt_size() -> TestResult {
    if SALT_SIZE != 16 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_constants_max_file_size() -> TestResult {
    if MAX_FILE_SIZE != 256 * 1024 * 1024 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_constants_max_path_len() -> TestResult {
    if MAX_PATH_LEN != 4096 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_constants_max_files() -> TestResult {
    if MAX_FILES != 65536 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_nonos_file_system_type_variants() -> TestResult {
    if NonosFileSystemType::QuantumSafe as u8 != 0 { return TestResult::Fail; }
    if NonosFileSystemType::Encrypted as u8 != 1 { return TestResult::Fail; }
    if NonosFileSystemType::Ephemeral as u8 != 2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_statistics_default() -> TestResult {
    let stats = FsStatistics::default();
    if stats.files != 0 { return TestResult::Fail; }
    if stats.bytes_stored != 0 { return TestResult::Fail; }
    if stats.reads != 0 { return TestResult::Fail; }
    if stats.writes != 0 { return TestResult::Fail; }
    if stats.deletes != 0 { return TestResult::Fail; }
    if stats.encryptions != 0 { return TestResult::Fail; }
    if stats.decryptions != 0 { return TestResult::Fail; }
    if stats.decryption_failures != 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_statistics_clone() -> TestResult {
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
    if cloned.files != 10 { return TestResult::Fail; }
    if cloned.bytes_stored != 1024 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_dir_entry_file() -> TestResult {
    let entry = DirEntry {
        name: alloc::string::String::from("test.txt"),
        is_dir: false,
        size: 1024,
    };
    if entry.name != "test.txt" { return TestResult::Fail; }
    if entry.is_dir { return TestResult::Fail; }
    if entry.size != 1024 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_dir_entry_directory() -> TestResult {
    let entry = DirEntry {
        name: alloc::string::String::from("subdir"),
        is_dir: true,
        size: 0,
    };
    if entry.name != "subdir" { return TestResult::Fail; }
    if !entry.is_dir { return TestResult::Fail; }
    if entry.size != 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_secure_zeroize() -> TestResult {
    let mut data = [0xFFu8; 32];
    secure_zeroize(&mut data);
    if !data.iter().all(|&b| b == 0) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_secure_zeroize_array() -> TestResult {
    let mut data: [u8; 16] = [0xAA; 16];
    secure_zeroize_array(&mut data);
    if !data.iter().all(|&b| b == 0) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_secure_zeroize_empty() -> TestResult {
    let mut data: [u8; 0] = [];
    secure_zeroize(&mut data);
    if !data.is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_secure_zeroize_single_byte() -> TestResult {
    let mut data = [0xFF];
    secure_zeroize(&mut data);
    if data[0] != 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_absolute() -> TestResult {
    if normalize_path("/a/b/c") != "/a/b/c" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_double_slash() -> TestResult {
    if normalize_path("/a//b/c") != "/a/b/c" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_dot() -> TestResult {
    if normalize_path("/a/./b") != "/a/b" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_dotdot() -> TestResult {
    if normalize_path("/a/b/../c") != "/a/c" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_relative() -> TestResult {
    if normalize_path("a/b/c") != "a/b/c" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_empty_result() -> TestResult {
    if normalize_path("/") != "/" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_nonos_file_info_clone() -> TestResult {
    let info = NonosFileInfo {
        name: alloc::string::String::from("test"),
        size: 512,
        created: 1000,
        modified: 2000,
        encrypted: true,
        quantum_protected: false,
        mode: 0o644,
        uid: 0,
        gid: 0,
        inode: 12345,
    };
    let cloned = info.clone();
    if cloned.name != "test" { return TestResult::Fail; }
    if cloned.size != 512 { return TestResult::Fail; }
    if !cloned.encrypted { return TestResult::Fail; }
    if cloned.quantum_protected { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_nonos_file_clone() -> TestResult {
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
    if cloned.name != "data.bin" { return TestResult::Fail; }
    if cloned.data != &[1, 2, 3, 4] { return TestResult::Fail; }
    if cloned.size != 4 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_dir_entry_clone() -> TestResult {
    let entry = DirEntry {
        name: alloc::string::String::from("file.txt"),
        is_dir: false,
        size: 256,
    };
    let cloned = entry.clone();
    if cloned.name != "file.txt" { return TestResult::Fail; }
    if cloned.is_dir { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_statistics_with_values() -> TestResult {
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
    if stats.files != 100 { return TestResult::Fail; }
    if stats.bytes_stored != 1024 * 1024 { return TestResult::Fail; }
    if stats.decryption_failures != 2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_nonos_file_system_type_equality() -> TestResult {
    if NonosFileSystemType::QuantumSafe != NonosFileSystemType::QuantumSafe { return TestResult::Fail; }
    if NonosFileSystemType::Encrypted == NonosFileSystemType::Ephemeral { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_fs_error_io_error() -> TestResult {
    let err = FsError::IoError("custom error");
    if err.to_errno() != -5 { return TestResult::Fail; }
    if err.as_str() != "custom error" { return TestResult::Fail; }
    TestResult::Pass
}
