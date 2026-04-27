use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_error_package_not_found_message() -> TestResult {
    let err = NpkgError::PackageNotFound(alloc::string::String::from("missing-pkg"));
    if err.message() != "package not found: missing-pkg" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_version_not_found_message() -> TestResult {
    let err = NpkgError::VersionNotFound(
        alloc::string::String::from("pkg"),
        alloc::string::String::from("2.0.0"),
    );
    if err.message() != "version 2.0.0 not found for pkg" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_dependency_conflict_message() -> TestResult {
    let err = NpkgError::DependencyConflict(
        alloc::string::String::from("pkg-a"),
        alloc::string::String::from("pkg-b"),
    );
    if err.message() != "conflict between pkg-a and pkg-b" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_dependency_missing_message() -> TestResult {
    let err = NpkgError::DependencyMissing(alloc::string::String::from("libfoo"));
    if err.message() != "missing dependency: libfoo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_circular_dependency_message() -> TestResult {
    let err = NpkgError::CircularDependency(alloc::string::String::from("a -> b -> a"));
    if err.message() != "circular dependency: a -> b -> a" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_checksum_mismatch_message() -> TestResult {
    let err = NpkgError::ChecksumMismatch(alloc::string::String::from("pkg-1.0.0"));
    if err.message() != "checksum mismatch: pkg-1.0.0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_signature_invalid_message() -> TestResult {
    let err = NpkgError::SignatureInvalid(alloc::string::String::from("pkg"));
    if err.message() != "invalid signature: pkg" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_signature_key_not_found_message() -> TestResult {
    let err = NpkgError::SignatureKeyNotFound;
    if err.message() != "signing key not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_download_failed_message() -> TestResult {
    let err = NpkgError::DownloadFailed(alloc::string::String::from("https://example.com/pkg"));
    if err.message() != "download failed: https://example.com/pkg" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_network_unavailable_message() -> TestResult {
    let err = NpkgError::NetworkUnavailable;
    if err.message() != "network unavailable" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_repository_not_found_message() -> TestResult {
    let err = NpkgError::RepositoryNotFound(alloc::string::String::from("main"));
    if err.message() != "repository not found: main" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_repository_sync_failed_message() -> TestResult {
    let err = NpkgError::RepositorySyncFailed(alloc::string::String::from("community"));
    if err.message() != "sync failed: community" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_manifest_parse_error_message() -> TestResult {
    let err = NpkgError::ManifestParseError(alloc::string::String::from("invalid syntax"));
    if err.message() != "manifest error: invalid syntax" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_archive_corrupt_message() -> TestResult {
    let err = NpkgError::ArchiveCorrupt(alloc::string::String::from("pkg.npkg"));
    if err.message() != "corrupt archive: pkg.npkg" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_extraction_failed_message() -> TestResult {
    let err = NpkgError::ExtractionFailed(alloc::string::String::from("write failed"));
    if err.message() != "extraction failed: write failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_installation_failed_message() -> TestResult {
    let err = NpkgError::InstallationFailed(alloc::string::String::from("disk full"));
    if err.message() != "installation failed: disk full" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_removal_failed_message() -> TestResult {
    let err = NpkgError::RemovalFailed(alloc::string::String::from("file in use"));
    if err.message() != "removal failed: file in use" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_file_conflict_message() -> TestResult {
    let err = NpkgError::FileConflict(
        alloc::string::String::from("/usr/bin/foo"),
        alloc::string::String::from("other-pkg"),
    );
    if err.message() != "file /usr/bin/foo owned by other-pkg" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_permission_denied_message() -> TestResult {
    let err = NpkgError::PermissionDenied(alloc::string::String::from("/root/secret"));
    if err.message() != "permission denied: /root/secret" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_disk_full_message() -> TestResult {
    let err = NpkgError::DiskFull;
    if err.message() != "disk full" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_database_corrupt_message() -> TestResult {
    let err = NpkgError::DatabaseCorrupt;
    if err.message() != "package database corrupt" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_database_locked_message() -> TestResult {
    let err = NpkgError::DatabaseLocked;
    if err.message() != "package database locked" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_io_error_message() -> TestResult {
    let err = NpkgError::IoError(alloc::string::String::from("read failed"));
    if err.message() != "I/O error: read failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_internal_error_message() -> TestResult {
    let err = NpkgError::InternalError(alloc::string::String::from("unexpected state"));
    if err.message() != "internal error: unexpected state" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_package_name_message() -> TestResult {
    let err = NpkgError::InvalidPackageName(alloc::string::String::from("bad name!"));
    if err.message() != "invalid package name: bad name!" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_version_message() -> TestResult {
    let err = NpkgError::InvalidVersion(alloc::string::String::from("not.a.version"));
    if err.message() != "invalid version: not.a.version" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_hook_failed_message() -> TestResult {
    let err = NpkgError::HookFailed(alloc::string::String::from("post_install"));
    if err.message() != "hook failed: post_install" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_sandbox_violation_message() -> TestResult {
    let err = NpkgError::SandboxViolation(alloc::string::String::from("access to /root"));
    if err.message() != "sandbox violation: access to /root" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_package_on_hold_message() -> TestResult {
    let err = NpkgError::PackageOnHold(alloc::string::String::from("critical-pkg"));
    if err.message() != "package on hold: critical-pkg" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_already_installed_message() -> TestResult {
    let err = NpkgError::AlreadyInstalled(alloc::string::String::from("pkg-1.0.0"));
    if err.message() != "already installed: pkg-1.0.0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_not_installed_message() -> TestResult {
    let err = NpkgError::NotInstalled(alloc::string::String::from("missing"));
    if err.message() != "not installed: missing" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_upgrade_not_needed_message() -> TestResult {
    let err = NpkgError::UpgradeNotNeeded(alloc::string::String::from("pkg"));
    if err.message() != "already up to date: pkg" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable_database_corrupt() -> TestResult {
    let err = NpkgError::DatabaseCorrupt;
    if err.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable_internal_error() -> TestResult {
    let err = NpkgError::InternalError(alloc::string::String::from("bad"));
    if err.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable_network_unavailable() -> TestResult {
    let err = NpkgError::NetworkUnavailable;
    if !err.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable_package_not_found() -> TestResult {
    let err = NpkgError::PackageNotFound(alloc::string::String::from("pkg"));
    if !err.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_is_recoverable_disk_full() -> TestResult {
    let err = NpkgError::DiskFull;
    if !err.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_clone() -> TestResult {
    let err = NpkgError::PackageNotFound(alloc::string::String::from("test"));
    let cloned = err.clone();
    if err.message() != cloned.message() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_npkg_result_ok() -> TestResult {
    let result: NpkgResult<i32> = Ok(42);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_npkg_result_err() -> TestResult {
    let result: NpkgResult<i32> = Err(NpkgError::DiskFull);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
