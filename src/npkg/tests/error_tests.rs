use crate::npkg::*;

#[test]
fn test_error_package_not_found_message() {
    let err = NpkgError::PackageNotFound(alloc::string::String::from("missing-pkg"));
    assert_eq!(err.message(), "package not found: missing-pkg");
}

#[test]
fn test_error_version_not_found_message() {
    let err = NpkgError::VersionNotFound(
        alloc::string::String::from("pkg"),
        alloc::string::String::from("2.0.0"),
    );
    assert_eq!(err.message(), "version 2.0.0 not found for pkg");
}

#[test]
fn test_error_dependency_conflict_message() {
    let err = NpkgError::DependencyConflict(
        alloc::string::String::from("pkg-a"),
        alloc::string::String::from("pkg-b"),
    );
    assert_eq!(err.message(), "conflict between pkg-a and pkg-b");
}

#[test]
fn test_error_dependency_missing_message() {
    let err = NpkgError::DependencyMissing(alloc::string::String::from("libfoo"));
    assert_eq!(err.message(), "missing dependency: libfoo");
}

#[test]
fn test_error_circular_dependency_message() {
    let err = NpkgError::CircularDependency(alloc::string::String::from("a -> b -> a"));
    assert_eq!(err.message(), "circular dependency: a -> b -> a");
}

#[test]
fn test_error_checksum_mismatch_message() {
    let err = NpkgError::ChecksumMismatch(alloc::string::String::from("pkg-1.0.0"));
    assert_eq!(err.message(), "checksum mismatch: pkg-1.0.0");
}

#[test]
fn test_error_signature_invalid_message() {
    let err = NpkgError::SignatureInvalid(alloc::string::String::from("pkg"));
    assert_eq!(err.message(), "invalid signature: pkg");
}

#[test]
fn test_error_signature_key_not_found_message() {
    let err = NpkgError::SignatureKeyNotFound;
    assert_eq!(err.message(), "signing key not found");
}

#[test]
fn test_error_download_failed_message() {
    let err = NpkgError::DownloadFailed(alloc::string::String::from("https://example.com/pkg"));
    assert_eq!(err.message(), "download failed: https://example.com/pkg");
}

#[test]
fn test_error_network_unavailable_message() {
    let err = NpkgError::NetworkUnavailable;
    assert_eq!(err.message(), "network unavailable");
}

#[test]
fn test_error_repository_not_found_message() {
    let err = NpkgError::RepositoryNotFound(alloc::string::String::from("main"));
    assert_eq!(err.message(), "repository not found: main");
}

#[test]
fn test_error_repository_sync_failed_message() {
    let err = NpkgError::RepositorySyncFailed(alloc::string::String::from("community"));
    assert_eq!(err.message(), "sync failed: community");
}

#[test]
fn test_error_manifest_parse_error_message() {
    let err = NpkgError::ManifestParseError(alloc::string::String::from("invalid syntax"));
    assert_eq!(err.message(), "manifest error: invalid syntax");
}

#[test]
fn test_error_archive_corrupt_message() {
    let err = NpkgError::ArchiveCorrupt(alloc::string::String::from("pkg.npkg"));
    assert_eq!(err.message(), "corrupt archive: pkg.npkg");
}

#[test]
fn test_error_extraction_failed_message() {
    let err = NpkgError::ExtractionFailed(alloc::string::String::from("write failed"));
    assert_eq!(err.message(), "extraction failed: write failed");
}

#[test]
fn test_error_installation_failed_message() {
    let err = NpkgError::InstallationFailed(alloc::string::String::from("disk full"));
    assert_eq!(err.message(), "installation failed: disk full");
}

#[test]
fn test_error_removal_failed_message() {
    let err = NpkgError::RemovalFailed(alloc::string::String::from("file in use"));
    assert_eq!(err.message(), "removal failed: file in use");
}

#[test]
fn test_error_file_conflict_message() {
    let err = NpkgError::FileConflict(
        alloc::string::String::from("/usr/bin/foo"),
        alloc::string::String::from("other-pkg"),
    );
    assert_eq!(err.message(), "file /usr/bin/foo owned by other-pkg");
}

#[test]
fn test_error_permission_denied_message() {
    let err = NpkgError::PermissionDenied(alloc::string::String::from("/root/secret"));
    assert_eq!(err.message(), "permission denied: /root/secret");
}

#[test]
fn test_error_disk_full_message() {
    let err = NpkgError::DiskFull;
    assert_eq!(err.message(), "disk full");
}

#[test]
fn test_error_database_corrupt_message() {
    let err = NpkgError::DatabaseCorrupt;
    assert_eq!(err.message(), "package database corrupt");
}

#[test]
fn test_error_database_locked_message() {
    let err = NpkgError::DatabaseLocked;
    assert_eq!(err.message(), "package database locked");
}

#[test]
fn test_error_io_error_message() {
    let err = NpkgError::IoError(alloc::string::String::from("read failed"));
    assert_eq!(err.message(), "I/O error: read failed");
}

#[test]
fn test_error_internal_error_message() {
    let err = NpkgError::InternalError(alloc::string::String::from("unexpected state"));
    assert_eq!(err.message(), "internal error: unexpected state");
}

#[test]
fn test_error_invalid_package_name_message() {
    let err = NpkgError::InvalidPackageName(alloc::string::String::from("bad name!"));
    assert_eq!(err.message(), "invalid package name: bad name!");
}

#[test]
fn test_error_invalid_version_message() {
    let err = NpkgError::InvalidVersion(alloc::string::String::from("not.a.version"));
    assert_eq!(err.message(), "invalid version: not.a.version");
}

#[test]
fn test_error_hook_failed_message() {
    let err = NpkgError::HookFailed(alloc::string::String::from("post_install"));
    assert_eq!(err.message(), "hook failed: post_install");
}

#[test]
fn test_error_sandbox_violation_message() {
    let err = NpkgError::SandboxViolation(alloc::string::String::from("access to /root"));
    assert_eq!(err.message(), "sandbox violation: access to /root");
}

#[test]
fn test_error_package_on_hold_message() {
    let err = NpkgError::PackageOnHold(alloc::string::String::from("critical-pkg"));
    assert_eq!(err.message(), "package on hold: critical-pkg");
}

#[test]
fn test_error_already_installed_message() {
    let err = NpkgError::AlreadyInstalled(alloc::string::String::from("pkg-1.0.0"));
    assert_eq!(err.message(), "already installed: pkg-1.0.0");
}

#[test]
fn test_error_not_installed_message() {
    let err = NpkgError::NotInstalled(alloc::string::String::from("missing"));
    assert_eq!(err.message(), "not installed: missing");
}

#[test]
fn test_error_upgrade_not_needed_message() {
    let err = NpkgError::UpgradeNotNeeded(alloc::string::String::from("pkg"));
    assert_eq!(err.message(), "already up to date: pkg");
}

#[test]
fn test_error_is_recoverable_database_corrupt() {
    let err = NpkgError::DatabaseCorrupt;
    assert!(!err.is_recoverable());
}

#[test]
fn test_error_is_recoverable_internal_error() {
    let err = NpkgError::InternalError(alloc::string::String::from("bad"));
    assert!(!err.is_recoverable());
}

#[test]
fn test_error_is_recoverable_network_unavailable() {
    let err = NpkgError::NetworkUnavailable;
    assert!(err.is_recoverable());
}

#[test]
fn test_error_is_recoverable_package_not_found() {
    let err = NpkgError::PackageNotFound(alloc::string::String::from("pkg"));
    assert!(err.is_recoverable());
}

#[test]
fn test_error_is_recoverable_disk_full() {
    let err = NpkgError::DiskFull;
    assert!(err.is_recoverable());
}

#[test]
fn test_error_clone() {
    let err = NpkgError::PackageNotFound(alloc::string::String::from("test"));
    let cloned = err.clone();
    assert_eq!(err.message(), cloned.message());
}

#[test]
fn test_npkg_result_ok() {
    let result: NpkgResult<i32> = Ok(42);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_npkg_result_err() {
    let result: NpkgResult<i32> = Err(NpkgError::DiskFull);
    assert!(result.is_err());
}
