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

#[cfg(test)]
mod utils_tests {
    use crate::fs::utils::*;

    #[test]
    fn test_is_hidden_file() {
        assert!(is_hidden_file(".gitignore"));
        assert!(is_hidden_file("/home/user/.bashrc"));
        assert!(is_hidden_file("/path/to/.hidden"));
        assert!(!is_hidden_file("visible.txt"));
        assert!(!is_hidden_file("/path/to/file.txt"));
    }

    #[test]
    fn test_is_sensitive_file() {
        assert!(is_sensitive_file("/home/.ssh/id_rsa"));
        assert!(is_sensitive_file("/app/secrets.yaml"));
        assert!(is_sensitive_file("/etc/passwd"));
        assert!(is_sensitive_file("/app/.env"));
        assert!(is_sensitive_file("/keys/server.key"));
        assert!(!is_sensitive_file("/var/log/app.log"));
        assert!(!is_sensitive_file("/home/user/document.txt"));
    }

    #[test]
    fn test_file_classification_crypto() {
        let classification = classify_file("/home/.ssh/id_rsa");
        assert_eq!(classification.category, FileCategory::CryptoKey);
        assert_eq!(classification.sensitivity, SensitivityLevel::Critical);
    }

    #[test]
    fn test_file_classification_config() {
        let classification = classify_file("/app/config.json");
        assert_eq!(classification.category, FileCategory::Configuration);
    }

    #[test]
    fn test_file_classification_log() {
        let classification = classify_file("/var/log/app.log");
        assert_eq!(classification.category, FileCategory::Log);
    }

    #[test]
    fn test_scan_config_builder() {
        let config = ScanConfig::new()
            .with_max_depth(10)
            .hidden_only();

        assert_eq!(config.max_depth, 10);
        assert!(config.include_hidden);
    }
}

#[cfg(test)]
mod storage_tests {
    use crate::fs::storage::*;

    #[test]
    fn test_storage_stats_usage_percent() {
        let stats = StorageStats {
            total_bytes: 1000,
            used_bytes: 250,
            available_bytes: 750,
            file_count: 10,
            directory_count: 2,
            block_size: 4096,
            total_blocks: 100,
            used_blocks: 25,
            free_blocks: 75,
        };

        assert!((stats.usage_percent() - 25.0).abs() < 0.01);
        assert!((stats.free_percent() - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_storage_quota_default() {
        let quota = StorageQuota::default();
        assert!(quota.soft_limit < quota.hard_limit);
        assert!(quota.file_limit > 0);
    }

    #[test]
    fn test_inode_stats_usage() {
        let stats = InodeStats {
            total_inodes: 1000,
            used_inodes: 100,
            free_inodes: 900,
            inode_size: 256,
        };

        assert!((stats.usage_percent() - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_storage_issues_detection() {
        let mut issues = StorageIssues::default();
        assert!(!issues.has_issues());
        assert_eq!(issues.issue_count(), 0);

        issues.low_space = true;
        assert!(issues.has_issues());
        assert_eq!(issues.issue_count(), 1);

        issues.low_inodes = true;
        assert_eq!(issues.issue_count(), 2);
    }

    #[test]
    fn test_filesystem_breakdown_totals() {
        let breakdown = FilesystemBreakdown {
            ramfs_bytes: 1000,
            ramfs_files: 10,
            cryptofs_bytes: 500,
            cryptofs_files: 5,
            cache_bytes: 200,
            metadata_bytes: 100,
        };

        assert_eq!(breakdown.total_bytes(), 1800);
        assert_eq!(breakdown.total_files(), 15);
    }
}

#[cfg(test)]
mod path_tests {
    use crate::fs::path::*;

    #[test]
    fn test_normalize_absolute() {
        assert_eq!(normalize_path("/foo/bar"), "/foo/bar");
        assert_eq!(normalize_path("/foo/./bar"), "/foo/bar");
        assert_eq!(normalize_path("/foo/../bar"), "/bar");
        assert_eq!(normalize_path("/foo/bar/.."), "/foo");
        assert_eq!(normalize_path("//foo//bar//"), "/foo/bar");
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_normalize_relative() {
        assert_eq!(normalize_path("foo/bar"), "foo/bar");
        assert_eq!(normalize_path("foo/./bar"), "foo/bar");
        assert_eq!(normalize_path("foo/../bar"), "bar");
        assert_eq!(normalize_path("../foo"), "../foo");
    }

    #[test]
    fn test_is_absolute() {
        assert!(is_absolute("/foo/bar"));
        assert!(is_absolute("/"));
        assert!(!is_absolute("foo/bar"));
        assert!(!is_absolute(""));
    }

    #[test]
    fn test_parent() {
        assert_eq!(parent("/foo/bar"), "/foo");
        assert_eq!(parent("/foo"), "/");
        assert_eq!(parent("/"), "/");
        assert_eq!(parent("foo/bar"), "foo");
        assert_eq!(parent("foo"), ".");
    }

    #[test]
    fn test_file_name() {
        assert_eq!(file_name("/foo/bar.txt"), "bar.txt");
        assert_eq!(file_name("/foo/bar/"), "bar");
        assert_eq!(file_name("/"), "");
        assert_eq!(file_name("foo.txt"), "foo.txt");
    }

    #[test]
    fn test_extension() {
        assert_eq!(extension("foo.txt"), Some("txt"));
        assert_eq!(extension("foo.tar.gz"), Some("gz"));
        assert_eq!(extension("foo"), None);
        assert_eq!(extension(".hidden"), None);
    }

    #[test]
    fn test_join() {
        assert_eq!(join("/foo", "bar"), "/foo/bar");
        assert_eq!(join("/foo/", "bar"), "/foo/bar");
        assert_eq!(join("/foo", "/bar"), "/bar");
        assert_eq!(join("", "bar"), "bar");
    }

    #[test]
    fn test_validate_path_secure() {
        assert!(validate_path_secure("../etc/passwd").is_err());
        assert!(validate_path_secure("/foo/bar").is_ok());
    }
}

#[cfg(test)]
mod cache_tests {
    use crate::fs::cache::*;

    #[test]
    fn test_cache_stats_hit_ratio() {
        let stats = CacheStats {
            hits: 80,
            misses: 20,
            evictions: 5,
            writebacks: 10,
            pages_used: 100,
            dirty_pages: 5,
            bytes_cached: 409600,
        };

        assert!((stats.hit_ratio() - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_cache_stats_zero_total() {
        let stats = CacheStats::default();
        assert!((stats.hit_ratio() - 0.0).abs() < 0.01);
    }
}

#[cfg(test)]
mod vfs_tests {
    use crate::fs::vfs::types::*;

    #[test]
    fn test_open_flags() {
        let flags = OpenFlags::READ | OpenFlags::WRITE;
        assert!(flags.is_readable());
        assert!(flags.is_writable());
        assert!(flags.contains(OpenFlags::READ));
        assert!(flags.contains(OpenFlags::WRITE));
        assert!(!flags.contains(OpenFlags::CREATE));
    }

    #[test]
    fn test_file_metadata_default() {
        let meta = FileMetadata {
            size: 1024,
            atime: 0,
            mtime: 0,
            ctime: 0,
            file_type: FileType::File,
            mode: 0o644,
            inode: 1,
        };

        assert_eq!(meta.size, 1024);
        assert_eq!(meta.mode, 0o644);
    }
}

#[cfg(test)]
mod ramfs_tests {
    use crate::fs::ramfs::error::*;

    #[test]
    fn test_fs_error_errno() {
        assert_eq!(FsError::NotFound.to_errno(), -2);
        assert_eq!(FsError::AlreadyExists.to_errno(), -17);
        assert_eq!(FsError::PathTooLong.to_errno(), -36);
        assert_eq!(FsError::PermissionDenied.to_errno(), -13);
    }

    #[test]
    fn test_fs_error_str() {
        assert_eq!(FsError::NotFound.as_str(), "File not found");
        assert_eq!(FsError::AlreadyExists.as_str(), "File already exists");
    }
}

#[cfg(test)]
mod cryptofs_tests {
    use crate::fs::cryptofs::error::*;

    #[test]
    fn test_crypto_error_errno() {
        assert_eq!(CryptoFsError::NotFound.to_errno(), -2);
        assert_eq!(CryptoFsError::AuthenticationFailed.to_errno(), -5);
    }
}
