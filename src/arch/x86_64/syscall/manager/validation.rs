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

use core::sync::atomic::Ordering;

use crate::arch::x86_64::syscall::error::SyscallError;
use crate::arch::x86_64::syscall::numbers::*;
use crate::arch::x86_64::syscall::util::read_user_string;
use super::core::SyscallManager;

impl SyscallManager {
    pub(crate) fn validate_syscall(&self, number: u64, args: &[u64; 6]) -> Result<(), SyscallError> {
        let config = self.config.read();

        match number {
            SYS_OPEN | SYS_STAT | SYS_LSTAT | SYS_ACCESS => {
                if config.validate_paths {
                    self.validate_user_path(args[0])?;
                }
            }

            SYS_FORK | SYS_VFORK | SYS_CLONE => {
                if config.max_fork_rate > 0 {
                    self.check_fork_rate(config.max_fork_rate)?;
                }
            }

            SYS_EXECVE => {
                if config.verify_executables {
                    self.validate_user_path(args[0])?;
                    self.verify_executable(args[0])?;
                }
            }

            _ => {}
        }

        Ok(())
    }

    pub(crate) fn validate_user_path(&self, path_ptr: u64) -> Result<(), SyscallError> {
        if path_ptr == 0 {
            return Err(SyscallError::InvalidPath { address: 0 });
        }

        if path_ptr >= 0xFFFF_8000_0000_0000 {
            return Err(SyscallError::InvalidPath { address: path_ptr });
        }

        if path_ptr > 0x7FFF_FFFF_FFFF && path_ptr < 0xFFFF_8000_0000_0000 {
            return Err(SyscallError::InvalidPath { address: path_ptr });
        }

        Ok(())
    }

    pub(crate) fn check_fork_rate(&self, max_rate: u32) -> Result<(), SyscallError> {
        let now = crate::time::now_ns();
        let last_reset = self.fork_reset_time.load(Ordering::Relaxed);

        if now.saturating_sub(last_reset) >= 1_000_000_000 {
            self.fork_counter.store(0, Ordering::Relaxed);
            self.fork_reset_time.store(now, Ordering::Relaxed);
        }

        let count = self.fork_counter.fetch_add(1, Ordering::Relaxed);
        if count >= max_rate {
            return Err(SyscallError::RateLimitExceeded { syscall: SYS_FORK });
        }

        Ok(())
    }

    pub(crate) fn verify_executable(&self, path_ptr: u64) -> Result<(), SyscallError> {
        let path = match read_user_string(path_ptr) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };

        let file_contents = match crate::fs::read_file(&path) {
            Ok(data) => data,
            Err(_) => return Ok(()),
        };

        let actual_hash = crate::crypto::hash::sha3_256(&file_contents);

        if let Some(trusted_hash) = crate::security::nonos_trusted_hashes::get_trusted_hash(&path) {
            if actual_hash != trusted_hash {
                self.stats.security_violations.fetch_add(1, Ordering::Relaxed);
                return Err(SyscallError::SecurityViolation {
                    reason: "Executable integrity check failed - hash mismatch",
                });
            }
        }

        Ok(())
    }
}
