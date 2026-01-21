// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub struct SecurityConfig {
    pub max_fork_rate: u32,
    pub validate_paths: bool,
    pub verify_executables: bool,
    pub max_syscall_rate: u32,
    pub audit_enabled: bool,
    pub max_audit_records: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_fork_rate: 100,
            validate_paths: true,
            verify_executables: true,
            max_syscall_rate: 0,
            audit_enabled: true,
            max_audit_records: 1000,
        }
    }
}

pub fn validate_user_pointer(ptr: u64) -> bool {
    if ptr == 0 {
        return false;
    }
    if ptr >= 0xFFFF_8000_0000_0000 {
        return false;
    }
    if ptr > 0x7FFF_FFFF_FFFF && ptr < 0xFFFF_8000_0000_0000 {
        return false;
    }
    true
}

pub fn validate_user_path(path_ptr: u64) -> bool {
    validate_user_pointer(path_ptr)
}
