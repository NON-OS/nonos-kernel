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

pub use super::state_ops::{
    get_boot_tsc, get_error, get_exception_count, get_stage, get_stage_tsc,
    increment_exception_count, is_complete, set_boot_tsc, set_complete, set_error, set_stage,
};
pub use super::state_stats::get_stats;

#[cfg(test)]
mod tests {
    use super::super::error::BootError;
    use super::super::stage::BootStage;
    use super::*;

    #[test]
    fn test_stage_operations() {
        set_stage(BootStage::Entry, 1000);
        assert_eq!(get_stage(), BootStage::Entry);
        assert_eq!(get_stage_tsc(BootStage::Entry), 1000);
    }

    #[test]
    fn test_error_operations() {
        set_error(BootError::NoSse);
        assert_eq!(get_error(), BootError::NoSse);
    }

    #[test]
    fn test_complete_flag() {
        set_complete(false);
        assert!(!is_complete());
        set_complete(true);
        assert!(is_complete());
    }

    #[test]
    fn test_exception_count() {
        let initial = get_exception_count();
        increment_exception_count();
        assert_eq!(get_exception_count(), initial + 1);
    }
}
