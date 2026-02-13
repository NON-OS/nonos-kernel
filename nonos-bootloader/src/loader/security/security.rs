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

pub use super::audit::SecurityAudit;
pub use super::checks::{
    check_address_bounds, check_critical_memory, check_pie_policy, check_size_policy,
    check_wx_policy, compute_kernel_hash, validate_security, verify_kernel_hash,
};
pub use super::policy::{SecurityCheckResult, SecurityPolicy};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::types::{ph_flags, LoadedSegment};

    fn make_segment(addr: u64, size: u64, flags: u32) -> LoadedSegment {
        LoadedSegment {
            file_offset: 0,
            file_size: size,
            mem_size: size,
            target_addr: addr,
            alignment: 0x1000,
            flags,
        }
    }

    #[test]
    fn test_size_policy() {
        let policy = SecurityPolicy::default();

        assert!(check_size_policy(1024, &policy).is_ok());
        assert!(check_size_policy(0, &policy).is_err());
        assert!(check_size_policy(policy.max_kernel_size + 1, &policy).is_err());
    }

    #[test]
    fn test_wx_policy() {
        let strict_policy = SecurityPolicy::strict();
        let dev_policy = SecurityPolicy::development();

        let wx_segment = [Some(make_segment(
            0x200000,
            0x1000,
            ph_flags::PF_R | ph_flags::PF_W | ph_flags::PF_X,
        ))];

        assert!(check_wx_policy(&wx_segment, &strict_policy).is_err());

        let result = check_wx_policy(&wx_segment, &dev_policy).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn test_critical_memory() {
        let bad_segment = [Some(make_segment(0x0, 0x1000, ph_flags::PF_R))];
        assert!(check_critical_memory(&bad_segment).is_err());

        let good_segment = [Some(make_segment(0x100000, 0x1000, ph_flags::PF_R))];
        assert!(check_critical_memory(&good_segment).is_ok());
    }

    #[test]
    fn test_kernel_hash() {
        let data = b"test kernel data";
        let hash = compute_kernel_hash(data);

        assert!(verify_kernel_hash(data, &hash).is_ok());

        let wrong_hash = [0u8; 32];
        assert!(verify_kernel_hash(data, &wrong_hash).is_err());
    }
}
