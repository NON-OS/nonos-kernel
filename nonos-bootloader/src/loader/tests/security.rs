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

use crate::loader::*;

#[test]
fn test_security_policy_defaults() {
    let default = security::SecurityPolicy::default();
    let strict = security::SecurityPolicy::strict();
    let dev = security::SecurityPolicy::development();

    assert!(default.enforce_wx);
    assert!(strict.enforce_wx);
    assert!(!dev.enforce_wx);

    assert!(strict.require_pie);
    assert!(!default.require_pie);
}

#[test]
fn test_hash_computation() {
    let data = b"test kernel data";
    let hash1 = security::compute_kernel_hash(data);
    let hash2 = security::compute_kernel_hash(data);

    assert_eq!(hash1, hash2);

    let different = b"different data";
    let hash3 = security::compute_kernel_hash(different);
    assert_ne!(hash1, hash3);
}
