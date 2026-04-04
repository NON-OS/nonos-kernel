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

use crate::capabilities::*;

#[test]
fn test_caps_to_bits_empty() {
    assert_eq!(caps_to_bits(&[]), 0);
}

#[test]
fn test_caps_to_bits_single() {
    assert_eq!(caps_to_bits(&[Capability::CoreExec]), 1);
    assert_eq!(caps_to_bits(&[Capability::IO]), 2);
    assert_eq!(caps_to_bits(&[Capability::Admin]), 512);
}

#[test]
fn test_caps_to_bits_multiple() {
    let caps = [Capability::CoreExec, Capability::IO, Capability::Network];
    assert_eq!(caps_to_bits(&caps), 1 | 2 | 4);
}

#[test]
fn test_caps_to_bits_all() {
    let all = Capability::all();
    let bits = caps_to_bits(&all);
    assert_eq!(bits, 2047);
}

#[test]
fn test_caps_to_bits_duplicates() {
    let caps = [Capability::Admin, Capability::Admin, Capability::Admin];
    assert_eq!(caps_to_bits(&caps), 512);
}

#[test]
fn test_bits_to_caps_zero() {
    let caps = bits_to_caps(0);
    assert!(caps.is_empty());
}

#[test]
fn test_bits_to_caps_single() {
    let caps = bits_to_caps(1);
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0], Capability::CoreExec);
}

#[test]
fn test_bits_to_caps_multiple() {
    let caps = bits_to_caps(1 | 2 | 4);
    assert_eq!(caps.len(), 3);
    assert!(caps.contains(&Capability::CoreExec));
    assert!(caps.contains(&Capability::IO));
    assert!(caps.contains(&Capability::Network));
}

#[test]
fn test_bits_to_caps_all() {
    let caps = bits_to_caps(2047);
    assert_eq!(caps.len(), 11);
}

#[test]
fn test_bits_to_caps_ignores_invalid_bits() {
    let caps = bits_to_caps(1 | (1 << 20));
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0], Capability::CoreExec);
}

#[test]
fn test_roundtrip_caps_to_bits_to_caps() {
    let original = [Capability::Admin, Capability::Crypto, Capability::Memory];
    let bits = caps_to_bits(&original);
    let recovered = bits_to_caps(bits);
    assert_eq!(recovered.len(), 3);
    for cap in &original {
        assert!(recovered.contains(cap));
    }
}

#[test]
fn test_has_capability_true() {
    let bits = caps_to_bits(&[Capability::Admin, Capability::Debug]);
    assert!(has_capability(bits, Capability::Admin));
    assert!(has_capability(bits, Capability::Debug));
}

#[test]
fn test_has_capability_false() {
    let bits = caps_to_bits(&[Capability::Admin]);
    assert!(!has_capability(bits, Capability::Debug));
    assert!(!has_capability(bits, Capability::Network));
}

#[test]
fn test_has_capability_zero_bits() {
    assert!(!has_capability(0, Capability::Admin));
    assert!(!has_capability(0, Capability::CoreExec));
}

#[test]
fn test_add_capability_to_zero() {
    let bits = add_capability(0, Capability::Admin);
    assert_eq!(bits, 512);
}

#[test]
fn test_add_capability_cumulative() {
    let mut bits = 0;
    bits = add_capability(bits, Capability::CoreExec);
    bits = add_capability(bits, Capability::IO);
    bits = add_capability(bits, Capability::Network);
    assert_eq!(bits, 7);
}

#[test]
fn test_add_capability_idempotent() {
    let bits = add_capability(512, Capability::Admin);
    assert_eq!(bits, 512);
}

#[test]
fn test_remove_capability_present() {
    let bits = caps_to_bits(&[Capability::Admin, Capability::Debug]);
    let after = remove_capability(bits, Capability::Admin);
    assert!(!has_capability(after, Capability::Admin));
    assert!(has_capability(after, Capability::Debug));
}

#[test]
fn test_remove_capability_not_present() {
    let bits = caps_to_bits(&[Capability::Admin]);
    let after = remove_capability(bits, Capability::Debug);
    assert_eq!(bits, after);
}

#[test]
fn test_remove_capability_from_zero() {
    let after = remove_capability(0, Capability::Admin);
    assert_eq!(after, 0);
}

#[test]
fn test_remove_all_capabilities() {
    let mut bits = caps_to_bits(&Capability::all());
    for cap in Capability::all() {
        bits = remove_capability(bits, cap);
    }
    assert_eq!(bits, 0);
}

#[test]
fn test_capability_count_zero() {
    assert_eq!(capability_count(0), 0);
}

#[test]
fn test_capability_count_one() {
    assert_eq!(capability_count(1), 1);
    assert_eq!(capability_count(512), 1);
}

#[test]
fn test_capability_count_multiple() {
    let bits = caps_to_bits(&[Capability::Admin, Capability::Debug, Capability::Crypto]);
    assert_eq!(capability_count(bits), 3);
}

#[test]
fn test_capability_count_all() {
    let bits = caps_to_bits(&Capability::all());
    assert_eq!(capability_count(bits), 11);
}

#[test]
fn test_capability_count_ignores_high_bits() {
    let bits = 1 | (1 << 50);
    assert_eq!(capability_count(bits), 2);
}
