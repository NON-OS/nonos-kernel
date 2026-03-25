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

/// RFC 5280 §7.1 Distinguished Name comparison.
///
/// Fast path: byte-exact equality (covers the common case where both DNs
/// come from the same encoder). Slow path: walk both Name DER structures
/// in parallel and compare PrintableString values case-insensitively with
/// leading/trailing whitespace stripped and internal runs collapsed.

/// Compare two DER-encoded Name values per RFC 5280 §7.1.
pub(crate) fn dn_equal(a: &[u8], b: &[u8]) -> bool {
    // Empty DER is not a valid Name SEQUENCE — reject early
    if a.is_empty() || b.is_empty() {
        return false;
    }
    // Fast path — identical encoding (common case)
    if a == b {
        return true;
    }
    // Slow path — structural comparison with PrintableString normalization
    dn_equal_normalized(a, b)
}

/// Walk two DER-encoded Name (SEQUENCE OF SET OF SEQUENCE { OID, value })
/// structures in parallel, comparing attribute values with RFC 5280 §7.1
/// normalization for PrintableString.
fn dn_equal_normalized(a: &[u8], b: &[u8]) -> bool {
    let a_inner = match unwrap_sequence(a) {
        Some(v) => v,
        None => return false,
    };
    let b_inner = match unwrap_sequence(b) {
        Some(v) => v,
        None => return false,
    };

    let mut ai = 0usize;
    let mut bi = 0usize;

    // Compare RDN SETs one by one
    while ai < a_inner.len() && bi < b_inner.len() {
        // Each RDN is a SET
        let (a_rdn, a_next) = match read_tlv(a_inner, ai) {
            Some(v) => v,
            None => return false,
        };
        let (b_rdn, b_next) = match read_tlv(b_inner, bi) {
            Some(v) => v,
            None => return false,
        };

        if !rdn_equal(a_rdn, b_rdn) {
            return false;
        }

        ai = a_next;
        bi = b_next;
    }

    // Both must be exhausted
    ai >= a_inner.len() && bi >= b_inner.len()
}

/// Compare two RDN SET values (each containing one or more ATV SEQUENCEs).
fn rdn_equal(a: &[u8], b: &[u8]) -> bool {
    // For simplicity, assume single-valued RDNs (which covers >99% of certs).
    // Walk ATVs in order.
    let mut ai = 0usize;
    let mut bi = 0usize;

    while ai < a.len() && bi < b.len() {
        let (a_atv, a_next) = match read_tlv(a, ai) {
            Some(v) => v,
            None => return false,
        };
        let (b_atv, b_next) = match read_tlv(b, bi) {
            Some(v) => v,
            None => return false,
        };

        if !atv_equal(a_atv, b_atv) {
            return false;
        }

        ai = a_next;
        bi = b_next;
    }

    ai >= a.len() && bi >= b.len()
}

/// Compare two AttributeTypeAndValue SEQUENCE values.
/// If the attribute type (OID) matches and both values are PrintableString,
/// compare case-insensitively with whitespace normalization.
fn atv_equal(a: &[u8], b: &[u8]) -> bool {
    // Parse OID from each
    let (a_oid, a_after_oid) = match read_tlv(a, 0) {
        Some(v) => v,
        None => return false,
    };
    let (b_oid, b_after_oid) = match read_tlv(b, 0) {
        Some(v) => v,
        None => return false,
    };

    // OIDs must match exactly
    if a_oid != b_oid {
        return false;
    }

    // Read value tag + content from each
    let a_tag = match a.get(a_after_oid) {
        Some(&t) => t,
        None => return false,
    };
    let b_tag = match b.get(b_after_oid) {
        Some(&t) => t,
        None => return false,
    };

    let (a_val, _) = match read_tlv_raw(a, a_after_oid) {
        Some(v) => v,
        None => return false,
    };
    let (b_val, _) = match read_tlv_raw(b, b_after_oid) {
        Some(v) => v,
        None => return false,
    };

    // Both PrintableString (0x13) → case-insensitive + whitespace normalized
    if a_tag == 0x13 && b_tag == 0x13 {
        return printable_string_equal(a_val, b_val);
    }

    // Otherwise, exact value comparison (tag + length + content)
    a[a_after_oid..] == b[b_after_oid..]
}

/// RFC 5280 §7.1 PrintableString comparison:
/// - Case-insensitive
/// - Strip leading/trailing whitespace
/// - Collapse internal whitespace runs to a single space
fn printable_string_equal(a: &[u8], b: &[u8]) -> bool {
    let a_norm = normalize_printable(a);
    let b_norm = normalize_printable(b);
    a_norm == b_norm
}

fn normalize_printable(s: &[u8]) -> alloc::vec::Vec<u8> {
    let mut result = alloc::vec::Vec::with_capacity(s.len());
    let mut in_space = true; // treat leading spaces as already consumed
    for &b in s {
        if b == b' ' {
            if !in_space {
                result.push(b' ');
                in_space = true;
            }
        } else {
            result.push(b.to_ascii_lowercase());
            in_space = false;
        }
    }
    // Strip trailing space
    if result.last() == Some(&b' ') {
        result.pop();
    }
    result
}

/// Read a TLV at offset, return (value_bytes, offset_after_tlv).
fn read_tlv(data: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    if offset >= data.len() {
        return None;
    }
    let _tag = data[offset];
    let (len, content_start) = read_der_length(data, offset + 1)?;
    let content_end = content_start + len;
    if content_end > data.len() {
        return None;
    }
    Some((&data[content_start..content_end], content_end))
}

/// Read a TLV at offset, return (content_bytes_only, offset_after_tlv).
/// Like read_tlv but skips the tag byte.
fn read_tlv_raw(data: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    read_tlv(data, offset)
}

/// Unwrap a SEQUENCE: return its content bytes, or None if not a SEQUENCE.
fn unwrap_sequence(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }
    let (len, content_start) = read_der_length(data, 1)?;
    let end = content_start + len;
    if end > data.len() {
        return None;
    }
    Some(&data[content_start..end])
}

/// Read a DER length starting at `offset`, return (length_value, offset_after_length).
fn read_der_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset];
    if first & 0x80 == 0 {
        Some((first as usize, offset + 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || offset + 1 + num_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[offset + 1 + i] as usize;
        }
        Some((len, offset + 1 + num_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_dn_equal_identical_bytes() {
        let dn = &[0x30, 0x03, 0x31, 0x01, 0x00];
        assert!(dn_equal(dn, dn));
    }

    #[test]
    fn test_dn_equal_empty_both() {
        let a: &[u8] = &[];
        let b: &[u8] = &[];
        // Empty is not a valid SEQUENCE
        assert!(!dn_equal(a, b));
    }

    #[test]
    fn test_dn_equal_different_bytes_same_meaning() {
        // Build two Name structures with the same CN but different case in PrintableString
        // Name = SEQUENCE { SET { SEQUENCE { OID cn, PrintableString "Test" } } }
        let cn_oid = &[0x55, 0x04, 0x03]; // 2.5.4.3

        // Helper to build a Name with a single CN PrintableString value
        fn build_name(cn_value: &[u8]) -> alloc::vec::Vec<u8> {
            // ATV: SEQUENCE { OID, PrintableString }
            let mut atv = alloc::vec::Vec::new();
            atv.push(0x06); // OID tag
            atv.push(0x03); // OID len
            atv.extend_from_slice(&[0x55, 0x04, 0x03]); // cn OID
            atv.push(0x13); // PrintableString tag
            atv.push(cn_value.len() as u8);
            atv.extend_from_slice(cn_value);

            // Wrap in SEQUENCE
            let mut atv_seq = vec![0x30, atv.len() as u8];
            atv_seq.extend_from_slice(&atv);

            // Wrap in SET
            let mut rdn_set = vec![0x31, atv_seq.len() as u8];
            rdn_set.extend_from_slice(&atv_seq);

            // Wrap in SEQUENCE (Name)
            let mut name = vec![0x30, rdn_set.len() as u8];
            name.extend_from_slice(&rdn_set);

            name
        }

        let name_a = build_name(b"Test CA");
        let name_b = build_name(b"test ca");
        let name_c = build_name(b"  TEST  CA  ");

        assert!(dn_equal(&name_a, &name_b), "case-insensitive match");
        assert!(dn_equal(&name_a, &name_c), "whitespace normalization");
        assert!(dn_equal(&name_b, &name_c), "both normalizations combined");
    }

    #[test]
    fn test_dn_equal_different_values() {
        fn build_name(cn_value: &[u8]) -> alloc::vec::Vec<u8> {
            let mut atv = alloc::vec::Vec::new();
            atv.push(0x06);
            atv.push(0x03);
            atv.extend_from_slice(&[0x55, 0x04, 0x03]);
            atv.push(0x13);
            atv.push(cn_value.len() as u8);
            atv.extend_from_slice(cn_value);
            let mut atv_seq = vec![0x30, atv.len() as u8];
            atv_seq.extend_from_slice(&atv);
            let mut rdn_set = vec![0x31, atv_seq.len() as u8];
            rdn_set.extend_from_slice(&atv_seq);
            let mut name = vec![0x30, rdn_set.len() as u8];
            name.extend_from_slice(&rdn_set);
            name
        }

        let name_a = build_name(b"Root CA One");
        let name_b = build_name(b"Root CA Two");
        assert!(!dn_equal(&name_a, &name_b));
    }

    #[test]
    fn test_dn_equal_utf8string_exact() {
        // UTF8String (0x0C) values must match exactly (no normalization)
        fn build_name_utf8(cn_value: &[u8]) -> alloc::vec::Vec<u8> {
            let mut atv = alloc::vec::Vec::new();
            atv.push(0x06);
            atv.push(0x03);
            atv.extend_from_slice(&[0x55, 0x04, 0x03]);
            atv.push(0x0C); // UTF8String
            atv.push(cn_value.len() as u8);
            atv.extend_from_slice(cn_value);
            let mut atv_seq = vec![0x30, atv.len() as u8];
            atv_seq.extend_from_slice(&atv);
            let mut rdn_set = vec![0x31, atv_seq.len() as u8];
            rdn_set.extend_from_slice(&atv_seq);
            let mut name = vec![0x30, rdn_set.len() as u8];
            name.extend_from_slice(&rdn_set);
            name
        }

        let name_a = build_name_utf8(b"Test CA");
        let name_b = build_name_utf8(b"test ca");
        // Different case in UTF8String → not normalized → not equal
        assert!(!dn_equal(&name_a, &name_b));
    }

    #[test]
    fn test_normalize_printable() {
        assert_eq!(normalize_printable(b"Hello"), b"hello");
        assert_eq!(normalize_printable(b"  Hello  "), b"hello");
        assert_eq!(normalize_printable(b"Hello  World"), b"hello world");
        assert_eq!(normalize_printable(b"  A  B  "), b"a b");
    }
}
