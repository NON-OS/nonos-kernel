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

//! Hash functions for channel keys and message checksums.

/// Compute channel key from endpoints using BLAKE3
#[inline]
pub fn compute_channel_key(from: &str, to: &str) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(from.as_bytes());
    hasher.update(&[0x00]); // Separator
    hasher.update(to.as_bytes());

    let out = hasher.finalize();
    let bytes = out.as_bytes();

    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Compute message checksum using BLAKE3
#[inline]
pub fn compute_checksum(from: &str, to: &str, data: &[u8], ts_ms: u64) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(from.as_bytes());
    hasher.update(&[0xF0]); // Separator
    hasher.update(to.as_bytes());
    hasher.update(&ts_ms.to_le_bytes());
    hasher.update(data);

    let out = hasher.finalize();
    let b = out.as_bytes();

    // Use bytes from different position than channel key
    u64::from_le_bytes([
        b[24], b[25], b[26], b[27],
        b[28], b[29], b[30], b[31],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_key_deterministic() {
        let key1 = compute_channel_key("alice", "bob");
        let key2 = compute_channel_key("alice", "bob");
        assert_eq!(key1, key2);

        // Different endpoints should give different keys
        let key3 = compute_channel_key("bob", "alice");
        assert_ne!(key1, key3);
    }
}
