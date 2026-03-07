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
mod tests {
    use crate::drivers::virtio_rng;

    // ── is_available() ───────────────────────────────────────────────────

    #[test]
    fn test_is_available_before_init() {
        // In the test harness, init() is never called, so the device
        // should not report as available.
        assert!(!virtio_rng::is_available());
    }

    // ── get_random_bytes() without init ──────────────────────────────────

    #[test]
    fn test_get_random_bytes_fails_before_init() {
        let mut buf = [0u8; 32];
        let result = virtio_rng::get_random_bytes(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "virtio-rng not available");
    }

    #[test]
    fn test_get_random_bytes_empty_buf_fails_before_init() {
        let mut buf = [0u8; 0];
        // Even an empty buffer should fail — device not available
        let result = virtio_rng::get_random_bytes(&mut buf);
        assert!(result.is_err());
    }

    // ── fill_random() without init ───────────────────────────────────────

    #[test]
    fn test_fill_random_empty_buf_ok() {
        // Empty buffer is a no-op — should succeed even without device
        let mut buf = [0u8; 0];
        let result = virtio_rng::fill_random(&mut buf);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fill_random_fails_before_init() {
        let mut buf = [0u8; 32];
        let result = virtio_rng::fill_random(&mut buf);
        assert!(result.is_err());
    }
}
