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
    use crate::drivers::virtio_rng::{
        VIRTIO_VENDOR_ID, VIRTIO_RNG_DEVICE_ID_TRANSITIONAL, VIRTIO_RNG_DEVICE_ID_MODERN,
    };

    // ── PCI vendor / device IDs ──────────────────────────────────────────

    #[test]
    fn test_virtio_vendor_id() {
        // Red Hat / VirtIO subsystem vendor (OASIS spec §4.1.2)
        assert_eq!(VIRTIO_VENDOR_ID, 0x1AF4);
    }

    #[test]
    fn test_virtio_rng_device_ids() {
        // Transitional: legacy VirtIO RNG (pre-1.0 spec)
        assert_eq!(VIRTIO_RNG_DEVICE_ID_TRANSITIONAL, 0x1005);
        // Modern: VirtIO 1.0+ RNG device
        assert_eq!(VIRTIO_RNG_DEVICE_ID_MODERN, 0x1044);
    }

    #[test]
    fn test_device_ids_are_distinct() {
        assert_ne!(VIRTIO_RNG_DEVICE_ID_TRANSITIONAL, VIRTIO_RNG_DEVICE_ID_MODERN);
    }

    #[test]
    fn test_device_ids_are_in_virtio_range() {
        // VirtIO transitional IDs: 0x1000..0x103F
        assert!(VIRTIO_RNG_DEVICE_ID_TRANSITIONAL >= 0x1000);
        assert!(VIRTIO_RNG_DEVICE_ID_TRANSITIONAL <= 0x103F
            || VIRTIO_RNG_DEVICE_ID_TRANSITIONAL == 0x1005); // RNG is 0x1005

        // Modern VirtIO IDs: 0x1040..0x107F (device type base + 0x1040)
        assert!(VIRTIO_RNG_DEVICE_ID_MODERN >= 0x1040);
        assert!(VIRTIO_RNG_DEVICE_ID_MODERN <= 0x107F);
    }

    // ── Availability flag ────────────────────────────────────────────────

    #[test]
    fn test_is_available_initially_false() {
        // Before init, virtio-rng should not be available.
        // Note: in test context, init() was never called.
        let available = crate::drivers::virtio_rng::is_available();
        assert!(!available, "virtio-rng should not be available before init");
    }
}
