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

pub const MIN_ETHERNET_FRAME: usize = 60;
pub const MAX_MTU: usize = 1500;
pub const MAX_ETHERNET_FRAME: usize = MAX_MTU + 14;
pub const ETHERNET_HEADER_SIZE: usize = 14;
pub const MAX_PACKET_WITH_HEADER: usize = MAX_ETHERNET_FRAME + core::mem::size_of::<super::header::VirtioNetHeader>();
pub const MAX_DESC_CHAIN_LEN: usize = 16;
pub const RATE_LIMIT_RX_PPS: u64 = 100_000;
pub const RATE_LIMIT_TX_PPS: u64 = 50_000;
pub const RATE_LIMIT_BURST_RX: u64 = 1000;
pub const RATE_LIMIT_BURST_TX: u64 = 500;
pub const RATE_LIMIT_WINDOW_MS: u64 = 1000;
pub const DMA_ALIGNMENT: usize = 64;
pub const MAX_DMA_REGION_SIZE: usize = 16 * 1024 * 1024;
pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_NET_DEVICE_ID_TRANSITIONAL: u16 = 0x1000;
pub const VIRTIO_NET_DEVICE_ID_MODERN: u16 = 0x1041;
pub const VIRTIO_NET_F_MAC: u32 = 5;
pub const VIRTIO_NET_F_STATUS: u32 = 16;
pub const VIRTIO_NET_F_CTRL_VQ: u32 = 17;
pub const VIRTIO_NET_F_CSUM: u32 = 0;
pub const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;
pub const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;
pub const VIRTIO_NET_F_GUEST_UFO: u32 = 10;
pub const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
pub const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
pub const VIRTIO_NET_F_HOST_UFO: u32 = 14;
pub const VIRTIO_NET_F_MQ: u32 = 22;
pub const VIRTIO_NET_F_MTU: u32 = 3;
pub const Q_RX: u16 = 0;
pub const Q_TX: u16 = 1;
pub const Q_CTRL: u16 = 2;
pub const DEFAULT_QUEUE_SIZE: u16 = 256;
pub const CTRL_QUEUE_SIZE: u16 = 64;
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;
pub const VIRTIO_NET_HDR_F_RSC_INFO: u8 = 4;
pub const VIRTIO_NET_HDR_F_ALL_VALID: u8 =
    VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID | VIRTIO_NET_HDR_F_RSC_INFO;
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_UDP: u8 = 3;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;
pub const VIRTIO_PCI_CAP_VENDOR: u8 = 0x09;
pub const CAP_COMMON_CFG: u8 = 1;
pub const CAP_NOTIFY_CFG: u8 = 2;
pub const CAP_ISR_CFG: u8 = 3;
pub const CAP_DEVICE_CFG: u8 = 4;
pub const CAP_PCI_CFG: u8 = 5;
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const VIRTIO_STATUS_FAILED: u8 = 128;
pub const LEG_HOST_FEATURES: usize = 0x00;
pub const LEG_GUEST_FEATURES: usize = 0x04;
pub const LEG_QUEUE_PFN: usize = 0x08;
pub const LEG_QUEUE_NUM: usize = 0x0C;
pub const LEG_QUEUE_SEL: usize = 0x0E;
pub const LEG_NOTIFY: usize = 0x10;
pub const LEG_STATUS: usize = 0x12;
pub const LEG_ISR: usize = 0x13;
pub const LEG_MAC: usize = 0x14;
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;
pub const RX_BUFFER_SIZE: usize = 2048;
pub const TX_BUFFER_SIZE: usize = 2048;
pub const DEFAULT_RX_BUFFER_COUNT: usize = 128;
pub const DEFAULT_TX_BUFFER_COUNT: usize = 64;
pub const INITIAL_RX_PRIME_COUNT: usize = 64;
pub const DEVICE_RESET_TIMEOUT_MS: u64 = 1000;
pub const QUEUE_TIMEOUT_MS: u64 = 5000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_size_constants() {
        assert!(MAX_ETHERNET_FRAME > MIN_ETHERNET_FRAME);
        assert_eq!(MAX_ETHERNET_FRAME, MAX_MTU + 14);
    }

    #[test]
    fn test_rate_limit_constants() {
        assert!(RATE_LIMIT_BURST_RX <= RATE_LIMIT_RX_PPS);
        assert!(RATE_LIMIT_BURST_TX <= RATE_LIMIT_TX_PPS);
    }

    #[test]
    fn test_valid_header_flags() {
        assert_eq!(
            VIRTIO_NET_HDR_F_ALL_VALID,
            VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID | VIRTIO_NET_HDR_F_RSC_INFO
        );
    }
}
