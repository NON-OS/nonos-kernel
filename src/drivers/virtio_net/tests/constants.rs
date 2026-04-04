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

use crate::drivers::virtio_net::constants::*;

#[test]
fn test_min_ethernet_frame() {
    assert_eq!(MIN_ETHERNET_FRAME, 60);
}

#[test]
fn test_max_mtu() {
    assert_eq!(MAX_MTU, 1500);
}

#[test]
fn test_max_ethernet_frame() {
    assert_eq!(MAX_ETHERNET_FRAME, MAX_MTU + 14);
    assert_eq!(MAX_ETHERNET_FRAME, 1514);
}

#[test]
fn test_ethernet_header_size() {
    assert_eq!(ETHERNET_HEADER_SIZE, 14);
}

#[test]
fn test_frame_size_ordering() {
    assert!(MAX_ETHERNET_FRAME > MIN_ETHERNET_FRAME);
}

#[test]
fn test_max_desc_chain_len() {
    assert_eq!(MAX_DESC_CHAIN_LEN, 16);
}

#[test]
fn test_rate_limit_rx_pps() {
    assert_eq!(RATE_LIMIT_RX_PPS, 100_000);
}

#[test]
fn test_rate_limit_tx_pps() {
    assert_eq!(RATE_LIMIT_TX_PPS, 50_000);
}

#[test]
fn test_rate_limit_burst_rx() {
    assert_eq!(RATE_LIMIT_BURST_RX, 1000);
}

#[test]
fn test_rate_limit_burst_tx() {
    assert_eq!(RATE_LIMIT_BURST_TX, 500);
}

#[test]
fn test_rate_limit_window_ms() {
    assert_eq!(RATE_LIMIT_WINDOW_MS, 1000);
}

#[test]
fn test_dma_alignment() {
    assert_eq!(DMA_ALIGNMENT, 64);
}

#[test]
fn test_max_dma_region_size() {
    assert_eq!(MAX_DMA_REGION_SIZE, 16 * 1024 * 1024);
}

#[test]
fn test_virtio_vendor_id() {
    assert_eq!(VIRTIO_VENDOR_ID, 0x1AF4);
}

#[test]
fn test_virtio_net_device_id_transitional() {
    assert_eq!(VIRTIO_NET_DEVICE_ID_TRANSITIONAL, 0x1000);
}

#[test]
fn test_virtio_net_device_id_modern() {
    assert_eq!(VIRTIO_NET_DEVICE_ID_MODERN, 0x1041);
}

#[test]
fn test_virtio_net_feature_mac() {
    assert_eq!(VIRTIO_NET_F_MAC, 5);
}

#[test]
fn test_virtio_net_feature_status() {
    assert_eq!(VIRTIO_NET_F_STATUS, 16);
}

#[test]
fn test_virtio_net_feature_ctrl_vq() {
    assert_eq!(VIRTIO_NET_F_CTRL_VQ, 17);
}

#[test]
fn test_virtio_net_feature_csum() {
    assert_eq!(VIRTIO_NET_F_CSUM, 0);
}

#[test]
fn test_queue_rx() {
    assert_eq!(Q_RX, 0);
}

#[test]
fn test_queue_tx() {
    assert_eq!(Q_TX, 1);
}

#[test]
fn test_queue_ctrl() {
    assert_eq!(Q_CTRL, 2);
}

#[test]
fn test_default_queue_size() {
    assert_eq!(DEFAULT_QUEUE_SIZE, 256);
}

#[test]
fn test_ctrl_queue_size() {
    assert_eq!(CTRL_QUEUE_SIZE, 64);
}

#[test]
fn test_virtio_net_hdr_f_needs_csum() {
    assert_eq!(VIRTIO_NET_HDR_F_NEEDS_CSUM, 1);
}

#[test]
fn test_virtio_net_hdr_f_data_valid() {
    assert_eq!(VIRTIO_NET_HDR_F_DATA_VALID, 2);
}

#[test]
fn test_virtio_net_hdr_f_rsc_info() {
    assert_eq!(VIRTIO_NET_HDR_F_RSC_INFO, 4);
}

#[test]
fn test_virtio_net_hdr_f_all_valid() {
    assert_eq!(
        VIRTIO_NET_HDR_F_ALL_VALID,
        VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID | VIRTIO_NET_HDR_F_RSC_INFO
    );
}

#[test]
fn test_virtio_net_hdr_gso_none() {
    assert_eq!(VIRTIO_NET_HDR_GSO_NONE, 0);
}

#[test]
fn test_virtio_net_hdr_gso_tcpv4() {
    assert_eq!(VIRTIO_NET_HDR_GSO_TCPV4, 1);
}

#[test]
fn test_virtio_net_hdr_gso_udp() {
    assert_eq!(VIRTIO_NET_HDR_GSO_UDP, 3);
}

#[test]
fn test_virtio_net_hdr_gso_tcpv6() {
    assert_eq!(VIRTIO_NET_HDR_GSO_TCPV6, 4);
}

#[test]
fn test_virtio_net_hdr_gso_ecn() {
    assert_eq!(VIRTIO_NET_HDR_GSO_ECN, 0x80);
}

#[test]
fn test_virtio_pci_cap_vendor() {
    assert_eq!(VIRTIO_PCI_CAP_VENDOR, 0x09);
}

#[test]
fn test_cap_common_cfg() {
    assert_eq!(CAP_COMMON_CFG, 1);
}

#[test]
fn test_cap_notify_cfg() {
    assert_eq!(CAP_NOTIFY_CFG, 2);
}

#[test]
fn test_cap_isr_cfg() {
    assert_eq!(CAP_ISR_CFG, 3);
}

#[test]
fn test_cap_device_cfg() {
    assert_eq!(CAP_DEVICE_CFG, 4);
}

#[test]
fn test_cap_pci_cfg() {
    assert_eq!(CAP_PCI_CFG, 5);
}

#[test]
fn test_virtio_status_acknowledge() {
    assert_eq!(VIRTIO_STATUS_ACKNOWLEDGE, 1);
}

#[test]
fn test_virtio_status_driver() {
    assert_eq!(VIRTIO_STATUS_DRIVER, 2);
}

#[test]
fn test_virtio_status_driver_ok() {
    assert_eq!(VIRTIO_STATUS_DRIVER_OK, 4);
}

#[test]
fn test_virtio_status_features_ok() {
    assert_eq!(VIRTIO_STATUS_FEATURES_OK, 8);
}

#[test]
fn test_virtio_status_device_needs_reset() {
    assert_eq!(VIRTIO_STATUS_DEVICE_NEEDS_RESET, 64);
}

#[test]
fn test_virtio_status_failed() {
    assert_eq!(VIRTIO_STATUS_FAILED, 128);
}

#[test]
fn test_virtq_desc_f_next() {
    assert_eq!(VIRTQ_DESC_F_NEXT, 1);
}

#[test]
fn test_virtq_desc_f_write() {
    assert_eq!(VIRTQ_DESC_F_WRITE, 2);
}

#[test]
fn test_virtq_desc_f_indirect() {
    assert_eq!(VIRTQ_DESC_F_INDIRECT, 4);
}

#[test]
fn test_rx_buffer_size() {
    assert_eq!(RX_BUFFER_SIZE, 2048);
}

#[test]
fn test_tx_buffer_size() {
    assert_eq!(TX_BUFFER_SIZE, 2048);
}

#[test]
fn test_default_rx_buffer_count() {
    assert_eq!(DEFAULT_RX_BUFFER_COUNT, 128);
}

#[test]
fn test_default_tx_buffer_count() {
    assert_eq!(DEFAULT_TX_BUFFER_COUNT, 64);
}

#[test]
fn test_initial_rx_prime_count() {
    assert_eq!(INITIAL_RX_PRIME_COUNT, 64);
}

#[test]
fn test_device_reset_timeout() {
    assert_eq!(DEVICE_RESET_TIMEOUT_MS, 1000);
}

#[test]
fn test_queue_timeout() {
    assert_eq!(QUEUE_TIMEOUT_MS, 5000);
}

#[test]
fn test_rate_limit_burst_within_limits() {
    assert!(RATE_LIMIT_BURST_RX <= RATE_LIMIT_RX_PPS);
    assert!(RATE_LIMIT_BURST_TX <= RATE_LIMIT_TX_PPS);
}

#[test]
fn test_virtq_desc_flags_unique() {
    assert_eq!(VIRTQ_DESC_F_NEXT & VIRTQ_DESC_F_WRITE, 0);
    assert_eq!(VIRTQ_DESC_F_WRITE & VIRTQ_DESC_F_INDIRECT, 0);
    assert_eq!(VIRTQ_DESC_F_NEXT & VIRTQ_DESC_F_INDIRECT, 0);
}
