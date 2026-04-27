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
use crate::test::framework::TestResult;

pub(crate) fn test_min_ethernet_frame() -> TestResult {
    if MIN_ETHERNET_FRAME != 60 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_mtu() -> TestResult {
    if MAX_MTU != 1500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_ethernet_frame() -> TestResult {
    if MAX_ETHERNET_FRAME != MAX_MTU + 14 {
        return TestResult::Fail;
    }
    if MAX_ETHERNET_FRAME != 1514 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethernet_header_size() -> TestResult {
    if ETHERNET_HEADER_SIZE != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_size_ordering() -> TestResult {
    if !(MAX_ETHERNET_FRAME > MIN_ETHERNET_FRAME) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_desc_chain_len() -> TestResult {
    if MAX_DESC_CHAIN_LEN != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rate_limit_rx_pps() -> TestResult {
    if RATE_LIMIT_RX_PPS != 100_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rate_limit_tx_pps() -> TestResult {
    if RATE_LIMIT_TX_PPS != 50_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rate_limit_burst_rx() -> TestResult {
    if RATE_LIMIT_BURST_RX != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rate_limit_burst_tx() -> TestResult {
    if RATE_LIMIT_BURST_TX != 500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rate_limit_window_ms() -> TestResult {
    if RATE_LIMIT_WINDOW_MS != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_alignment() -> TestResult {
    if DMA_ALIGNMENT != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_dma_region_size() -> TestResult {
    if MAX_DMA_REGION_SIZE != 16 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_vendor_id() -> TestResult {
    if VIRTIO_VENDOR_ID != 0x1AF4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_device_id_transitional() -> TestResult {
    if VIRTIO_NET_DEVICE_ID_TRANSITIONAL != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_device_id_modern() -> TestResult {
    if VIRTIO_NET_DEVICE_ID_MODERN != 0x1041 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_feature_mac() -> TestResult {
    if VIRTIO_NET_F_MAC != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_feature_status() -> TestResult {
    if VIRTIO_NET_F_STATUS != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_feature_ctrl_vq() -> TestResult {
    if VIRTIO_NET_F_CTRL_VQ != 17 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_feature_csum() -> TestResult {
    if VIRTIO_NET_F_CSUM != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_queue_rx() -> TestResult {
    if Q_RX != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_queue_tx() -> TestResult {
    if Q_TX != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_queue_ctrl() -> TestResult {
    if Q_CTRL != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_queue_size() -> TestResult {
    if DEFAULT_QUEUE_SIZE != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ctrl_queue_size() -> TestResult {
    if CTRL_QUEUE_SIZE != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_hdr_f_needs_csum() -> TestResult {
    if VIRTIO_NET_HDR_F_NEEDS_CSUM != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_hdr_f_data_valid() -> TestResult {
    if VIRTIO_NET_HDR_F_DATA_VALID != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_hdr_f_rsc_info() -> TestResult {
    if VIRTIO_NET_HDR_F_RSC_INFO != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_hdr_f_all_valid() -> TestResult {
    if VIRTIO_NET_HDR_F_ALL_VALID
        != (VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID | VIRTIO_NET_HDR_F_RSC_INFO)
    {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_hdr_gso_none() -> TestResult {
    if VIRTIO_NET_HDR_GSO_NONE != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_hdr_gso_tcpv4() -> TestResult {
    if VIRTIO_NET_HDR_GSO_TCPV4 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_hdr_gso_udp() -> TestResult {
    if VIRTIO_NET_HDR_GSO_UDP != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_hdr_gso_tcpv6() -> TestResult {
    if VIRTIO_NET_HDR_GSO_TCPV6 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_net_hdr_gso_ecn() -> TestResult {
    if VIRTIO_NET_HDR_GSO_ECN != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_pci_cap_vendor() -> TestResult {
    if VIRTIO_PCI_CAP_VENDOR != 0x09 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_common_cfg() -> TestResult {
    if CAP_COMMON_CFG != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_notify_cfg() -> TestResult {
    if CAP_NOTIFY_CFG != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_isr_cfg() -> TestResult {
    if CAP_ISR_CFG != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_device_cfg() -> TestResult {
    if CAP_DEVICE_CFG != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_pci_cfg() -> TestResult {
    if CAP_PCI_CFG != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_acknowledge() -> TestResult {
    if VIRTIO_STATUS_ACKNOWLEDGE != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_driver() -> TestResult {
    if VIRTIO_STATUS_DRIVER != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_driver_ok() -> TestResult {
    if VIRTIO_STATUS_DRIVER_OK != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_features_ok() -> TestResult {
    if VIRTIO_STATUS_FEATURES_OK != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_device_needs_reset() -> TestResult {
    if VIRTIO_STATUS_DEVICE_NEEDS_RESET != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_failed() -> TestResult {
    if VIRTIO_STATUS_FAILED != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtq_desc_f_next() -> TestResult {
    if VIRTQ_DESC_F_NEXT != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtq_desc_f_write() -> TestResult {
    if VIRTQ_DESC_F_WRITE != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtq_desc_f_indirect() -> TestResult {
    if VIRTQ_DESC_F_INDIRECT != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_buffer_size() -> TestResult {
    if RX_BUFFER_SIZE != 2048 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_buffer_size() -> TestResult {
    if TX_BUFFER_SIZE != 2048 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_rx_buffer_count() -> TestResult {
    if DEFAULT_RX_BUFFER_COUNT != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_tx_buffer_count() -> TestResult {
    if DEFAULT_TX_BUFFER_COUNT != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_initial_rx_prime_count() -> TestResult {
    if INITIAL_RX_PRIME_COUNT != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_reset_timeout() -> TestResult {
    if DEVICE_RESET_TIMEOUT_MS != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_queue_timeout() -> TestResult {
    if QUEUE_TIMEOUT_MS != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rate_limit_burst_within_limits() -> TestResult {
    if !(RATE_LIMIT_BURST_RX <= RATE_LIMIT_RX_PPS) {
        return TestResult::Fail;
    }
    if !(RATE_LIMIT_BURST_TX <= RATE_LIMIT_TX_PPS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtq_desc_flags_unique() -> TestResult {
    if VIRTQ_DESC_F_NEXT & VIRTQ_DESC_F_WRITE != 0 {
        return TestResult::Fail;
    }
    if VIRTQ_DESC_F_WRITE & VIRTQ_DESC_F_INDIRECT != 0 {
        return TestResult::Fail;
    }
    if VIRTQ_DESC_F_NEXT & VIRTQ_DESC_F_INDIRECT != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
