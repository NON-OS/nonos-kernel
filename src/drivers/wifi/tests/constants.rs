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

use crate::drivers::wifi::constants::*;

#[test]
fn test_intel_vendor_id() {
    assert_eq!(INTEL_VENDOR_ID, 0x8086);
}

#[test]
fn test_supported_device_ids_not_empty() {
    assert!(!SUPPORTED_DEVICE_IDS.is_empty());
}

#[test]
fn test_ax210_device_id() {
    assert!(SUPPORTED_DEVICE_IDS.contains(&0x2725));
}

#[test]
fn test_ax200_device_id() {
    assert!(SUPPORTED_DEVICE_IDS.contains(&0x2723));
}

#[test]
fn test_ac8265_device_id() {
    assert!(SUPPORTED_DEVICE_IDS.contains(&0x24F3));
}

#[test]
fn test_wireless_n_device_id() {
    assert!(SUPPORTED_DEVICE_IDS.contains(&0x08B1));
}

#[test]
fn test_csr_hw_if_config() {
    assert_eq!(csr::HW_IF_CONFIG, 0x000);
}

#[test]
fn test_csr_int() {
    assert_eq!(csr::INT, 0x008);
}

#[test]
fn test_csr_int_mask() {
    assert_eq!(csr::INT_MASK, 0x00C);
}

#[test]
fn test_csr_reset() {
    assert_eq!(csr::RESET, 0x020);
}

#[test]
fn test_csr_gp_cntrl() {
    assert_eq!(csr::GP_CNTRL, 0x024);
}

#[test]
fn test_csr_hw_rev() {
    assert_eq!(csr::HW_REV, 0x028);
}

#[test]
fn test_gp_cntrl_mac_access_ena() {
    assert_eq!(csr_bits::GP_CNTRL_MAC_ACCESS_ENA, 0x00000001);
}

#[test]
fn test_gp_cntrl_mac_clock_ready() {
    assert_eq!(csr_bits::GP_CNTRL_MAC_CLOCK_READY, 0x00000002);
}

#[test]
fn test_gp_cntrl_init_done() {
    assert_eq!(csr_bits::GP_CNTRL_INIT_DONE, 0x00000004);
}

#[test]
fn test_gp_cntrl_mac_access_req() {
    assert_eq!(csr_bits::GP_CNTRL_MAC_ACCESS_REQ, 0x00000008);
}

#[test]
fn test_reset_sw_reset() {
    assert_eq!(csr_bits::RESET_REG_FLAG_SW_RESET, 0x00000080);
}

#[test]
fn test_reset_stop_master() {
    assert_eq!(csr_bits::RESET_REG_FLAG_STOP_MASTER, 0x00000200);
}

#[test]
fn test_int_bit_fh_rx() {
    assert_eq!(csr_bits::INT_BIT_FH_RX, 1 << 26);
}

#[test]
fn test_int_bit_hw_err() {
    assert_eq!(csr_bits::INT_BIT_HW_ERR, 1 << 29);
}

#[test]
fn test_int_bit_rf_kill() {
    assert_eq!(csr_bits::INT_BIT_RF_KILL, 1 << 7);
}

#[test]
fn test_int_bit_alive() {
    assert_eq!(csr_bits::INT_BIT_ALIVE, 1 << 0);
}

#[test]
fn test_num_tfd_queues() {
    assert_eq!(NUM_TFD_QUEUES, 31);
}

#[test]
fn test_tfd_queue_size_log() {
    assert_eq!(TFD_QUEUE_SIZE_LOG, 8);
}

#[test]
fn test_tfd_queue_size() {
    assert_eq!(TFD_QUEUE_SIZE, 256);
}

#[test]
fn test_tfd_queue_size_mask() {
    assert_eq!(TFD_QUEUE_SIZE_MASK, 255);
}

#[test]
fn test_rx_queue_size() {
    assert_eq!(RX_QUEUE_SIZE, 256);
}

#[test]
fn test_rx_buffer_size() {
    assert_eq!(RX_BUFFER_SIZE, 4096);
}

#[test]
fn test_tx_buffer_size() {
    assert_eq!(TX_BUFFER_SIZE, 4096);
}

#[test]
fn test_max_cmd_payload_size() {
    assert_eq!(MAX_CMD_PAYLOAD_SIZE, 320);
}

#[test]
fn test_alive_timeout() {
    assert_eq!(ALIVE_TIMEOUT_MS, 2000);
}

#[test]
fn test_init_timeout() {
    assert_eq!(INIT_TIMEOUT_MS, 5000);
}

#[test]
fn test_scan_timeout() {
    assert_eq!(SCAN_TIMEOUT_MS, 10000);
}

#[test]
fn test_connect_timeout() {
    assert_eq!(CONNECT_TIMEOUT_MS, 5000);
}

#[test]
fn test_apm_init_timeout() {
    assert_eq!(APM_INIT_TIMEOUT_US, 25000);
}

#[test]
fn test_nic_access_timeout() {
    assert_eq!(NIC_ACCESS_TIMEOUT_US, 15000);
}

#[test]
fn test_dma_alignment() {
    assert_eq!(DMA_ALIGNMENT, 4096);
}

#[test]
fn test_tfd_alignment() {
    assert_eq!(TFD_ALIGNMENT, 256);
}

#[test]
fn test_rssi_invalid() {
    assert_eq!(RSSI_INVALID, -100);
}

#[test]
fn test_fw_api_version_range() {
    assert!(MIN_FW_API_VERSION < MAX_FW_API_VERSION);
    assert_eq!(MIN_FW_API_VERSION, 22);
    assert_eq!(MAX_FW_API_VERSION, 77);
}

#[test]
fn test_iwl_fw_magic() {
    assert_eq!(IWL_FW_MAGIC, 0x0a4c5749);
}

#[test]
fn test_all_ints_mask() {
    assert_eq!(ALL_INTS_MASK, 0xFFFF_FFFF);
}

#[test]
fn test_int_mask_disabled() {
    assert_eq!(INT_MASK_DISABLED, 0x0000_0000);
}

#[test]
fn test_cmd_mvm_alive() {
    assert_eq!(cmd::MVM_ALIVE, 0x01);
}

#[test]
fn test_cmd_reply_error() {
    assert_eq!(cmd::REPLY_ERROR, 0x02);
}

#[test]
fn test_cmd_tx_cmd() {
    assert_eq!(cmd::TX_CMD, 0x1C);
}

#[test]
fn test_cmd_scan_req_umac() {
    assert_eq!(cmd::SCAN_REQ_UMAC, 0x0D);
}

#[test]
fn test_cmd_add_sta() {
    assert_eq!(cmd::ADD_STA, 0x18);
}

#[test]
fn test_queue_sizes_power_of_two() {
    assert!(TFD_QUEUE_SIZE.is_power_of_two());
    assert!(RX_QUEUE_SIZE.is_power_of_two());
}

#[test]
fn test_buffer_sizes_power_of_two() {
    assert!(RX_BUFFER_SIZE.is_power_of_two());
    assert!(TX_BUFFER_SIZE.is_power_of_two());
}
