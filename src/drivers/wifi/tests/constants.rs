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
use crate::test::framework::TestResult;

pub(crate) fn test_intel_vendor_id() -> TestResult {
    if INTEL_VENDOR_ID != 0x8086 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_device_ids_not_empty() -> TestResult {
    if SUPPORTED_DEVICE_IDS.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ax210_device_id() -> TestResult {
    if !SUPPORTED_DEVICE_IDS.contains(&0x2725) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ax200_device_id() -> TestResult {
    if !SUPPORTED_DEVICE_IDS.contains(&0x2723) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ac8265_device_id() -> TestResult {
    if !SUPPORTED_DEVICE_IDS.contains(&0x24F3) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_wireless_n_device_id() -> TestResult {
    if !SUPPORTED_DEVICE_IDS.contains(&0x08B1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_csr_hw_if_config() -> TestResult {
    if csr::HW_IF_CONFIG != 0x000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_csr_int() -> TestResult {
    if csr::INT != 0x008 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_csr_int_mask() -> TestResult {
    if csr::INT_MASK != 0x00C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_csr_reset() -> TestResult {
    if csr::RESET != 0x020 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_csr_gp_cntrl() -> TestResult {
    if csr::GP_CNTRL != 0x024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_csr_hw_rev() -> TestResult {
    if csr::HW_REV != 0x028 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gp_cntrl_mac_access_ena() -> TestResult {
    if csr_bits::GP_CNTRL_MAC_ACCESS_ENA != 0x00000001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gp_cntrl_mac_clock_ready() -> TestResult {
    if csr_bits::GP_CNTRL_MAC_CLOCK_READY != 0x00000002 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gp_cntrl_init_done() -> TestResult {
    if csr_bits::GP_CNTRL_INIT_DONE != 0x00000004 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gp_cntrl_mac_access_req() -> TestResult {
    if csr_bits::GP_CNTRL_MAC_ACCESS_REQ != 0x00000008 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reset_sw_reset() -> TestResult {
    if csr_bits::RESET_REG_FLAG_SW_RESET != 0x00000080 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reset_stop_master() -> TestResult {
    if csr_bits::RESET_REG_FLAG_STOP_MASTER != 0x00000200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_bit_fh_rx() -> TestResult {
    if csr_bits::INT_BIT_FH_RX != 1 << 26 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_bit_hw_err() -> TestResult {
    if csr_bits::INT_BIT_HW_ERR != 1 << 29 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_bit_rf_kill() -> TestResult {
    if csr_bits::INT_BIT_RF_KILL != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_bit_alive() -> TestResult {
    if csr_bits::INT_BIT_ALIVE != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_num_tfd_queues() -> TestResult {
    if NUM_TFD_QUEUES != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tfd_queue_size_log() -> TestResult {
    if TFD_QUEUE_SIZE_LOG != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tfd_queue_size() -> TestResult {
    if TFD_QUEUE_SIZE != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tfd_queue_size_mask() -> TestResult {
    if TFD_QUEUE_SIZE_MASK != 255 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_queue_size() -> TestResult {
    if RX_QUEUE_SIZE != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_buffer_size() -> TestResult {
    if RX_BUFFER_SIZE != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_buffer_size() -> TestResult {
    if TX_BUFFER_SIZE != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_cmd_payload_size() -> TestResult {
    if MAX_CMD_PAYLOAD_SIZE != 320 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alive_timeout() -> TestResult {
    if ALIVE_TIMEOUT_MS != 2000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_init_timeout() -> TestResult {
    if INIT_TIMEOUT_MS != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_timeout() -> TestResult {
    if SCAN_TIMEOUT_MS != 10000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_connect_timeout() -> TestResult {
    if CONNECT_TIMEOUT_MS != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apm_init_timeout() -> TestResult {
    if APM_INIT_TIMEOUT_US != 25000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nic_access_timeout() -> TestResult {
    if NIC_ACCESS_TIMEOUT_US != 15000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_alignment() -> TestResult {
    if DMA_ALIGNMENT != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tfd_alignment() -> TestResult {
    if TFD_ALIGNMENT != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rssi_invalid() -> TestResult {
    if RSSI_INVALID != -100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fw_api_version_range() -> TestResult {
    if !(MIN_FW_API_VERSION < MAX_FW_API_VERSION) {
        return TestResult::Fail;
    }
    if MIN_FW_API_VERSION != 22 {
        return TestResult::Fail;
    }
    if MAX_FW_API_VERSION != 77 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_iwl_fw_magic() -> TestResult {
    if IWL_FW_MAGIC != 0x0a4c5749 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_ints_mask() -> TestResult {
    if ALL_INTS_MASK != 0xFFFF_FFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_mask_disabled() -> TestResult {
    if INT_MASK_DISABLED != 0x0000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_mvm_alive() -> TestResult {
    if cmd::MVM_ALIVE != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_reply_error() -> TestResult {
    if cmd::REPLY_ERROR != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_tx_cmd() -> TestResult {
    if cmd::TX_CMD != 0x1C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_scan_req_umac() -> TestResult {
    if cmd::SCAN_REQ_UMAC != 0x0D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_add_sta() -> TestResult {
    if cmd::ADD_STA != 0x18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_queue_sizes_power_of_two() -> TestResult {
    if !TFD_QUEUE_SIZE.is_power_of_two() {
        return TestResult::Fail;
    }
    if !RX_QUEUE_SIZE.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_sizes_power_of_two() -> TestResult {
    if !RX_BUFFER_SIZE.is_power_of_two() {
        return TestResult::Fail;
    }
    if !TX_BUFFER_SIZE.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
