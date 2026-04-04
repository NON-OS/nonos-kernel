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

use crate::drivers::tpm::constants::*;

#[test]
fn test_tpm_mmio_base() {
    assert_eq!(TPM_MMIO_BASE, 0xFED4_0000);
}

#[test]
fn test_tpm_mmio_size() {
    assert_eq!(TPM_MMIO_SIZE, 0x5000);
}

#[test]
fn test_tpm_locality_0() {
    assert_eq!(TPM_LOCALITY_0, TPM_MMIO_BASE);
}

#[test]
fn test_tpm_locality_1() {
    assert_eq!(TPM_LOCALITY_1, TPM_MMIO_BASE + 0x1000);
}

#[test]
fn test_tpm_locality_2() {
    assert_eq!(TPM_LOCALITY_2, TPM_MMIO_BASE + 0x2000);
}

#[test]
fn test_tpm_locality_3() {
    assert_eq!(TPM_LOCALITY_3, TPM_MMIO_BASE + 0x3000);
}

#[test]
fn test_tpm_locality_4() {
    assert_eq!(TPM_LOCALITY_4, TPM_MMIO_BASE + 0x4000);
}

#[test]
fn test_regs_tpm_access() {
    assert_eq!(regs::TPM_ACCESS, 0x00);
}

#[test]
fn test_regs_tpm_int_enable() {
    assert_eq!(regs::TPM_INT_ENABLE, 0x08);
}

#[test]
fn test_regs_tpm_int_vector() {
    assert_eq!(regs::TPM_INT_VECTOR, 0x0C);
}

#[test]
fn test_regs_tpm_int_status() {
    assert_eq!(regs::TPM_INT_STATUS, 0x10);
}

#[test]
fn test_regs_tpm_intf_caps() {
    assert_eq!(regs::TPM_INTF_CAPS, 0x14);
}

#[test]
fn test_regs_tpm_sts() {
    assert_eq!(regs::TPM_STS, 0x18);
}

#[test]
fn test_regs_tpm_data_fifo() {
    assert_eq!(regs::TPM_DATA_FIFO, 0x24);
}

#[test]
fn test_regs_tpm_interface_id() {
    assert_eq!(regs::TPM_INTERFACE_ID, 0x30);
}

#[test]
fn test_regs_tpm_xdata_fifo() {
    assert_eq!(regs::TPM_XDATA_FIFO, 0x80);
}

#[test]
fn test_regs_tpm_did_vid() {
    assert_eq!(regs::TPM_DID_VID, 0xF00);
}

#[test]
fn test_regs_tpm_rid() {
    assert_eq!(regs::TPM_RID, 0xF04);
}

#[test]
fn test_access_valid() {
    assert_eq!(access::TPM_ACCESS_VALID, 1 << 7);
}

#[test]
fn test_access_active_locality() {
    assert_eq!(access::TPM_ACCESS_ACTIVE_LOCALITY, 1 << 5);
}

#[test]
fn test_access_been_seized() {
    assert_eq!(access::TPM_ACCESS_BEEN_SEIZED, 1 << 4);
}

#[test]
fn test_access_seize() {
    assert_eq!(access::TPM_ACCESS_SEIZE, 1 << 3);
}

#[test]
fn test_access_pending_request() {
    assert_eq!(access::TPM_ACCESS_PENDING_REQUEST, 1 << 2);
}

#[test]
fn test_access_request_use() {
    assert_eq!(access::TPM_ACCESS_REQUEST_USE, 1 << 1);
}

#[test]
fn test_access_establishment() {
    assert_eq!(access::TPM_ACCESS_ESTABLISHMENT, 1 << 0);
}

#[test]
fn test_sts_family_tpm2() {
    assert_eq!(sts::TPM_STS_FAMILY_TPM2, 1 << 26);
}

#[test]
fn test_sts_reset_establishment() {
    assert_eq!(sts::TPM_STS_RESET_ESTABLISHMENT, 1 << 25);
}

#[test]
fn test_sts_command_cancel() {
    assert_eq!(sts::TPM_STS_COMMAND_CANCEL, 1 << 24);
}

#[test]
fn test_sts_valid() {
    assert_eq!(sts::TPM_STS_VALID, 1 << 7);
}

#[test]
fn test_sts_command_ready() {
    assert_eq!(sts::TPM_STS_COMMAND_READY, 1 << 6);
}

#[test]
fn test_sts_go() {
    assert_eq!(sts::TPM_STS_GO, 1 << 5);
}

#[test]
fn test_sts_data_avail() {
    assert_eq!(sts::TPM_STS_DATA_AVAIL, 1 << 4);
}

#[test]
fn test_sts_data_expect() {
    assert_eq!(sts::TPM_STS_DATA_EXPECT, 1 << 3);
}

#[test]
fn test_sts_selftest_done() {
    assert_eq!(sts::TPM_STS_SELFTEST_DONE, 1 << 2);
}

#[test]
fn test_sts_response_retry() {
    assert_eq!(sts::TPM_STS_RESPONSE_RETRY, 1 << 1);
}

#[test]
fn test_commands_startup() {
    assert_eq!(commands::TPM2_CC_STARTUP, 0x0000_0144);
}

#[test]
fn test_commands_shutdown() {
    assert_eq!(commands::TPM2_CC_SHUTDOWN, 0x0000_0145);
}

#[test]
fn test_commands_self_test() {
    assert_eq!(commands::TPM2_CC_SELF_TEST, 0x0000_0143);
}

#[test]
fn test_commands_pcr_extend() {
    assert_eq!(commands::TPM2_CC_PCR_EXTEND, 0x0000_0182);
}

#[test]
fn test_commands_pcr_read() {
    assert_eq!(commands::TPM2_CC_PCR_READ, 0x0000_017E);
}

#[test]
fn test_commands_pcr_reset() {
    assert_eq!(commands::TPM2_CC_PCR_RESET, 0x0000_013D);
}

#[test]
fn test_commands_get_random() {
    assert_eq!(commands::TPM2_CC_GET_RANDOM, 0x0000_017B);
}

#[test]
fn test_commands_get_capability() {
    assert_eq!(commands::TPM2_CC_GET_CAPABILITY, 0x0000_017A);
}

#[test]
fn test_commands_hash() {
    assert_eq!(commands::TPM2_CC_HASH, 0x0000_017D);
}

#[test]
fn test_commands_create_primary() {
    assert_eq!(commands::TPM2_CC_CREATE_PRIMARY, 0x0000_0131);
}

#[test]
fn test_commands_create() {
    assert_eq!(commands::TPM2_CC_CREATE, 0x0000_0153);
}

#[test]
fn test_commands_load() {
    assert_eq!(commands::TPM2_CC_LOAD, 0x0000_0157);
}

#[test]
fn test_commands_unseal() {
    assert_eq!(commands::TPM2_CC_UNSEAL, 0x0000_015E);
}

#[test]
fn test_commands_quote() {
    assert_eq!(commands::TPM2_CC_QUOTE, 0x0000_0158);
}

#[test]
fn test_commands_clear() {
    assert_eq!(commands::TPM2_CC_CLEAR, 0x0000_0126);
}

#[test]
fn test_alg_sha1() {
    assert_eq!(alg::TPM2_ALG_SHA1, 0x0004);
}

#[test]
fn test_alg_sha256() {
    assert_eq!(alg::TPM2_ALG_SHA256, 0x000B);
}

#[test]
fn test_alg_sha384() {
    assert_eq!(alg::TPM2_ALG_SHA384, 0x000C);
}

#[test]
fn test_alg_sha512() {
    assert_eq!(alg::TPM2_ALG_SHA512, 0x000D);
}

#[test]
fn test_alg_sha3_256() {
    assert_eq!(alg::TPM2_ALG_SHA3_256, 0x0027);
}

#[test]
fn test_alg_sha3_384() {
    assert_eq!(alg::TPM2_ALG_SHA3_384, 0x0028);
}

#[test]
fn test_alg_sha3_512() {
    assert_eq!(alg::TPM2_ALG_SHA3_512, 0x0029);
}

#[test]
fn test_alg_null() {
    assert_eq!(alg::TPM2_ALG_NULL, 0x0010);
}

#[test]
fn test_alg_rsa() {
    assert_eq!(alg::TPM2_ALG_RSA, 0x0001);
}

#[test]
fn test_alg_ecc() {
    assert_eq!(alg::TPM2_ALG_ECC, 0x0023);
}

#[test]
fn test_startup_clear() {
    assert_eq!(startup::TPM2_SU_CLEAR, 0x0000);
}

#[test]
fn test_startup_state() {
    assert_eq!(startup::TPM2_SU_STATE, 0x0001);
}

#[test]
fn test_pcr_bios_start() {
    assert_eq!(PCR_BIOS_START, 0);
}

#[test]
fn test_pcr_bios_end() {
    assert_eq!(PCR_BIOS_END, 7);
}

#[test]
fn test_pcr_os_start() {
    assert_eq!(PCR_OS_START, 8);
}

#[test]
fn test_pcr_os_end() {
    assert_eq!(PCR_OS_END, 15);
}

#[test]
fn test_pcr_debug() {
    assert_eq!(PCR_DEBUG, 16);
}

#[test]
fn test_pcr_locality_3() {
    assert_eq!(PCR_LOCALITY_3, 17);
}

#[test]
fn test_pcr_locality_4() {
    assert_eq!(PCR_LOCALITY_4, 18);
}

#[test]
fn test_pcr_application() {
    assert_eq!(PCR_APPLICATION, 23);
}

#[test]
fn test_pcr_nonos_bootloader() {
    assert_eq!(PCR_NONOS_BOOTLOADER, 4);
}

#[test]
fn test_pcr_nonos_bootloader_config() {
    assert_eq!(PCR_NONOS_BOOTLOADER_CONFIG, 5);
}

#[test]
fn test_pcr_nonos_kernel() {
    assert_eq!(PCR_NONOS_KERNEL, 8);
}

#[test]
fn test_pcr_nonos_kernel_config() {
    assert_eq!(PCR_NONOS_KERNEL_CONFIG, 9);
}

#[test]
fn test_pcr_nonos_ima() {
    assert_eq!(PCR_NONOS_IMA, 10);
}

#[test]
fn test_pcr_nonos_modules() {
    assert_eq!(PCR_NONOS_MODULES, 11);
}

#[test]
fn test_tpm_st_no_sessions() {
    assert_eq!(TPM_ST_NO_SESSIONS, 0x8001);
}

#[test]
fn test_tpm_st_sessions() {
    assert_eq!(TPM_ST_SESSIONS, 0x8002);
}

#[test]
fn test_tpm_rs_pw() {
    assert_eq!(TPM_RS_PW, 0x4000_0009);
}

#[test]
fn test_tpm_rh_endorsement() {
    assert_eq!(TPM_RH_ENDORSEMENT, 0x4000_000B);
}

#[test]
fn test_locality_request_timeout() {
    assert_eq!(LOCALITY_REQUEST_TIMEOUT_MS, 5000);
}

#[test]
fn test_command_ready_timeout() {
    assert_eq!(COMMAND_READY_TIMEOUT_MS, 5000);
}

#[test]
fn test_response_timeout() {
    assert_eq!(RESPONSE_TIMEOUT_MS, 30000);
}

#[test]
fn test_tpm_buffer_size() {
    assert_eq!(TPM_BUFFER_SIZE, 4096);
}

#[test]
fn test_tpm_max_random_bytes() {
    assert_eq!(TPM_MAX_RANDOM_BYTES, 48);
}

#[test]
fn test_tpm_max_digest_size() {
    assert_eq!(TPM_MAX_DIGEST_SIZE, 64);
}

#[test]
fn test_tpm_num_pcrs() {
    assert_eq!(TPM_NUM_PCRS, 24);
}

#[test]
fn test_ev_nonos_kernel() {
    assert_eq!(EV_NONOS_KERNEL, 0x8000_0001);
}

#[test]
fn test_ev_nonos_module() {
    assert_eq!(EV_NONOS_MODULE, 0x8000_0002);
}

#[test]
fn test_ev_nonos_config() {
    assert_eq!(EV_NONOS_CONFIG, 0x8000_0003);
}

#[test]
fn test_tpm_max_commands_per_sec() {
    assert_eq!(TPM_MAX_COMMANDS_PER_SEC, 100);
}

#[test]
fn test_tpm_max_random_requests_per_sec() {
    assert_eq!(TPM_MAX_RANDOM_REQUESTS_PER_SEC, 50);
}

#[test]
fn test_locality_spacing() {
    assert_eq!(TPM_LOCALITY_1 - TPM_LOCALITY_0, 0x1000);
    assert_eq!(TPM_LOCALITY_2 - TPM_LOCALITY_1, 0x1000);
    assert_eq!(TPM_LOCALITY_3 - TPM_LOCALITY_2, 0x1000);
    assert_eq!(TPM_LOCALITY_4 - TPM_LOCALITY_3, 0x1000);
}

#[test]
fn test_pcr_ranges_valid() {
    assert!(PCR_BIOS_START < PCR_BIOS_END);
    assert!(PCR_OS_START < PCR_OS_END);
    assert!(PCR_BIOS_END < PCR_OS_START);
}
