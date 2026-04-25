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
use crate::test::framework::TestResult;

pub(crate) fn test_tpm_mmio_base() -> TestResult {
    if TPM_MMIO_BASE != 0xFED4_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_mmio_size() -> TestResult {
    if TPM_MMIO_SIZE != 0x5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_locality_0() -> TestResult {
    if TPM_LOCALITY_0 != TPM_MMIO_BASE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_locality_1() -> TestResult {
    if TPM_LOCALITY_1 != TPM_MMIO_BASE + 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_locality_2() -> TestResult {
    if TPM_LOCALITY_2 != TPM_MMIO_BASE + 0x2000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_locality_3() -> TestResult {
    if TPM_LOCALITY_3 != TPM_MMIO_BASE + 0x3000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_locality_4() -> TestResult {
    if TPM_LOCALITY_4 != TPM_MMIO_BASE + 0x4000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_access() -> TestResult {
    if regs::TPM_ACCESS != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_int_enable() -> TestResult {
    if regs::TPM_INT_ENABLE != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_int_vector() -> TestResult {
    if regs::TPM_INT_VECTOR != 0x0C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_int_status() -> TestResult {
    if regs::TPM_INT_STATUS != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_intf_caps() -> TestResult {
    if regs::TPM_INTF_CAPS != 0x14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_sts() -> TestResult {
    if regs::TPM_STS != 0x18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_data_fifo() -> TestResult {
    if regs::TPM_DATA_FIFO != 0x24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_interface_id() -> TestResult {
    if regs::TPM_INTERFACE_ID != 0x30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_xdata_fifo() -> TestResult {
    if regs::TPM_XDATA_FIFO != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_did_vid() -> TestResult {
    if regs::TPM_DID_VID != 0xF00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_regs_tpm_rid() -> TestResult {
    if regs::TPM_RID != 0xF04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_access_valid() -> TestResult {
    if access::TPM_ACCESS_VALID != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_access_active_locality() -> TestResult {
    if access::TPM_ACCESS_ACTIVE_LOCALITY != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_access_been_seized() -> TestResult {
    if access::TPM_ACCESS_BEEN_SEIZED != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_access_seize() -> TestResult {
    if access::TPM_ACCESS_SEIZE != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_access_pending_request() -> TestResult {
    if access::TPM_ACCESS_PENDING_REQUEST != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_access_request_use() -> TestResult {
    if access::TPM_ACCESS_REQUEST_USE != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_access_establishment() -> TestResult {
    if access::TPM_ACCESS_ESTABLISHMENT != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_family_tpm2() -> TestResult {
    if sts::TPM_STS_FAMILY_TPM2 != 1 << 26 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_reset_establishment() -> TestResult {
    if sts::TPM_STS_RESET_ESTABLISHMENT != 1 << 25 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_command_cancel() -> TestResult {
    if sts::TPM_STS_COMMAND_CANCEL != 1 << 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_valid() -> TestResult {
    if sts::TPM_STS_VALID != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_command_ready() -> TestResult {
    if sts::TPM_STS_COMMAND_READY != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_go() -> TestResult {
    if sts::TPM_STS_GO != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_data_avail() -> TestResult {
    if sts::TPM_STS_DATA_AVAIL != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_data_expect() -> TestResult {
    if sts::TPM_STS_DATA_EXPECT != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_selftest_done() -> TestResult {
    if sts::TPM_STS_SELFTEST_DONE != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sts_response_retry() -> TestResult {
    if sts::TPM_STS_RESPONSE_RETRY != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_startup() -> TestResult {
    if commands::TPM2_CC_STARTUP != 0x0000_0144 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_shutdown() -> TestResult {
    if commands::TPM2_CC_SHUTDOWN != 0x0000_0145 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_self_test() -> TestResult {
    if commands::TPM2_CC_SELF_TEST != 0x0000_0143 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_pcr_extend() -> TestResult {
    if commands::TPM2_CC_PCR_EXTEND != 0x0000_0182 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_pcr_read() -> TestResult {
    if commands::TPM2_CC_PCR_READ != 0x0000_017E {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_pcr_reset() -> TestResult {
    if commands::TPM2_CC_PCR_RESET != 0x0000_013D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_get_random() -> TestResult {
    if commands::TPM2_CC_GET_RANDOM != 0x0000_017B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_get_capability() -> TestResult {
    if commands::TPM2_CC_GET_CAPABILITY != 0x0000_017A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_hash() -> TestResult {
    if commands::TPM2_CC_HASH != 0x0000_017D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_create_primary() -> TestResult {
    if commands::TPM2_CC_CREATE_PRIMARY != 0x0000_0131 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_create() -> TestResult {
    if commands::TPM2_CC_CREATE != 0x0000_0153 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_load() -> TestResult {
    if commands::TPM2_CC_LOAD != 0x0000_0157 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_unseal() -> TestResult {
    if commands::TPM2_CC_UNSEAL != 0x0000_015E {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_quote() -> TestResult {
    if commands::TPM2_CC_QUOTE != 0x0000_0158 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commands_clear() -> TestResult {
    if commands::TPM2_CC_CLEAR != 0x0000_0126 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_sha1() -> TestResult {
    if alg::TPM2_ALG_SHA1 != 0x0004 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_sha256() -> TestResult {
    if alg::TPM2_ALG_SHA256 != 0x000B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_sha384() -> TestResult {
    if alg::TPM2_ALG_SHA384 != 0x000C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_sha512() -> TestResult {
    if alg::TPM2_ALG_SHA512 != 0x000D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_sha3_256() -> TestResult {
    if alg::TPM2_ALG_SHA3_256 != 0x0027 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_sha3_384() -> TestResult {
    if alg::TPM2_ALG_SHA3_384 != 0x0028 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_sha3_512() -> TestResult {
    if alg::TPM2_ALG_SHA3_512 != 0x0029 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_null() -> TestResult {
    if alg::TPM2_ALG_NULL != 0x0010 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_rsa() -> TestResult {
    if alg::TPM2_ALG_RSA != 0x0001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alg_ecc() -> TestResult {
    if alg::TPM2_ALG_ECC != 0x0023 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_startup_clear() -> TestResult {
    if startup::TPM2_SU_CLEAR != 0x0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_startup_state() -> TestResult {
    if startup::TPM2_SU_STATE != 0x0001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bios_start() -> TestResult {
    if PCR_BIOS_START != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bios_end() -> TestResult {
    if PCR_BIOS_END != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_os_start() -> TestResult {
    if PCR_OS_START != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_os_end() -> TestResult {
    if PCR_OS_END != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_debug() -> TestResult {
    if PCR_DEBUG != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_locality_3() -> TestResult {
    if PCR_LOCALITY_3 != 17 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_locality_4() -> TestResult {
    if PCR_LOCALITY_4 != 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_application() -> TestResult {
    if PCR_APPLICATION != 23 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_nonos_bootloader() -> TestResult {
    if PCR_NONOS_BOOTLOADER != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_nonos_bootloader_config() -> TestResult {
    if PCR_NONOS_BOOTLOADER_CONFIG != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_nonos_kernel() -> TestResult {
    if PCR_NONOS_KERNEL != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_nonos_kernel_config() -> TestResult {
    if PCR_NONOS_KERNEL_CONFIG != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_nonos_ima() -> TestResult {
    if PCR_NONOS_IMA != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_nonos_modules() -> TestResult {
    if PCR_NONOS_MODULES != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_st_no_sessions() -> TestResult {
    if TPM_ST_NO_SESSIONS != 0x8001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_st_sessions() -> TestResult {
    if TPM_ST_SESSIONS != 0x8002 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_rs_pw() -> TestResult {
    if TPM_RS_PW != 0x4000_0009 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_rh_endorsement() -> TestResult {
    if TPM_RH_ENDORSEMENT != 0x4000_000B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_locality_request_timeout() -> TestResult {
    if LOCALITY_REQUEST_TIMEOUT_MS != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_ready_timeout() -> TestResult {
    if COMMAND_READY_TIMEOUT_MS != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_response_timeout() -> TestResult {
    if RESPONSE_TIMEOUT_MS != 30000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_buffer_size() -> TestResult {
    if TPM_BUFFER_SIZE != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_max_random_bytes() -> TestResult {
    if TPM_MAX_RANDOM_BYTES != 48 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_max_digest_size() -> TestResult {
    if TPM_MAX_DIGEST_SIZE != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_num_pcrs() -> TestResult {
    if TPM_NUM_PCRS != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ev_nonos_kernel() -> TestResult {
    if EV_NONOS_KERNEL != 0x8000_0001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ev_nonos_module() -> TestResult {
    if EV_NONOS_MODULE != 0x8000_0002 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ev_nonos_config() -> TestResult {
    if EV_NONOS_CONFIG != 0x8000_0003 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_max_commands_per_sec() -> TestResult {
    if TPM_MAX_COMMANDS_PER_SEC != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_max_random_requests_per_sec() -> TestResult {
    if TPM_MAX_RANDOM_REQUESTS_PER_SEC != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_locality_spacing() -> TestResult {
    if TPM_LOCALITY_1 - TPM_LOCALITY_0 != 0x1000 {
        return TestResult::Fail;
    }
    if TPM_LOCALITY_2 - TPM_LOCALITY_1 != 0x1000 {
        return TestResult::Fail;
    }
    if TPM_LOCALITY_3 - TPM_LOCALITY_2 != 0x1000 {
        return TestResult::Fail;
    }
    if TPM_LOCALITY_4 - TPM_LOCALITY_3 != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_ranges_valid() -> TestResult {
    if !(PCR_BIOS_START < PCR_BIOS_END) {
        return TestResult::Fail;
    }
    if !(PCR_OS_START < PCR_OS_END) {
        return TestResult::Fail;
    }
    if !(PCR_BIOS_END < PCR_OS_START) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
