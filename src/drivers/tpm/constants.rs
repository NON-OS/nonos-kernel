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

//! TPM 2.0 constants.

pub const TPM_MMIO_BASE: u64 = 0xFED4_0000;
pub const TPM_MMIO_SIZE: usize = 0x5000;
pub const TPM_LOCALITY_0: u64 = TPM_MMIO_BASE;
pub const TPM_LOCALITY_1: u64 = TPM_MMIO_BASE + 0x1000;
pub const TPM_LOCALITY_2: u64 = TPM_MMIO_BASE + 0x2000;
pub const TPM_LOCALITY_3: u64 = TPM_MMIO_BASE + 0x3000;
pub const TPM_LOCALITY_4: u64 = TPM_MMIO_BASE + 0x4000;

pub mod regs {
    pub const TPM_ACCESS: u64 = 0x00;
    pub const TPM_INT_ENABLE: u64 = 0x08;
    pub const TPM_INT_VECTOR: u64 = 0x0C;
    pub const TPM_INT_STATUS: u64 = 0x10;
    pub const TPM_INTF_CAPS: u64 = 0x14;
    pub const TPM_STS: u64 = 0x18;
    pub const TPM_DATA_FIFO: u64 = 0x24;
    pub const TPM_INTERFACE_ID: u64 = 0x30;
    pub const TPM_XDATA_FIFO: u64 = 0x80;
    pub const TPM_DID_VID: u64 = 0xF00;
    pub const TPM_RID: u64 = 0xF04;
}

pub mod access {
    pub const TPM_ACCESS_VALID: u8 = 1 << 7;
    pub const TPM_ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;
    pub const TPM_ACCESS_BEEN_SEIZED: u8 = 1 << 4;
    pub const TPM_ACCESS_SEIZE: u8 = 1 << 3;
    pub const TPM_ACCESS_PENDING_REQUEST: u8 = 1 << 2;
    pub const TPM_ACCESS_REQUEST_USE: u8 = 1 << 1;
    pub const TPM_ACCESS_ESTABLISHMENT: u8 = 1 << 0;
}

pub mod sts {
    pub const TPM_STS_FAMILY_TPM2: u32 = 1 << 26;
    pub const TPM_STS_RESET_ESTABLISHMENT: u32 = 1 << 25;
    pub const TPM_STS_COMMAND_CANCEL: u32 = 1 << 24;
    pub const TPM_STS_VALID: u32 = 1 << 7;
    pub const TPM_STS_COMMAND_READY: u32 = 1 << 6;
    pub const TPM_STS_GO: u32 = 1 << 5;
    pub const TPM_STS_DATA_AVAIL: u32 = 1 << 4;
    pub const TPM_STS_DATA_EXPECT: u32 = 1 << 3;
    pub const TPM_STS_SELFTEST_DONE: u32 = 1 << 2;
    pub const TPM_STS_RESPONSE_RETRY: u32 = 1 << 1;
}

pub mod commands {
    pub const TPM2_CC_STARTUP: u32 = 0x0000_0144;
    pub const TPM2_CC_SHUTDOWN: u32 = 0x0000_0145;
    pub const TPM2_CC_SELF_TEST: u32 = 0x0000_0143;
    pub const TPM2_CC_PCR_EXTEND: u32 = 0x0000_0182;
    pub const TPM2_CC_PCR_READ: u32 = 0x0000_017E;
    pub const TPM2_CC_PCR_RESET: u32 = 0x0000_013D;
    pub const TPM2_CC_GET_RANDOM: u32 = 0x0000_017B;
    pub const TPM2_CC_GET_CAPABILITY: u32 = 0x0000_017A;
    pub const TPM2_CC_HASH: u32 = 0x0000_017D;
    pub const TPM2_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
    pub const TPM2_CC_CREATE: u32 = 0x0000_0153;
    pub const TPM2_CC_LOAD: u32 = 0x0000_0157;
    pub const TPM2_CC_UNSEAL: u32 = 0x0000_015E;
    pub const TPM2_CC_QUOTE: u32 = 0x0000_0158;
    pub const TPM2_CC_CLEAR: u32 = 0x0000_0126;
}

pub mod alg {
    pub const TPM2_ALG_SHA1: u16 = 0x0004;
    pub const TPM2_ALG_SHA256: u16 = 0x000B;
    pub const TPM2_ALG_SHA384: u16 = 0x000C;
    pub const TPM2_ALG_SHA512: u16 = 0x000D;
    pub const TPM2_ALG_SHA3_256: u16 = 0x0027;
    pub const TPM2_ALG_SHA3_384: u16 = 0x0028;
    pub const TPM2_ALG_SHA3_512: u16 = 0x0029;
    pub const TPM2_ALG_NULL: u16 = 0x0010;
    pub const TPM2_ALG_RSA: u16 = 0x0001;
    pub const TPM2_ALG_ECC: u16 = 0x0023;
}

pub mod startup {
    pub const TPM2_SU_CLEAR: u16 = 0x0000;
    pub const TPM2_SU_STATE: u16 = 0x0001;
}

pub const PCR_BIOS_START: u32 = 0;
pub const PCR_BIOS_END: u32 = 7;
pub const PCR_OS_START: u32 = 8;
pub const PCR_OS_END: u32 = 15;
pub const PCR_DEBUG: u32 = 16;
pub const PCR_LOCALITY_3: u32 = 17;
pub const PCR_LOCALITY_4: u32 = 18;
pub const PCR_RESERVED_START: u32 = 19;
pub const PCR_RESERVED_END: u32 = 22;
pub const PCR_APPLICATION: u32 = 23;

pub const PCR_NONOS_BOOTLOADER: u32 = 4;
pub const PCR_NONOS_BOOTLOADER_CONFIG: u32 = 5;
pub const PCR_NONOS_KERNEL: u32 = 8;
pub const PCR_NONOS_KERNEL_CONFIG: u32 = 9;
pub const PCR_NONOS_IMA: u32 = 10;
pub const PCR_NONOS_MODULES: u32 = 11;

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;

pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;

pub const LOCALITY_REQUEST_TIMEOUT_MS: u32 = 5000;
pub const COMMAND_READY_TIMEOUT_MS: u32 = 5000;
pub const RESPONSE_TIMEOUT_MS: u32 = 30000;

pub const TPM_BUFFER_SIZE: usize = 4096;
pub const TPM_MAX_RANDOM_BYTES: u16 = 48;
pub const TPM_MAX_DIGEST_SIZE: usize = 64;
pub const TPM_NUM_PCRS: usize = 24;

pub const EV_NONOS_KERNEL: u32 = 0x8000_0001;
pub const EV_NONOS_MODULE: u32 = 0x8000_0002;
pub const EV_NONOS_CONFIG: u32 = 0x8000_0003;

pub const TPM_MAX_COMMANDS_PER_SEC: u32 = 100;
pub const TPM_MAX_RANDOM_REQUESTS_PER_SEC: u32 = 50;
