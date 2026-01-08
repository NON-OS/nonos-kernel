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

pub const NVME_CLASS: u8 = 0x01;
pub const NVME_SUBCLASS: u8 = 0x08;
pub const NVME_PROGIF: u8 = 0x02;
pub const NVME_BAR_INDEX: u8 = 0;
pub const REG_CAP: usize = 0x0000;
pub const REG_VS: usize = 0x0008;
pub const REG_INTMS: usize = 0x000C;
pub const REG_INTMC: usize = 0x0010;
pub const REG_CC: usize = 0x0014;
pub const REG_CSTS: usize = 0x001C;
pub const REG_NSSR: usize = 0x0020;
pub const REG_AQA: usize = 0x0024;
pub const REG_ASQ: usize = 0x0028;
pub const REG_ACQ: usize = 0x0030;
pub const REG_CMBLOC: usize = 0x0038;
pub const REG_CMBSZ: usize = 0x003C;
pub const REG_BPINFO: usize = 0x0040;
pub const REG_BPRSEL: usize = 0x0044;
pub const REG_BPMBL: usize = 0x0048;
pub const REG_DBS: usize = 0x1000;
pub const CAP_MQES_MASK: u64 = 0xFFFF;
pub const CAP_CQR_BIT: u64 = 1 << 16;
pub const CAP_AMS_SHIFT: u32 = 17;
pub const CAP_AMS_MASK: u64 = 0x3 << 17;
pub const CAP_TO_SHIFT: u32 = 24;
pub const CAP_TO_MASK: u64 = 0xFF << 24;
pub const CAP_DSTRD_SHIFT: u32 = 32;
pub const CAP_DSTRD_MASK: u64 = 0xF << 32;
pub const CAP_NSSRS_BIT: u64 = 1 << 36;
pub const CAP_CSS_SHIFT: u32 = 37;
pub const CAP_CSS_MASK: u64 = 0xFF << 37;
pub const CAP_BPS_BIT: u64 = 1 << 45;
pub const CAP_MPSMIN_SHIFT: u32 = 48;
pub const CAP_MPSMIN_MASK: u64 = 0xF << 48;
pub const CAP_MPSMAX_SHIFT: u32 = 52;
pub const CAP_MPSMAX_MASK: u64 = 0xF << 52;
pub const CAP_PMRS_BIT: u64 = 1 << 56;
pub const CAP_CMBS_BIT: u64 = 1 << 57;
pub const CC_EN: u32 = 1 << 0;
pub const CC_CSS_SHIFT: u32 = 4;
pub const CC_CSS_NVM: u32 = 0 << 4;
pub const CC_CSS_ADMIN_ONLY: u32 = 7 << 4;
pub const CC_MPS_SHIFT: u32 = 7;
pub const CC_MPS_MASK: u32 = 0xF << 7;
pub const CC_AMS_SHIFT: u32 = 11;
pub const CC_AMS_RR: u32 = 0 << 11;
pub const CC_AMS_WRR: u32 = 1 << 11;
pub const CC_AMS_VS: u32 = 7 << 11;
pub const CC_SHN_SHIFT: u32 = 14;
pub const CC_SHN_NONE: u32 = 0 << 14;
pub const CC_SHN_NORMAL: u32 = 1 << 14;
pub const CC_SHN_ABRUPT: u32 = 2 << 14;
pub const CC_IOSQES_SHIFT: u32 = 16;
pub const CC_IOCQES_SHIFT: u32 = 20;
pub const CSTS_RDY: u32 = 1 << 0;
pub const CSTS_CFS: u32 = 1 << 1;
pub const CSTS_SHST_SHIFT: u32 = 2;
pub const CSTS_SHST_MASK: u32 = 0x3 << 2;
pub const CSTS_SHST_NORMAL: u32 = 0 << 2;
pub const CSTS_SHST_OCCURRING: u32 = 1 << 2;
pub const CSTS_SHST_COMPLETE: u32 = 2 << 2;
pub const CSTS_NSSRO: u32 = 1 << 4;
pub const CSTS_PP: u32 = 1 << 5;
pub const AQA_ASQS_SHIFT: u32 = 0;
pub const AQA_ACQS_SHIFT: u32 = 16;
pub const ADMIN_OPC_DELETE_SQ: u8 = 0x00;
pub const ADMIN_OPC_CREATE_SQ: u8 = 0x01;
pub const ADMIN_OPC_GET_LOG_PAGE: u8 = 0x02;
pub const ADMIN_OPC_DELETE_CQ: u8 = 0x04;
pub const ADMIN_OPC_CREATE_CQ: u8 = 0x05;
pub const ADMIN_OPC_IDENTIFY: u8 = 0x06;
pub const ADMIN_OPC_ABORT: u8 = 0x08;
pub const ADMIN_OPC_SET_FEATURES: u8 = 0x09;
pub const ADMIN_OPC_GET_FEATURES: u8 = 0x0A;
pub const ADMIN_OPC_ASYNC_EVENT: u8 = 0x0C;
pub const ADMIN_OPC_NS_MGMT: u8 = 0x0D;
pub const ADMIN_OPC_FW_COMMIT: u8 = 0x10;
pub const ADMIN_OPC_FW_DOWNLOAD: u8 = 0x11;
pub const ADMIN_OPC_DEVICE_SELF_TEST: u8 = 0x14;
pub const ADMIN_OPC_NS_ATTACH: u8 = 0x15;
pub const ADMIN_OPC_KEEP_ALIVE: u8 = 0x18;
pub const ADMIN_OPC_DIRECTIVE_SEND: u8 = 0x19;
pub const ADMIN_OPC_DIRECTIVE_RECV: u8 = 0x1A;
pub const ADMIN_OPC_VIRT_MGMT: u8 = 0x1C;
pub const ADMIN_OPC_MI_SEND: u8 = 0x1D;
pub const ADMIN_OPC_MI_RECV: u8 = 0x1E;
pub const ADMIN_OPC_DOORBELL_BUF_CFG: u8 = 0x7C;
pub const ADMIN_OPC_FORMAT_NVM: u8 = 0x80;
pub const ADMIN_OPC_SECURITY_SEND: u8 = 0x81;
pub const ADMIN_OPC_SECURITY_RECV: u8 = 0x82;
pub const ADMIN_OPC_SANITIZE: u8 = 0x84;
pub const ADMIN_OPC_GET_LBA_STATUS: u8 = 0x86;
pub const IO_OPC_FLUSH: u8 = 0x00;
pub const IO_OPC_WRITE: u8 = 0x01;
pub const IO_OPC_READ: u8 = 0x02;
pub const IO_OPC_WRITE_UNCORRECTABLE: u8 = 0x04;
pub const IO_OPC_COMPARE: u8 = 0x05;
pub const IO_OPC_WRITE_ZEROES: u8 = 0x08;
pub const IO_OPC_DSM: u8 = 0x09;
pub const IO_OPC_VERIFY: u8 = 0x0C;
pub const IO_OPC_RESERVATION_REGISTER: u8 = 0x0D;
pub const IO_OPC_RESERVATION_REPORT: u8 = 0x0E;
pub const IO_OPC_RESERVATION_ACQUIRE: u8 = 0x11;
pub const IO_OPC_RESERVATION_RELEASE: u8 = 0x15;
pub const IO_OPC_ZONE_MGMT_SEND: u8 = 0x79;
pub const IO_OPC_ZONE_MGMT_RECV: u8 = 0x7A;
pub const IO_OPC_ZONE_APPEND: u8 = 0x7D;
pub const CNS_NAMESPACE: u32 = 0x00;
pub const CNS_CONTROLLER: u32 = 0x01;
pub const CNS_ACTIVE_NS_LIST: u32 = 0x02;
pub const CNS_NS_DESC_LIST: u32 = 0x03;
pub const CNS_NVM_SET_LIST: u32 = 0x04;
pub const CNS_ALLOC_NS_LIST: u32 = 0x10;
pub const CNS_ALLOC_NS: u32 = 0x11;
pub const CNS_CTRL_NS_LIST: u32 = 0x12;
pub const CNS_CTRL_LIST: u32 = 0x13;
pub const CNS_PRIMARY_CTRL_CAP: u32 = 0x14;
pub const CNS_SECONDARY_CTRL_LIST: u32 = 0x15;
pub const CNS_NS_GRANULARITY: u32 = 0x16;
pub const CNS_UUID_LIST: u32 = 0x17;
pub const LID_ERROR_INFO: u8 = 0x01;
pub const LID_SMART_HEALTH: u8 = 0x02;
pub const LID_FW_SLOT_INFO: u8 = 0x03;
pub const LID_CHANGED_NS_LIST: u8 = 0x04;
pub const LID_CMD_EFFECTS: u8 = 0x05;
pub const LID_DEVICE_SELF_TEST: u8 = 0x06;
pub const LID_TELEMETRY_HOST: u8 = 0x07;
pub const LID_TELEMETRY_CTRL: u8 = 0x08;
pub const LID_ENDURANCE_GROUP: u8 = 0x09;
pub const LID_PRED_LAT_PER_NVM_SET: u8 = 0x0A;
pub const LID_PRED_LAT_AGG: u8 = 0x0B;
pub const LID_ANA: u8 = 0x0C;
pub const LID_PERSISTENT_EVENT: u8 = 0x0D;
pub const LID_LBA_STATUS_INFO: u8 = 0x0E;
pub const LID_ENDURANCE_GRP_AGG: u8 = 0x0F;
pub const FID_ARBITRATION: u8 = 0x01;
pub const FID_POWER_MGMT: u8 = 0x02;
pub const FID_LBA_RANGE_TYPE: u8 = 0x03;
pub const FID_TEMP_THRESH: u8 = 0x04;
pub const FID_ERR_RECOVERY: u8 = 0x05;
pub const FID_VOLATILE_WC: u8 = 0x06;
pub const FID_NUM_QUEUES: u8 = 0x07;
pub const FID_IRQ_COALESCE: u8 = 0x08;
pub const FID_IRQ_CONFIG: u8 = 0x09;
pub const FID_WRITE_ATOMICITY: u8 = 0x0A;
pub const FID_ASYNC_EVENT_CFG: u8 = 0x0B;
pub const FID_AUTO_PS_TRANS: u8 = 0x0C;
pub const FID_HOST_MEM_BUF: u8 = 0x0D;
pub const FID_TIMESTAMP: u8 = 0x0E;
pub const FID_KEEP_ALIVE: u8 = 0x0F;
pub const FID_HOST_CTRL_THERMAL: u8 = 0x10;
pub const FID_NON_OP_PS_CONFIG: u8 = 0x11;
pub const FID_READ_RECOVERY_LEVEL: u8 = 0x12;
pub const FID_PRED_LAT_MODE: u8 = 0x13;
pub const FID_PRED_LAT_WINDOW: u8 = 0x14;
pub const FID_LBA_STATUS_INFO_ATTRS: u8 = 0x15;
pub const FID_HOST_BEHAVIOR: u8 = 0x16;
pub const FID_SANITIZE_CONFIG: u8 = 0x17;
pub const FID_ENDURANCE_GRP_EVENT: u8 = 0x18;
pub const SQ_FLAGS_PHYS_CONTIG: u16 = 1 << 0;
pub const SQ_FLAGS_PRIO_URGENT: u16 = 0 << 1;
pub const SQ_FLAGS_PRIO_HIGH: u16 = 1 << 1;
pub const SQ_FLAGS_PRIO_MEDIUM: u16 = 2 << 1;
pub const SQ_FLAGS_PRIO_LOW: u16 = 3 << 1;
pub const CQ_FLAGS_PHYS_CONTIG: u16 = 1 << 0;
pub const CQ_FLAGS_IRQ_ENABLED: u16 = 1 << 1;
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_MASK: usize = PAGE_SIZE - 1;
pub const PAGE_SHIFT: u32 = 12;
pub const ADMIN_QUEUE_DEPTH: u16 = 32;
pub const IO_QUEUE_DEPTH: u16 = 256;
pub const MAX_IO_QUEUES: u16 = 64;
pub const SUBMISSION_ENTRY_SIZE: usize = 64;
pub const COMPLETION_ENTRY_SIZE: usize = 16;
pub const DEFAULT_TIMEOUT_SPINS: u32 = 2_000_000;
pub const ENABLE_TIMEOUT_SPINS: u32 = 5_000_000;
pub const DISABLE_TIMEOUT_SPINS: u32 = 5_000_000;
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 100_000;
pub const RATE_WINDOW_MS: u64 = 1000;
pub const KERNEL_PHYS_START: u64 = 0x0000_0000_0000_0000;
pub const KERNEL_PHYS_END: u64 = 0x0000_0000_4000_0000;
pub const MAX_DMA_SIZE: usize = 128 * 1024 * 1024;
pub const MAX_TRANSFER_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_PRP_ENTRIES_PER_PAGE: usize = PAGE_SIZE / 8;
pub const MAX_CID_MISMATCHES: u32 = 10;
pub const IDENTIFY_DATA_SIZE: usize = 4096;
pub const NS_LIST_SIZE: usize = 4096;
pub const NS_LIST_ENTRIES: usize = NS_LIST_SIZE / 4;
pub const IDENTIFY_NS_NSZE_OFFSET: usize = 0x00;
pub const IDENTIFY_NS_NCAP_OFFSET: usize = 0x08;
pub const IDENTIFY_NS_NUSE_OFFSET: usize = 0x10;
pub const IDENTIFY_NS_NSFEAT_OFFSET: usize = 0x18;
pub const IDENTIFY_NS_NLBAF_OFFSET: usize = 0x19;
pub const IDENTIFY_NS_FLBAS_OFFSET: usize = 0x1A;
pub const IDENTIFY_NS_MC_OFFSET: usize = 0x1B;
pub const IDENTIFY_NS_DPC_OFFSET: usize = 0x1C;
pub const IDENTIFY_NS_DPS_OFFSET: usize = 0x1D;
pub const IDENTIFY_NS_NMIC_OFFSET: usize = 0x1E;
pub const IDENTIFY_NS_RESCAP_OFFSET: usize = 0x1F;
pub const IDENTIFY_NS_FPI_OFFSET: usize = 0x20;
pub const IDENTIFY_NS_DLFEAT_OFFSET: usize = 0x21;
pub const IDENTIFY_NS_NAWUN_OFFSET: usize = 0x22;
pub const IDENTIFY_NS_NAWUPF_OFFSET: usize = 0x24;
pub const IDENTIFY_NS_NACWU_OFFSET: usize = 0x26;
pub const IDENTIFY_NS_NABSN_OFFSET: usize = 0x28;
pub const IDENTIFY_NS_NABO_OFFSET: usize = 0x2A;
pub const IDENTIFY_NS_NABSPF_OFFSET: usize = 0x2C;
pub const IDENTIFY_NS_NOIOB_OFFSET: usize = 0x2E;
pub const IDENTIFY_NS_NVMCAP_OFFSET: usize = 0x30;
pub const IDENTIFY_NS_NPWG_OFFSET: usize = 0x40;
pub const IDENTIFY_NS_NPWA_OFFSET: usize = 0x42;
pub const IDENTIFY_NS_NPDG_OFFSET: usize = 0x44;
pub const IDENTIFY_NS_NPDA_OFFSET: usize = 0x46;
pub const IDENTIFY_NS_NOWS_OFFSET: usize = 0x48;
pub const IDENTIFY_NS_LBAF_OFFSET: usize = 0x80;
pub const LBAF_MS_SHIFT: u32 = 0;
pub const LBAF_MS_MASK: u32 = 0xFFFF;
pub const LBAF_LBADS_SHIFT: u32 = 16;
pub const LBAF_LBADS_MASK: u32 = 0xFF << 16;
pub const LBAF_RP_SHIFT: u32 = 24;
pub const LBAF_RP_MASK: u32 = 0x3 << 24;
pub const IDENTIFY_CTRL_VID_OFFSET: usize = 0x00;
pub const IDENTIFY_CTRL_SSVID_OFFSET: usize = 0x02;
pub const IDENTIFY_CTRL_SN_OFFSET: usize = 0x04;
pub const IDENTIFY_CTRL_MN_OFFSET: usize = 0x18;
pub const IDENTIFY_CTRL_FR_OFFSET: usize = 0x40;
pub const IDENTIFY_CTRL_RAB_OFFSET: usize = 0x48;
pub const IDENTIFY_CTRL_IEEE_OFFSET: usize = 0x49;
pub const IDENTIFY_CTRL_CMIC_OFFSET: usize = 0x4C;
pub const IDENTIFY_CTRL_MDTS_OFFSET: usize = 0x4D;
pub const IDENTIFY_CTRL_CNTLID_OFFSET: usize = 0x4E;
pub const IDENTIFY_CTRL_VER_OFFSET: usize = 0x50;
pub const IDENTIFY_CTRL_RTD3R_OFFSET: usize = 0x54;
pub const IDENTIFY_CTRL_RTD3E_OFFSET: usize = 0x58;
pub const IDENTIFY_CTRL_OAES_OFFSET: usize = 0x5C;
pub const IDENTIFY_CTRL_CTRATT_OFFSET: usize = 0x60;
pub const IDENTIFY_CTRL_RRLS_OFFSET: usize = 0x64;
pub const IDENTIFY_CTRL_CNTRLTYPE_OFFSET: usize = 0x6E;
pub const IDENTIFY_CTRL_FGUID_OFFSET: usize = 0x70;
pub const IDENTIFY_CTRL_CRDT1_OFFSET: usize = 0x80;
pub const IDENTIFY_CTRL_CRDT2_OFFSET: usize = 0x82;
pub const IDENTIFY_CTRL_CRDT3_OFFSET: usize = 0x84;
pub const IDENTIFY_CTRL_OACS_OFFSET: usize = 0x100;
pub const IDENTIFY_CTRL_ACL_OFFSET: usize = 0x102;
pub const IDENTIFY_CTRL_AERL_OFFSET: usize = 0x103;
pub const IDENTIFY_CTRL_FRMW_OFFSET: usize = 0x104;
pub const IDENTIFY_CTRL_LPA_OFFSET: usize = 0x105;
pub const IDENTIFY_CTRL_ELPE_OFFSET: usize = 0x106;
pub const IDENTIFY_CTRL_NPSS_OFFSET: usize = 0x107;
pub const IDENTIFY_CTRL_AVSCC_OFFSET: usize = 0x108;
pub const IDENTIFY_CTRL_APSTA_OFFSET: usize = 0x109;
pub const IDENTIFY_CTRL_WCTEMP_OFFSET: usize = 0x10A;
pub const IDENTIFY_CTRL_CCTEMP_OFFSET: usize = 0x10C;
pub const IDENTIFY_CTRL_MTFA_OFFSET: usize = 0x10E;
pub const IDENTIFY_CTRL_HMPRE_OFFSET: usize = 0x110;
pub const IDENTIFY_CTRL_HMMIN_OFFSET: usize = 0x114;
pub const IDENTIFY_CTRL_TNVMCAP_OFFSET: usize = 0x118;
pub const IDENTIFY_CTRL_UNVMCAP_OFFSET: usize = 0x128;
pub const IDENTIFY_CTRL_RPMBS_OFFSET: usize = 0x138;
pub const IDENTIFY_CTRL_EDSTT_OFFSET: usize = 0x13C;
pub const IDENTIFY_CTRL_DSTO_OFFSET: usize = 0x13E;
pub const IDENTIFY_CTRL_FWUG_OFFSET: usize = 0x13F;
pub const IDENTIFY_CTRL_KAS_OFFSET: usize = 0x140;
pub const IDENTIFY_CTRL_HCTMA_OFFSET: usize = 0x142;
pub const IDENTIFY_CTRL_MNTMT_OFFSET: usize = 0x144;
pub const IDENTIFY_CTRL_MXTMT_OFFSET: usize = 0x146;
pub const IDENTIFY_CTRL_SANICAP_OFFSET: usize = 0x148;
pub const IDENTIFY_CTRL_HMMINDS_OFFSET: usize = 0x14C;
pub const IDENTIFY_CTRL_HMMAXD_OFFSET: usize = 0x150;
pub const IDENTIFY_CTRL_NSETIDMAX_OFFSET: usize = 0x152;
pub const IDENTIFY_CTRL_ENDGIDMAX_OFFSET: usize = 0x154;
pub const IDENTIFY_CTRL_ANATT_OFFSET: usize = 0x156;
pub const IDENTIFY_CTRL_ANACAP_OFFSET: usize = 0x157;
pub const IDENTIFY_CTRL_ANAGRPMAX_OFFSET: usize = 0x158;
pub const IDENTIFY_CTRL_NANAGRPID_OFFSET: usize = 0x15C;
pub const IDENTIFY_CTRL_PELS_OFFSET: usize = 0x160;
pub const IDENTIFY_CTRL_SQES_OFFSET: usize = 0x200;
pub const IDENTIFY_CTRL_CQES_OFFSET: usize = 0x201;
pub const IDENTIFY_CTRL_MAXCMD_OFFSET: usize = 0x202;
pub const IDENTIFY_CTRL_NN_OFFSET: usize = 0x204;
pub const IDENTIFY_CTRL_ONCS_OFFSET: usize = 0x208;
pub const IDENTIFY_CTRL_FUSES_OFFSET: usize = 0x20A;
pub const IDENTIFY_CTRL_FNA_OFFSET: usize = 0x20C;
pub const IDENTIFY_CTRL_VWC_OFFSET: usize = 0x20D;
pub const IDENTIFY_CTRL_AWUN_OFFSET: usize = 0x20E;
pub const IDENTIFY_CTRL_AWUPF_OFFSET: usize = 0x210;
pub const IDENTIFY_CTRL_NVSCC_OFFSET: usize = 0x212;
pub const IDENTIFY_CTRL_NWPC_OFFSET: usize = 0x213;
pub const IDENTIFY_CTRL_ACWU_OFFSET: usize = 0x214;
pub const IDENTIFY_CTRL_SGLS_OFFSET: usize = 0x218;
pub const IDENTIFY_CTRL_MNAN_OFFSET: usize = 0x21C;
pub const IDENTIFY_CTRL_SUBNQN_OFFSET: usize = 0x300;
pub const ONCS_COMPARE: u16 = 1 << 0;
pub const ONCS_WRITE_UNC: u16 = 1 << 1;
pub const ONCS_DSM: u16 = 1 << 2;
pub const ONCS_WRITE_ZEROES: u16 = 1 << 3;
pub const ONCS_SAVE_FEATURES: u16 = 1 << 4;
pub const ONCS_RESERVATIONS: u16 = 1 << 5;
pub const ONCS_TIMESTAMP: u16 = 1 << 6;
pub const ONCS_VERIFY: u16 = 1 << 7;
pub const OACS_SECURITY: u16 = 1 << 0;
pub const OACS_FORMAT: u16 = 1 << 1;
pub const OACS_FW_DOWNLOAD: u16 = 1 << 2;
pub const OACS_NS_MGMT: u16 = 1 << 3;
pub const OACS_SELF_TEST: u16 = 1 << 4;
pub const OACS_DIRECTIVES: u16 = 1 << 5;
pub const OACS_MI: u16 = 1 << 6;
pub const OACS_VIRT_MGMT: u16 = 1 << 7;
pub const OACS_DOORBELL_BUF: u16 = 1 << 8;
pub const OACS_GET_LBA_STATUS: u16 = 1 << 9;
pub const DSM_ATTR_INTEGRAL_READ: u32 = 1 << 0;
pub const DSM_ATTR_INTEGRAL_WRITE: u32 = 1 << 1;
pub const DSM_ATTR_DEALLOCATE: u32 = 1 << 2;
pub const DSM_RANGE_SIZE: usize = 16;
pub const DSM_MAX_RANGES: usize = 256;
pub const NSID_ALL: u32 = 0xFFFF_FFFF;

#[inline]
pub const fn doorbell_sq_offset(dstrd: u32, qid: u16) -> usize {
    REG_DBS + (2 * qid as usize) * (4 << dstrd)
}

#[inline]
pub const fn doorbell_cq_offset(dstrd: u32, qid: u16) -> usize {
    REG_DBS + (2 * qid as usize + 1) * (4 << dstrd)
}

#[inline]
pub const fn cap_mqes(cap: u64) -> u16 {
    (cap & CAP_MQES_MASK) as u16
}

#[inline]
pub const fn cap_timeout_ms(cap: u64) -> u32 {
    let to = ((cap & CAP_TO_MASK) >> CAP_TO_SHIFT) as u32;
    to * 500
}

#[inline]
pub const fn cap_dstrd(cap: u64) -> u32 {
    ((cap & CAP_DSTRD_MASK) >> CAP_DSTRD_SHIFT) as u32
}

#[inline]
pub const fn cap_mpsmin(cap: u64) -> u32 {
    ((cap & CAP_MPSMIN_MASK) >> CAP_MPSMIN_SHIFT) as u32
}

#[inline]
pub const fn cap_mpsmax(cap: u64) -> u32 {
    ((cap & CAP_MPSMAX_MASK) >> CAP_MPSMAX_SHIFT) as u32
}

#[inline]
pub const fn cc_mps(page_shift: u32) -> u32 {
    ((page_shift - 12) & 0xF) << CC_MPS_SHIFT
}

#[inline]
pub const fn cc_sqes(entry_size_log2: u32) -> u32 {
    (entry_size_log2 & 0xF) << CC_IOSQES_SHIFT
}

#[inline]
pub const fn cc_cqes(entry_size_log2: u32) -> u32 {
    (entry_size_log2 & 0xF) << CC_IOCQES_SHIFT
}

#[inline]
pub const fn aqa(asqs: u16, acqs: u16) -> u32 {
    ((asqs.saturating_sub(1) as u32) & 0xFFF) | (((acqs.saturating_sub(1) as u32) & 0xFFF) << 16)
}

#[inline]
pub const fn version_major(vs: u32) -> u16 {
    ((vs >> 16) & 0xFFFF) as u16
}

#[inline]
pub const fn version_minor(vs: u32) -> u8 {
    ((vs >> 8) & 0xFF) as u8
}

#[inline]
pub const fn version_tertiary(vs: u32) -> u8 {
    (vs & 0xFF) as u8
}
