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
