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

use core::mem;
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct SubmissionEntry {
    pub cdw0: u32,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl SubmissionEntry {
    pub const SIZE: usize = mem::size_of::<Self>();
    #[inline]
    pub const fn new() -> Self {
        Self {
            cdw0: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    #[inline]
    pub fn set_opcode(&mut self, opcode: u8) {
        self.cdw0 = (self.cdw0 & !0xFF) | (opcode as u32);
    }

    #[inline]
    pub fn set_fuse(&mut self, fuse: u8) {
        self.cdw0 = (self.cdw0 & !(0x3 << 8)) | (((fuse & 0x3) as u32) << 8);
    }

    #[inline]
    pub fn set_psdt(&mut self, psdt: u8) {
        self.cdw0 = (self.cdw0 & !(0x3 << 14)) | (((psdt & 0x3) as u32) << 14);
    }

    #[inline]
    pub fn set_cid(&mut self, cid: u16) {
        self.cdw0 = (self.cdw0 & 0xFFFF) | ((cid as u32) << 16);
    }

    #[inline]
    pub const fn opcode(&self) -> u8 {
        (self.cdw0 & 0xFF) as u8
    }

    #[inline]
    pub const fn cid(&self) -> u16 {
        ((self.cdw0 >> 16) & 0xFFFF) as u16
    }

    pub fn sanitize(&mut self) {
        self.cdw2 = 0;
        self.cdw3 = 0;
        self.cdw0 &= 0xFFFF_C3FF;
    }

    pub fn build_identify(cid: u16, nsid: u32, cns: u32, prp1: u64) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::ADMIN_OPC_IDENTIFY);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.cdw10 = cns;
        cmd
    }

    pub fn build_create_cq(
        cid: u16,
        qid: u16,
        qsize: u16,
        prp: u64,
        irq_vector: u16,
        irq_enabled: bool,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::ADMIN_OPC_CREATE_CQ);
        cmd.set_cid(cid);
        cmd.prp1 = prp;
        cmd.cdw10 = ((qsize.saturating_sub(1) as u32) << 16) | (qid as u32);
        let mut cdw11 = super::constants::CQ_FLAGS_PHYS_CONTIG as u32;
        if irq_enabled {
            cdw11 |= super::constants::CQ_FLAGS_IRQ_ENABLED as u32;
        }
        cdw11 |= (irq_vector as u32) << 16;
        cmd.cdw11 = cdw11;
        cmd
    }

    pub fn build_create_sq(
        cid: u16,
        qid: u16,
        qsize: u16,
        prp: u64,
        cqid: u16,
        priority: u8,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::ADMIN_OPC_CREATE_SQ);
        cmd.set_cid(cid);
        cmd.prp1 = prp;
        cmd.cdw10 = ((qsize.saturating_sub(1) as u32) << 16) | (qid as u32);
        let mut cdw11 = super::constants::SQ_FLAGS_PHYS_CONTIG as u32;
        cdw11 |= ((priority & 0x3) as u32) << 1;
        cdw11 |= (cqid as u32) << 16;
        cmd.cdw11 = cdw11;
        cmd
    }

    pub fn build_read(
        cid: u16,
        nsid: u32,
        lba: u64,
        block_count: u16,
        prp1: u64,
        prp2: u64,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::IO_OPC_READ);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
        cmd.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        cmd.cdw11 = ((lba >> 32) & 0xFFFF_FFFF) as u32;
        cmd.cdw12 = (block_count.saturating_sub(1) as u32) & 0xFFFF;
        cmd
    }

    pub fn build_write(
        cid: u16,
        nsid: u32,
        lba: u64,
        block_count: u16,
        prp1: u64,
        prp2: u64,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::IO_OPC_WRITE);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
        cmd.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        cmd.cdw11 = ((lba >> 32) & 0xFFFF_FFFF) as u32;
        cmd.cdw12 = (block_count.saturating_sub(1) as u32) & 0xFFFF;
        cmd
    }

    pub fn build_flush(cid: u16, nsid: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::IO_OPC_FLUSH);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd
    }

    pub fn build_dsm(
        cid: u16,
        nsid: u32,
        range_count: u8,
        attributes: u32,
        prp1: u64,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::IO_OPC_DSM);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.cdw10 = range_count.saturating_sub(1) as u32;
        cmd.cdw11 = attributes;
        cmd
    }

    pub fn build_get_features(cid: u16, fid: u8, nsid: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::ADMIN_OPC_GET_FEATURES);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.cdw10 = fid as u32;
        cmd
    }

    pub fn build_set_features(cid: u16, fid: u8, nsid: u32, value: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::ADMIN_OPC_SET_FEATURES);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.cdw10 = fid as u32;
        cmd.cdw11 = value;
        cmd
    }

    pub fn build_abort(cid: u16, sqid: u16, abort_cid: u16) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::ADMIN_OPC_ABORT);
        cmd.set_cid(cid);
        cmd.cdw10 = (sqid as u32) | ((abort_cid as u32) << 16);
        cmd
    }

    pub fn build_get_log_page(
        cid: u16,
        nsid: u32,
        lid: u8,
        numdl: u16,
        prp1: u64,
    ) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(super::constants::ADMIN_OPC_GET_LOG_PAGE);
        cmd.set_cid(cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.cdw10 = (lid as u32) | (((numdl as u32) & 0xFFFF) << 16);
        cmd
    }
}

impl Default for SubmissionEntry {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct CompletionEntry {
    pub dw0: u32,
    pub dw1: u32,
    pub sq_head: u16,
    pub sq_id: u16,
    pub cid: u16,
    pub status: u16,
}

impl CompletionEntry {
    pub const SIZE: usize = mem::size_of::<Self>();

    #[inline]
    pub const fn phase(&self) -> bool {
        (self.status & 1) != 0
    }

    #[inline]
    pub const fn status_code_type(&self) -> u8 {
        ((self.status >> 9) & 0x7) as u8
    }

    #[inline]
    pub const fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    #[inline]
    pub const fn status_field(&self) -> u16 {
        self.status >> 1
    }

    #[inline]
    pub const fn is_success(&self) -> bool {
        (self.status >> 1) == 0
    }

    #[inline]
    pub const fn is_error(&self) -> bool {
        !self.is_success()
    }

    #[inline]
    pub const fn more(&self) -> bool {
        (self.status & (1 << 14)) != 0
    }

    #[inline]
    pub const fn dnr(&self) -> bool {
        (self.status & (1 << 15)) != 0
    }

    #[inline]
    pub const fn result(&self) -> u64 {
        ((self.dw1 as u64) << 32) | (self.dw0 as u64)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DsmRange {
    pub context_attributes: u32,
    pub lba_count: u32,
    pub starting_lba: u64,
}

impl DsmRange {
    pub const SIZE: usize = mem::size_of::<Self>();

    pub const fn new(lba: u64, count: u32, attributes: u32) -> Self {
        Self {
            context_attributes: attributes,
            lba_count: count,
            starting_lba: lba,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerCapabilities {
    pub max_queue_entries: u16,
    pub contiguous_queues_required: bool,
    pub arbitration_mechanisms: u8,
    pub timeout_500ms_units: u8,
    pub doorbell_stride: u8,
    pub subsystem_reset_supported: bool,
    pub command_sets_supported: u8,
    pub boot_partition_supported: bool,
    pub memory_page_size_min_shift: u8,
    pub memory_page_size_max_shift: u8,
    pub persistent_memory_region: bool,
    pub controller_memory_buffer: bool,
}

impl ControllerCapabilities {
    pub fn from_register(cap: u64) -> Self {
        Self {
            max_queue_entries: ((cap & super::constants::CAP_MQES_MASK) as u16) + 1,
            contiguous_queues_required: (cap & super::constants::CAP_CQR_BIT) != 0,
            arbitration_mechanisms: ((cap >> super::constants::CAP_AMS_SHIFT) & 0x3) as u8,
            timeout_500ms_units: ((cap >> super::constants::CAP_TO_SHIFT) & 0xFF) as u8,
            doorbell_stride: ((cap >> super::constants::CAP_DSTRD_SHIFT) & 0xF) as u8,
            subsystem_reset_supported: (cap & super::constants::CAP_NSSRS_BIT) != 0,
            command_sets_supported: ((cap >> super::constants::CAP_CSS_SHIFT) & 0xFF) as u8,
            boot_partition_supported: (cap & super::constants::CAP_BPS_BIT) != 0,
            memory_page_size_min_shift: ((cap >> super::constants::CAP_MPSMIN_SHIFT) & 0xF) as u8 + 12,
            memory_page_size_max_shift: ((cap >> super::constants::CAP_MPSMAX_SHIFT) & 0xF) as u8 + 12,
            persistent_memory_region: (cap & super::constants::CAP_PMRS_BIT) != 0,
            controller_memory_buffer: (cap & super::constants::CAP_CMBS_BIT) != 0,
        }
    }

    pub const fn min_page_size(&self) -> usize {
        1 << self.memory_page_size_min_shift
    }

    pub const fn max_page_size(&self) -> usize {
        1 << self.memory_page_size_max_shift
    }

    pub const fn timeout_ms(&self) -> u32 {
        (self.timeout_500ms_units as u32) * 500
    }

    pub fn supports_nvm_command_set(&self) -> bool {
        (self.command_sets_supported & 0x01) != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerVersion {
    pub major: u16,
    pub minor: u8,
    pub tertiary: u8,
}

impl ControllerVersion {
    pub fn from_register(vs: u32) -> Self {
        Self {
            major: super::constants::version_major(vs),
            minor: super::constants::version_minor(vs),
            tertiary: super::constants::version_tertiary(vs),
        }
    }

    pub const fn is_at_least(&self, major: u16, minor: u8) -> bool {
        self.major > major || (self.major == major && self.minor >= minor)
    }
}

impl core::fmt::Display for ControllerVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.tertiary != 0 {
            write!(f, "{}.{}.{}", self.major, self.minor, self.tertiary)
        } else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}

#[derive(Debug, Clone)]
pub struct ControllerIdentity {
    pub vendor_id: u16,
    pub subsystem_vendor_id: u16,
    pub serial_number: [u8; 20],
    pub model_number: [u8; 40],
    pub firmware_revision: [u8; 8],
    pub recommended_arb_burst: u8,
    pub ieee_oui: [u8; 3],
    pub controller_multi_path: u8,
    pub max_data_transfer_size: u8,
    pub controller_id: u16,
    pub version: u32,
    pub rtd3_resume_latency: u32,
    pub rtd3_entry_latency: u32,
    pub optional_async_events: u32,
    pub controller_attributes: u32,
    pub controller_type: u8,
    pub fguid: [u8; 16],
    pub optional_admin_cmd_support: u16,
    pub abort_command_limit: u8,
    pub async_event_request_limit: u8,
    pub firmware_updates: u8,
    pub log_page_attributes: u8,
    pub error_log_page_entries: u8,
    pub num_power_states: u8,
    pub admin_vendor_specific_cmd_cfg: u8,
    pub autonomous_power_state_trans: u8,
    pub warning_composite_temp: u16,
    pub critical_composite_temp: u16,
    pub max_time_firmware_activation: u16,
    pub host_memory_buffer_preferred: u32,
    pub host_memory_buffer_minimum: u32,
    pub total_nvm_capacity: [u8; 16],
    pub unallocated_nvm_capacity: [u8; 16],
    pub max_namespaces: u32,
    pub submission_queue_entry_size: u8,
    pub completion_queue_entry_size: u8,
    pub max_outstanding_cmds: u16,
    pub number_namespaces: u32,
    pub optional_nvm_cmd_support: u16,
    pub fused_operation_support: u16,
    pub format_nvm_attributes: u8,
    pub volatile_write_cache: u8,
    pub atomic_write_unit_normal: u16,
    pub atomic_write_unit_power_fail: u16,
    pub nvm_vendor_specific_cmd_cfg: u8,
    pub namespace_write_protection: u8,
    pub atomic_compare_write_unit: u16,
    pub sgl_support: u32,
    pub max_namespaces_allocated: u32,
    pub nvm_subsystem_qualified_name: [u8; 256],
}

impl ControllerIdentity {
    pub fn from_data(data: &[u8; 4096]) -> Self {
        let mut serial = [0u8; 20];
        let mut model = [0u8; 40];
        let mut firmware = [0u8; 8];
        let mut ieee = [0u8; 3];
        let mut fguid = [0u8; 16];
        let mut total_cap = [0u8; 16];
        let mut unalloc_cap = [0u8; 16];
        let mut subnqn = [0u8; 256];

        serial.copy_from_slice(&data[0x04..0x18]);
        model.copy_from_slice(&data[0x18..0x40]);
        firmware.copy_from_slice(&data[0x40..0x48]);
        ieee.copy_from_slice(&data[0x49..0x4C]);
        fguid.copy_from_slice(&data[0x70..0x80]);
        total_cap.copy_from_slice(&data[0x118..0x128]);
        unalloc_cap.copy_from_slice(&data[0x128..0x138]);
        subnqn.copy_from_slice(&data[0x300..0x400]);

        Self {
            vendor_id: u16::from_le_bytes([data[0x00], data[0x01]]),
            subsystem_vendor_id: u16::from_le_bytes([data[0x02], data[0x03]]),
            serial_number: serial,
            model_number: model,
            firmware_revision: firmware,
            recommended_arb_burst: data[0x48],
            ieee_oui: ieee,
            controller_multi_path: data[0x4C],
            max_data_transfer_size: data[0x4D],
            controller_id: u16::from_le_bytes([data[0x4E], data[0x4F]]),
            version: u32::from_le_bytes([data[0x50], data[0x51], data[0x52], data[0x53]]),
            rtd3_resume_latency: u32::from_le_bytes([data[0x54], data[0x55], data[0x56], data[0x57]]),
            rtd3_entry_latency: u32::from_le_bytes([data[0x58], data[0x59], data[0x5A], data[0x5B]]),
            optional_async_events: u32::from_le_bytes([data[0x5C], data[0x5D], data[0x5E], data[0x5F]]),
            controller_attributes: u32::from_le_bytes([data[0x60], data[0x61], data[0x62], data[0x63]]),
            controller_type: data[0x6E],
            fguid,
            optional_admin_cmd_support: u16::from_le_bytes([data[0x100], data[0x101]]),
            abort_command_limit: data[0x102],
            async_event_request_limit: data[0x103],
            firmware_updates: data[0x104],
            log_page_attributes: data[0x105],
            error_log_page_entries: data[0x106],
            num_power_states: data[0x107],
            admin_vendor_specific_cmd_cfg: data[0x108],
            autonomous_power_state_trans: data[0x109],
            warning_composite_temp: u16::from_le_bytes([data[0x10A], data[0x10B]]),
            critical_composite_temp: u16::from_le_bytes([data[0x10C], data[0x10D]]),
            max_time_firmware_activation: u16::from_le_bytes([data[0x10E], data[0x10F]]),
            host_memory_buffer_preferred: u32::from_le_bytes([data[0x110], data[0x111], data[0x112], data[0x113]]),
            host_memory_buffer_minimum: u32::from_le_bytes([data[0x114], data[0x115], data[0x116], data[0x117]]),
            total_nvm_capacity: total_cap,
            unallocated_nvm_capacity: unalloc_cap,
            max_namespaces: u32::from_le_bytes([data[0x21C], data[0x21D], data[0x21E], data[0x21F]]),
            submission_queue_entry_size: data[0x200],
            completion_queue_entry_size: data[0x201],
            max_outstanding_cmds: u16::from_le_bytes([data[0x202], data[0x203]]),
            number_namespaces: u32::from_le_bytes([data[0x204], data[0x205], data[0x206], data[0x207]]),
            optional_nvm_cmd_support: u16::from_le_bytes([data[0x208], data[0x209]]),
            fused_operation_support: u16::from_le_bytes([data[0x20A], data[0x20B]]),
            format_nvm_attributes: data[0x20C],
            volatile_write_cache: data[0x20D],
            atomic_write_unit_normal: u16::from_le_bytes([data[0x20E], data[0x20F]]),
            atomic_write_unit_power_fail: u16::from_le_bytes([data[0x210], data[0x211]]),
            nvm_vendor_specific_cmd_cfg: data[0x212],
            namespace_write_protection: data[0x213],
            atomic_compare_write_unit: u16::from_le_bytes([data[0x214], data[0x215]]),
            sgl_support: u32::from_le_bytes([data[0x218], data[0x219], data[0x21A], data[0x21B]]),
            max_namespaces_allocated: u32::from_le_bytes([data[0x21C], data[0x21D], data[0x21E], data[0x21F]]),
            nvm_subsystem_qualified_name: subnqn,
        }
    }

    pub fn serial_string(&self) -> alloc::string::String {
        let cow = alloc::string::String::from_utf8_lossy(&self.serial_number);
        alloc::string::String::from(cow.trim())
    }

    pub fn model_string(&self) -> alloc::string::String {
        let cow = alloc::string::String::from_utf8_lossy(&self.model_number);
        alloc::string::String::from(cow.trim())
    }

    pub fn firmware_string(&self) -> alloc::string::String {
        let cow = alloc::string::String::from_utf8_lossy(&self.firmware_revision);
        alloc::string::String::from(cow.trim())
    }

    pub fn supports_dsm(&self) -> bool {
        (self.optional_nvm_cmd_support & super::constants::ONCS_DSM) != 0
    }

    pub fn supports_write_zeroes(&self) -> bool {
        (self.optional_nvm_cmd_support & super::constants::ONCS_WRITE_ZEROES) != 0
    }

    pub fn supports_compare(&self) -> bool {
        (self.optional_nvm_cmd_support & super::constants::ONCS_COMPARE) != 0
    }

    pub fn supports_reservations(&self) -> bool {
        (self.optional_nvm_cmd_support & super::constants::ONCS_RESERVATIONS) != 0
    }

    pub fn supports_security(&self) -> bool {
        (self.optional_admin_cmd_support & super::constants::OACS_SECURITY) != 0
    }

    pub fn supports_format(&self) -> bool {
        (self.optional_admin_cmd_support & super::constants::OACS_FORMAT) != 0
    }

    pub fn supports_firmware_download(&self) -> bool {
        (self.optional_admin_cmd_support & super::constants::OACS_FW_DOWNLOAD) != 0
    }

    pub fn supports_namespace_mgmt(&self) -> bool {
        (self.optional_admin_cmd_support & super::constants::OACS_NS_MGMT) != 0
    }

    pub fn supports_self_test(&self) -> bool {
        (self.optional_admin_cmd_support & super::constants::OACS_SELF_TEST) != 0
    }

    pub fn max_transfer_bytes(&self, page_size: usize) -> usize {
        if self.max_data_transfer_size == 0 {
            usize::MAX
        } else {
            page_size << self.max_data_transfer_size
        }
    }

    pub fn required_sqe_size(&self) -> usize {
        1 << (self.submission_queue_entry_size & 0x0F)
    }

    pub fn required_cqe_size(&self) -> usize {
        1 << (self.completion_queue_entry_size & 0x0F)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LbaFormat {
    pub metadata_size: u16,
    pub lba_data_size_shift: u8,
    pub relative_performance: u8,
}

impl LbaFormat {
    pub fn from_dword(dw: u32) -> Self {
        Self {
            metadata_size: (dw & 0xFFFF) as u16,
            lba_data_size_shift: ((dw >> 16) & 0xFF) as u8,
            relative_performance: ((dw >> 24) & 0x3) as u8,
        }
    }

    pub const fn lba_size(&self) -> u32 {
        if self.lba_data_size_shift == 0 {
            0
        } else {
            1 << self.lba_data_size_shift
        }
    }

    pub const fn performance_string(&self) -> &'static str {
        match self.relative_performance {
            0 => "Best",
            1 => "Better",
            2 => "Good",
            3 => "Degraded",
            _ => "Unknown",
        }
    }
}
