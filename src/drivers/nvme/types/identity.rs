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
        (self.optional_nvm_cmd_support & super::super::constants::ONCS_DSM) != 0
    }

    pub fn supports_write_zeroes(&self) -> bool {
        (self.optional_nvm_cmd_support & super::super::constants::ONCS_WRITE_ZEROES) != 0
    }

    pub fn supports_compare(&self) -> bool {
        (self.optional_nvm_cmd_support & super::super::constants::ONCS_COMPARE) != 0
    }

    pub fn supports_reservations(&self) -> bool {
        (self.optional_nvm_cmd_support & super::super::constants::ONCS_RESERVATIONS) != 0
    }

    pub fn supports_security(&self) -> bool {
        (self.optional_admin_cmd_support & super::super::constants::OACS_SECURITY) != 0
    }

    pub fn supports_format(&self) -> bool {
        (self.optional_admin_cmd_support & super::super::constants::OACS_FORMAT) != 0
    }

    pub fn supports_firmware_download(&self) -> bool {
        (self.optional_admin_cmd_support & super::super::constants::OACS_FW_DOWNLOAD) != 0
    }

    pub fn supports_namespace_mgmt(&self) -> bool {
        (self.optional_admin_cmd_support & super::super::constants::OACS_NS_MGMT) != 0
    }

    pub fn supports_self_test(&self) -> bool {
        (self.optional_admin_cmd_support & super::super::constants::OACS_SELF_TEST) != 0
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
