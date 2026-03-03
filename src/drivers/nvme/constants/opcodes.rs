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
