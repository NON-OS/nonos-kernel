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

use crate::drivers::ahci::constants::*;
use crate::test::framework::TestResult;

pub(crate) fn test_hba_register_offsets() -> TestResult {
    if HBA_CAP != 0x00 {
        return TestResult::Fail;
    }
    if HBA_GHC != 0x04 {
        return TestResult::Fail;
    }
    if HBA_IS != 0x08 {
        return TestResult::Fail;
    }
    if HBA_PI != 0x0C {
        return TestResult::Fail;
    }
    if HBA_VS != 0x10 {
        return TestResult::Fail;
    }
    if HBA_CAP2 != 0x24 {
        return TestResult::Fail;
    }
    if HBA_BOHC != 0x28 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_register_offsets() -> TestResult {
    if PORT_CLB != 0x00 {
        return TestResult::Fail;
    }
    if PORT_CLBU != 0x04 {
        return TestResult::Fail;
    }
    if PORT_FB != 0x08 {
        return TestResult::Fail;
    }
    if PORT_FBU != 0x0C {
        return TestResult::Fail;
    }
    if PORT_IS != 0x10 {
        return TestResult::Fail;
    }
    if PORT_IE != 0x14 {
        return TestResult::Fail;
    }
    if PORT_CMD != 0x18 {
        return TestResult::Fail;
    }
    if PORT_TFD != 0x20 {
        return TestResult::Fail;
    }
    if PORT_SIG != 0x24 {
        return TestResult::Fail;
    }
    if PORT_SSTS != 0x28 {
        return TestResult::Fail;
    }
    if PORT_SCTL != 0x2C {
        return TestResult::Fail;
    }
    if PORT_SERR != 0x30 {
        return TestResult::Fail;
    }
    if PORT_SACT != 0x34 {
        return TestResult::Fail;
    }
    if PORT_CI != 0x38 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_bits() -> TestResult {
    if CMD_ST != 1 << 0 {
        return TestResult::Fail;
    }
    if CMD_FRE != 1 << 4 {
        return TestResult::Fail;
    }
    if CMD_FR != 1 << 14 {
        return TestResult::Fail;
    }
    if CMD_CR != 1 << 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_bits_unique() -> TestResult {
    if CMD_ST == CMD_FRE {
        return TestResult::Fail;
    }
    if CMD_FRE == CMD_FR {
        return TestResult::Fail;
    }
    if CMD_FR == CMD_CR {
        return TestResult::Fail;
    }
    if CMD_ST == CMD_CR {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_tfes_bit() -> TestResult {
    if IS_TFES != 1 << 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fis_type_values() -> TestResult {
    if FIS_TYPE_REG_H2D != 0x27 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ata_identify_command() -> TestResult {
    if ATA_CMD_IDENTIFY != 0xEC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ata_read_write_commands() -> TestResult {
    if ATA_CMD_READ_DMA_EXT != 0x25 {
        return TestResult::Fail;
    }
    if ATA_CMD_WRITE_DMA_EXT != 0x35 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ata_dsm_command() -> TestResult {
    if ATA_CMD_DSM != 0x06 {
        return TestResult::Fail;
    }
    if DSM_TRIM != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ata_security_commands() -> TestResult {
    if ATA_CMD_SECURITY_ERASE_PREPARE != 0xF3 {
        return TestResult::Fail;
    }
    if ATA_CMD_SECURITY_ERASE_UNIT != 0xF4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_device_sectors() -> TestResult {
    if MAX_DEVICE_SECTORS != 0x0010_0000_0000 {
        return TestResult::Fail;
    }
    if !(MAX_DEVICE_SECTORS > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_timeouts() -> TestResult {
    if !(COMMAND_TIMEOUT_DEFAULT > 0) {
        return TestResult::Fail;
    }
    if !(COMMAND_TIMEOUT_ERASE > COMMAND_TIMEOUT_DEFAULT) {
        return TestResult::Fail;
    }
    if COMMAND_TIMEOUT_DEFAULT != 5_000_000 {
        return TestResult::Fail;
    }
    if COMMAND_TIMEOUT_ERASE != 3600_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trim_rate_limit() -> TestResult {
    if !(TRIM_RATE_LIMIT_INTERVAL_US > 0) {
        return TestResult::Fail;
    }
    if TRIM_RATE_LIMIT_INTERVAL_US != 10_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_reset_timeout() -> TestResult {
    if !(PORT_RESET_TIMEOUT > 0) {
        return TestResult::Fail;
    }
    if PORT_RESET_TIMEOUT != 1_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_slot_constants() -> TestResult {
    if COMMAND_SLOTS_PER_PORT != 32 {
        return TestResult::Fail;
    }
    if COMMAND_TABLE_SLOT_SIZE != 256 {
        return TestResult::Fail;
    }
    if !(COMMAND_TABLE_SLOT_SIZE >= 128) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_register_spacing() -> TestResult {
    if PORT_IE - PORT_IS != 0x04 {
        return TestResult::Fail;
    }
    if PORT_CMD - PORT_IE != 0x04 {
        return TestResult::Fail;
    }
    if PORT_TFD - PORT_CMD != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hba_register_spacing() -> TestResult {
    if HBA_GHC - HBA_CAP != 0x04 {
        return TestResult::Fail;
    }
    if HBA_IS - HBA_GHC != 0x04 {
        return TestResult::Fail;
    }
    if HBA_PI - HBA_IS != 0x04 {
        return TestResult::Fail;
    }
    if HBA_VS - HBA_PI != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
