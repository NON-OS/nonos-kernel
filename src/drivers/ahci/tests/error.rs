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

use crate::drivers::ahci::error::AhciError;
use crate::test::framework::TestResult;

pub(crate) fn test_error_as_str_bar5() -> TestResult {
    if AhciError::Bar5NotConfigured.as_str() != "AHCI BAR5 not configured" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_hba_reset() -> TestResult {
    if AhciError::HbaResetTimeout.as_str() != "HBA reset timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_bios_handoff() -> TestResult {
    if AhciError::BiosHandoffTimeout.as_str() != "BIOS handoff timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_port_cmd_list() -> TestResult {
    if AhciError::PortCmdListStopTimeout.as_str() != "Port command list runner didn't stop" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_port_fis() -> TestResult {
    if AhciError::PortFisStopTimeout.as_str() != "Port FIS runner didn't stop" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_zero_sector() -> TestResult {
    if AhciError::ZeroSectorCapacity.as_str() != "Device reports zero sectors" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_port_not_init() -> TestResult {
    if AhciError::PortNotInitialized.as_str() != "Port not initialized" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_lba_range() -> TestResult {
    if AhciError::LbaRangeExceeded.as_str() != "LBA range exceeds device capacity" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_lba_overflow() -> TestResult {
    if AhciError::LbaOverflow.as_str() != "LBA range overflow" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_invalid_buffer() -> TestResult {
    if AhciError::InvalidBufferSize.as_str() != "Invalid buffer size: 0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_buffer_overflow() -> TestResult {
    if AhciError::BufferAddressOverflow.as_str() != "Buffer address overflow" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_buffer_critical() -> TestResult {
    if AhciError::BufferInCriticalRegion.as_str() != "DMA buffer overlaps kernel critical region" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_buffer_alignment() -> TestResult {
    if AhciError::BufferNotAligned.as_str() != "DMA buffer not properly aligned" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_no_slots() -> TestResult {
    if AhciError::NoFreeSlots.as_str() != "No free command slots" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_command_failed() -> TestResult {
    if AhciError::CommandFailed.as_str() != "AHCI command failed (TFES/ERR)" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_command_timeout() -> TestResult {
    if AhciError::CommandTimeout.as_str() != "AHCI command timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_trim_not_supported() -> TestResult {
    if AhciError::TrimNotSupported.as_str() != "Device does not support TRIM" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_trim_rate_limit() -> TestResult {
    if AhciError::TrimRateLimitExceeded.as_str() != "TRIM rate limit exceeded" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_secure_erase() -> TestResult {
    if AhciError::SecureEraseNotSupported.as_str() != "Device does not support secure erase" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_cipher() -> TestResult {
    if AhciError::CipherNotInitialized.as_str() != "AES cipher not initialized" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_port_dma() -> TestResult {
    if AhciError::PortDmaNotInitialized.as_str() != "Port DMA not initialized" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_dma_alloc() -> TestResult {
    if AhciError::DmaAllocationFailed.as_str() != "DMA allocation failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_port_reset() -> TestResult {
    if AhciError::PortResetFailed.as_str() != "Port reset failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_as_str_no_controller() -> TestResult {
    if AhciError::NoControllerFound.as_str() != "No AHCI controller found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_equality() -> TestResult {
    if AhciError::Bar5NotConfigured != AhciError::Bar5NotConfigured {
        return TestResult::Fail;
    }
    if AhciError::Bar5NotConfigured == AhciError::HbaResetTimeout {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_copy() -> TestResult {
    let err1 = AhciError::CommandFailed;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_clone() -> TestResult {
    let err1 = AhciError::CommandTimeout;
    let err2 = err1.clone();
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_from_str_port_not_init() -> TestResult {
    let err: AhciError = "Port not initialized".into();
    if err != AhciError::PortNotInitialized {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_from_str_trim() -> TestResult {
    let err: AhciError = "Device does not support TRIM".into();
    if err != AhciError::TrimNotSupported {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_from_str_trim_rate() -> TestResult {
    let err: AhciError = "TRIM rate limit exceeded".into();
    if err != AhciError::TrimRateLimitExceeded {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_from_str_secure_erase() -> TestResult {
    let err: AhciError = "Device does not support secure erase".into();
    if err != AhciError::SecureEraseNotSupported {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_from_str_unknown() -> TestResult {
    let err: AhciError = "Unknown error".into();
    if err != AhciError::CommandFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_from_str_bar5() -> TestResult {
    let err: AhciError = "AHCI BAR5 not configured".into();
    if err != AhciError::Bar5NotConfigured {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_from_str_zero_sectors() -> TestResult {
    let err: AhciError = "Device reports zero sectors".into();
    if err != AhciError::ZeroSectorCapacity {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_from_str_cmd_list_stop() -> TestResult {
    let err: AhciError = "Port command list runner didn't stop".into();
    if err != AhciError::PortCmdListStopTimeout {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_from_str_fis_stop() -> TestResult {
    let err: AhciError = "Port FIS runner didn't stop".into();
    if err != AhciError::PortFisStopTimeout {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_debug() -> TestResult {
    let err = AhciError::CommandTimeout;
    let debug_str = format!("{:?}", err);
    if debug_str != "CommandTimeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_display() -> TestResult {
    let err = AhciError::CommandTimeout;
    let display_str = format!("{}", err);
    if display_str != "AHCI command timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_error_variants_have_message() -> TestResult {
    let errors = [
        AhciError::Bar5NotConfigured,
        AhciError::HbaResetTimeout,
        AhciError::BiosHandoffTimeout,
        AhciError::PortCmdListStopTimeout,
        AhciError::PortFisStopTimeout,
        AhciError::ZeroSectorCapacity,
        AhciError::PortNotInitialized,
        AhciError::LbaRangeExceeded,
        AhciError::LbaOverflow,
        AhciError::InvalidBufferSize,
        AhciError::BufferAddressOverflow,
        AhciError::BufferInCriticalRegion,
        AhciError::BufferNotAligned,
        AhciError::NoFreeSlots,
        AhciError::CommandFailed,
        AhciError::CommandTimeout,
        AhciError::TrimNotSupported,
        AhciError::TrimRateLimitExceeded,
        AhciError::SecureEraseNotSupported,
        AhciError::CipherNotInitialized,
        AhciError::PortDmaNotInitialized,
        AhciError::DmaAllocationFailed,
        AhciError::PortResetFailed,
        AhciError::NoControllerFound,
    ];

    for err in &errors {
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_error_variant_count() -> TestResult {
    let errors = [
        AhciError::Bar5NotConfigured,
        AhciError::HbaResetTimeout,
        AhciError::BiosHandoffTimeout,
        AhciError::PortCmdListStopTimeout,
        AhciError::PortFisStopTimeout,
        AhciError::ZeroSectorCapacity,
        AhciError::PortNotInitialized,
        AhciError::LbaRangeExceeded,
        AhciError::LbaOverflow,
        AhciError::InvalidBufferSize,
        AhciError::BufferAddressOverflow,
        AhciError::BufferInCriticalRegion,
        AhciError::BufferNotAligned,
        AhciError::NoFreeSlots,
        AhciError::CommandFailed,
        AhciError::CommandTimeout,
        AhciError::TrimNotSupported,
        AhciError::TrimRateLimitExceeded,
        AhciError::SecureEraseNotSupported,
        AhciError::CipherNotInitialized,
        AhciError::PortDmaNotInitialized,
        AhciError::DmaAllocationFailed,
        AhciError::PortResetFailed,
        AhciError::NoControllerFound,
    ];

    if errors.len() != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
