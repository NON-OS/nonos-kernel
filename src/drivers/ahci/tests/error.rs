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

#[test]
fn test_error_as_str_bar5() {
    assert_eq!(AhciError::Bar5NotConfigured.as_str(), "AHCI BAR5 not configured");
}

#[test]
fn test_error_as_str_hba_reset() {
    assert_eq!(AhciError::HbaResetTimeout.as_str(), "HBA reset timeout");
}

#[test]
fn test_error_as_str_bios_handoff() {
    assert_eq!(AhciError::BiosHandoffTimeout.as_str(), "BIOS handoff timeout");
}

#[test]
fn test_error_as_str_port_cmd_list() {
    assert_eq!(AhciError::PortCmdListStopTimeout.as_str(), "Port command list runner didn't stop");
}

#[test]
fn test_error_as_str_port_fis() {
    assert_eq!(AhciError::PortFisStopTimeout.as_str(), "Port FIS runner didn't stop");
}

#[test]
fn test_error_as_str_zero_sector() {
    assert_eq!(AhciError::ZeroSectorCapacity.as_str(), "Device reports zero sectors");
}

#[test]
fn test_error_as_str_port_not_init() {
    assert_eq!(AhciError::PortNotInitialized.as_str(), "Port not initialized");
}

#[test]
fn test_error_as_str_lba_range() {
    assert_eq!(AhciError::LbaRangeExceeded.as_str(), "LBA range exceeds device capacity");
}

#[test]
fn test_error_as_str_lba_overflow() {
    assert_eq!(AhciError::LbaOverflow.as_str(), "LBA range overflow");
}

#[test]
fn test_error_as_str_invalid_buffer() {
    assert_eq!(AhciError::InvalidBufferSize.as_str(), "Invalid buffer size: 0");
}

#[test]
fn test_error_as_str_buffer_overflow() {
    assert_eq!(AhciError::BufferAddressOverflow.as_str(), "Buffer address overflow");
}

#[test]
fn test_error_as_str_buffer_critical() {
    assert_eq!(AhciError::BufferInCriticalRegion.as_str(), "DMA buffer overlaps kernel critical region");
}

#[test]
fn test_error_as_str_buffer_alignment() {
    assert_eq!(AhciError::BufferNotAligned.as_str(), "DMA buffer not properly aligned");
}

#[test]
fn test_error_as_str_no_slots() {
    assert_eq!(AhciError::NoFreeSlots.as_str(), "No free command slots");
}

#[test]
fn test_error_as_str_command_failed() {
    assert_eq!(AhciError::CommandFailed.as_str(), "AHCI command failed (TFES/ERR)");
}

#[test]
fn test_error_as_str_command_timeout() {
    assert_eq!(AhciError::CommandTimeout.as_str(), "AHCI command timeout");
}

#[test]
fn test_error_as_str_trim_not_supported() {
    assert_eq!(AhciError::TrimNotSupported.as_str(), "Device does not support TRIM");
}

#[test]
fn test_error_as_str_trim_rate_limit() {
    assert_eq!(AhciError::TrimRateLimitExceeded.as_str(), "TRIM rate limit exceeded");
}

#[test]
fn test_error_as_str_secure_erase() {
    assert_eq!(AhciError::SecureEraseNotSupported.as_str(), "Device does not support secure erase");
}

#[test]
fn test_error_as_str_cipher() {
    assert_eq!(AhciError::CipherNotInitialized.as_str(), "AES cipher not initialized");
}

#[test]
fn test_error_as_str_port_dma() {
    assert_eq!(AhciError::PortDmaNotInitialized.as_str(), "Port DMA not initialized");
}

#[test]
fn test_error_as_str_dma_alloc() {
    assert_eq!(AhciError::DmaAllocationFailed.as_str(), "DMA allocation failed");
}

#[test]
fn test_error_as_str_port_reset() {
    assert_eq!(AhciError::PortResetFailed.as_str(), "Port reset failed");
}

#[test]
fn test_error_as_str_no_controller() {
    assert_eq!(AhciError::NoControllerFound.as_str(), "No AHCI controller found");
}

#[test]
fn test_error_equality() {
    assert_eq!(AhciError::Bar5NotConfigured, AhciError::Bar5NotConfigured);
    assert_ne!(AhciError::Bar5NotConfigured, AhciError::HbaResetTimeout);
}

#[test]
fn test_error_copy() {
    let err1 = AhciError::CommandFailed;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_error_clone() {
    let err1 = AhciError::CommandTimeout;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_error_from_str_port_not_init() {
    let err: AhciError = "Port not initialized".into();
    assert_eq!(err, AhciError::PortNotInitialized);
}

#[test]
fn test_error_from_str_trim() {
    let err: AhciError = "Device does not support TRIM".into();
    assert_eq!(err, AhciError::TrimNotSupported);
}

#[test]
fn test_error_from_str_trim_rate() {
    let err: AhciError = "TRIM rate limit exceeded".into();
    assert_eq!(err, AhciError::TrimRateLimitExceeded);
}

#[test]
fn test_error_from_str_secure_erase() {
    let err: AhciError = "Device does not support secure erase".into();
    assert_eq!(err, AhciError::SecureEraseNotSupported);
}

#[test]
fn test_error_from_str_unknown() {
    let err: AhciError = "Unknown error".into();
    assert_eq!(err, AhciError::CommandFailed);
}

#[test]
fn test_error_from_str_bar5() {
    let err: AhciError = "AHCI BAR5 not configured".into();
    assert_eq!(err, AhciError::Bar5NotConfigured);
}

#[test]
fn test_error_from_str_zero_sectors() {
    let err: AhciError = "Device reports zero sectors".into();
    assert_eq!(err, AhciError::ZeroSectorCapacity);
}

#[test]
fn test_error_from_str_cmd_list_stop() {
    let err: AhciError = "Port command list runner didn't stop".into();
    assert_eq!(err, AhciError::PortCmdListStopTimeout);
}

#[test]
fn test_error_from_str_fis_stop() {
    let err: AhciError = "Port FIS runner didn't stop".into();
    assert_eq!(err, AhciError::PortFisStopTimeout);
}

#[test]
fn test_error_debug() {
    let err = AhciError::CommandTimeout;
    let debug_str = format!("{:?}", err);
    assert_eq!(debug_str, "CommandTimeout");
}

#[test]
fn test_error_display() {
    let err = AhciError::CommandTimeout;
    let display_str = format!("{}", err);
    assert_eq!(display_str, "AHCI command timeout");
}

#[test]
fn test_all_error_variants_have_message() {
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
        assert!(!err.as_str().is_empty());
    }
}

#[test]
fn test_error_variant_count() {
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

    assert_eq!(errors.len(), 24);
}
