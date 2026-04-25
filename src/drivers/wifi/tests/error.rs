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

use crate::drivers::wifi::error::WifiError;
use crate::test::framework::TestResult;

pub(crate) fn test_error_not_initialized() -> TestResult {
    if WifiError::NotInitialized.as_str() != "WiFi not initialized" {
        return TestResult::Fail;
    }
    if WifiError::NotInitialized.code() != 0x0001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_device_not_found() -> TestResult {
    if WifiError::DeviceNotFound.as_str() != "WiFi device not found" {
        return TestResult::Fail;
    }
    if WifiError::DeviceNotFound.code() != 0x0002 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_firmware_not_found() -> TestResult {
    if WifiError::FirmwareNotFound.as_str() != "Firmware not found" {
        return TestResult::Fail;
    }
    if WifiError::FirmwareNotFound.code() != 0x0003 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_firmware_invalid() -> TestResult {
    if WifiError::FirmwareInvalid.as_str() != "Invalid firmware" {
        return TestResult::Fail;
    }
    if WifiError::FirmwareInvalid.code() != 0x0004 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_firmware_load_failed() -> TestResult {
    if WifiError::FirmwareLoadFailed.as_str() != "Firmware load failed" {
        return TestResult::Fail;
    }
    if WifiError::FirmwareLoadFailed.code() != 0x0005 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_hardware_error() -> TestResult {
    if WifiError::HardwareError.as_str() != "Hardware error" {
        return TestResult::Fail;
    }
    if WifiError::HardwareError.code() != 0x0006 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_timeout() -> TestResult {
    if WifiError::Timeout.as_str() != "Operation timeout" {
        return TestResult::Fail;
    }
    if WifiError::Timeout.code() != 0x0007 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_state() -> TestResult {
    if WifiError::InvalidState.as_str() != "Invalid state" {
        return TestResult::Fail;
    }
    if WifiError::InvalidState.code() != 0x0008 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_not_connected() -> TestResult {
    if WifiError::NotConnected.as_str() != "Not connected" {
        return TestResult::Fail;
    }
    if WifiError::NotConnected.code() != 0x0009 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_authentication_failed() -> TestResult {
    if WifiError::AuthenticationFailed.as_str() != "Authentication failed" {
        return TestResult::Fail;
    }
    if WifiError::AuthenticationFailed.code() != 0x000A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_association_failed() -> TestResult {
    if WifiError::AssociationFailed.as_str() != "Association failed" {
        return TestResult::Fail;
    }
    if WifiError::AssociationFailed.code() != 0x000B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_scan_failed() -> TestResult {
    if WifiError::ScanFailed.as_str() != "Scan failed" {
        return TestResult::Fail;
    }
    if WifiError::ScanFailed.code() != 0x000C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_no_network() -> TestResult {
    if WifiError::NoNetwork.as_str() != "Network not found" {
        return TestResult::Fail;
    }
    if WifiError::NoNetwork.code() != 0x000D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_parameter() -> TestResult {
    if WifiError::InvalidParameter.as_str() != "Invalid parameter" {
        return TestResult::Fail;
    }
    if WifiError::InvalidParameter.code() != 0x000E {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_buffer_too_small() -> TestResult {
    if WifiError::BufferTooSmall.as_str() != "Buffer too small" {
        return TestResult::Fail;
    }
    if WifiError::BufferTooSmall.code() != 0x000F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_dma_error() -> TestResult {
    if WifiError::DmaError.as_str() != "DMA error" {
        return TestResult::Fail;
    }
    if WifiError::DmaError.code() != 0x0010 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_command_failed() -> TestResult {
    if WifiError::CommandFailed.as_str() != "Command failed" {
        return TestResult::Fail;
    }
    if WifiError::CommandFailed.code() != 0x0011 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_rf_kill() -> TestResult {
    if WifiError::RfKill.as_str() != "RF kill active" {
        return TestResult::Fail;
    }
    if WifiError::RfKill.code() != 0x0012 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_nvm_error() -> TestResult {
    if WifiError::NvmError.as_str() != "NVM error" {
        return TestResult::Fail;
    }
    if WifiError::NvmError.code() != 0x0013 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_out_of_memory() -> TestResult {
    if WifiError::OutOfMemory.as_str() != "Out of memory" {
        return TestResult::Fail;
    }
    if WifiError::OutOfMemory.code() != 0x0014 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_frame() -> TestResult {
    if WifiError::InvalidFrame.as_str() != "Invalid EAPOL frame" {
        return TestResult::Fail;
    }
    if WifiError::InvalidFrame.code() != 0x0015 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_invalid_key() -> TestResult {
    if WifiError::InvalidKey.as_str() != "Invalid encryption key" {
        return TestResult::Fail;
    }
    if WifiError::InvalidKey.code() != 0x0016 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_mic_failure() -> TestResult {
    if WifiError::MicFailure.as_str() != "MIC verification failed" {
        return TestResult::Fail;
    }
    if WifiError::MicFailure.code() != 0x0017 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_replay_attack() -> TestResult {
    if WifiError::ReplayAttack.as_str() != "Replay attack detected" {
        return TestResult::Fail;
    }
    if WifiError::ReplayAttack.code() != 0x0018 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_integrity_failure() -> TestResult {
    if WifiError::IntegrityFailure.as_str() != "Key integrity check failed" {
        return TestResult::Fail;
    }
    if WifiError::IntegrityFailure.code() != 0x0019 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_unsupported_security() -> TestResult {
    if WifiError::UnsupportedSecurity.as_str() != "Unsupported security type" {
        return TestResult::Fail;
    }
    if WifiError::UnsupportedSecurity.code() != 0x001A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_handshake_timeout() -> TestResult {
    if WifiError::HandshakeTimeout.as_str() != "Handshake timeout" {
        return TestResult::Fail;
    }
    if WifiError::HandshakeTimeout.code() != 0x001B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_handshake_failed() -> TestResult {
    if WifiError::HandshakeFailed.as_str() != "4-way handshake failed" {
        return TestResult::Fail;
    }
    if WifiError::HandshakeFailed.code() != 0x001C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_decryption_failed() -> TestResult {
    if WifiError::DecryptionFailed.as_str() != "Data decryption failed" {
        return TestResult::Fail;
    }
    if WifiError::DecryptionFailed.code() != 0x001D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_firmware_timeout() -> TestResult {
    if WifiError::FirmwareTimeout.as_str() != "Firmware init timeout" {
        return TestResult::Fail;
    }
    if WifiError::FirmwareTimeout.code() != 0x001E {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_network_not_found() -> TestResult {
    if WifiError::NetworkNotFound.as_str() != "Network not found" {
        return TestResult::Fail;
    }
    if WifiError::NetworkNotFound.code() != 0x001F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_equality() -> TestResult {
    if WifiError::Timeout != WifiError::Timeout {
        return TestResult::Fail;
    }
    if WifiError::Timeout == WifiError::NotConnected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_copy() -> TestResult {
    let err1 = WifiError::RfKill;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_clone() -> TestResult {
    let err1 = WifiError::ScanFailed;
    let err2 = err1.clone();
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_debug() -> TestResult {
    use core::fmt::Write;
    let err = WifiError::Timeout;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{:?}", err);
    if writer.as_str() != "Timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_display() -> TestResult {
    use core::fmt::Write;
    let err = WifiError::Timeout;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", err);
    if writer.as_str() != "Operation timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_codes_unique() -> TestResult {
    let errors = [
        WifiError::NotInitialized,
        WifiError::DeviceNotFound,
        WifiError::FirmwareNotFound,
        WifiError::FirmwareInvalid,
        WifiError::FirmwareLoadFailed,
        WifiError::HardwareError,
        WifiError::Timeout,
        WifiError::InvalidState,
        WifiError::NotConnected,
        WifiError::AuthenticationFailed,
        WifiError::AssociationFailed,
        WifiError::ScanFailed,
        WifiError::NoNetwork,
        WifiError::InvalidParameter,
        WifiError::BufferTooSmall,
        WifiError::DmaError,
        WifiError::CommandFailed,
        WifiError::RfKill,
        WifiError::NvmError,
        WifiError::OutOfMemory,
        WifiError::InvalidFrame,
        WifiError::InvalidKey,
        WifiError::MicFailure,
        WifiError::ReplayAttack,
        WifiError::IntegrityFailure,
        WifiError::UnsupportedSecurity,
        WifiError::HandshakeTimeout,
        WifiError::HandshakeFailed,
        WifiError::DecryptionFailed,
        WifiError::FirmwareTimeout,
        WifiError::NetworkNotFound,
    ];

    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            if errors[i].code() == errors[j].code() {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_errors_have_message() -> TestResult {
    let errors = [
        WifiError::NotInitialized,
        WifiError::DeviceNotFound,
        WifiError::FirmwareNotFound,
        WifiError::FirmwareInvalid,
        WifiError::FirmwareLoadFailed,
        WifiError::HardwareError,
        WifiError::Timeout,
        WifiError::InvalidState,
        WifiError::NotConnected,
        WifiError::AuthenticationFailed,
        WifiError::AssociationFailed,
        WifiError::ScanFailed,
        WifiError::NoNetwork,
        WifiError::InvalidParameter,
        WifiError::BufferTooSmall,
        WifiError::DmaError,
        WifiError::CommandFailed,
        WifiError::RfKill,
        WifiError::NvmError,
        WifiError::OutOfMemory,
        WifiError::InvalidFrame,
        WifiError::InvalidKey,
        WifiError::MicFailure,
        WifiError::ReplayAttack,
        WifiError::IntegrityFailure,
        WifiError::UnsupportedSecurity,
        WifiError::HandshakeTimeout,
        WifiError::HandshakeFailed,
        WifiError::DecryptionFailed,
        WifiError::FirmwareTimeout,
        WifiError::NetworkNotFound,
    ];

    for err in &errors {
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
