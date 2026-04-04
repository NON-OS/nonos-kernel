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

#[test]
fn test_error_not_initialized() {
    assert_eq!(WifiError::NotInitialized.as_str(), "WiFi not initialized");
    assert_eq!(WifiError::NotInitialized.code(), 0x0001);
}

#[test]
fn test_error_device_not_found() {
    assert_eq!(WifiError::DeviceNotFound.as_str(), "WiFi device not found");
    assert_eq!(WifiError::DeviceNotFound.code(), 0x0002);
}

#[test]
fn test_error_firmware_not_found() {
    assert_eq!(WifiError::FirmwareNotFound.as_str(), "Firmware not found");
    assert_eq!(WifiError::FirmwareNotFound.code(), 0x0003);
}

#[test]
fn test_error_firmware_invalid() {
    assert_eq!(WifiError::FirmwareInvalid.as_str(), "Invalid firmware");
    assert_eq!(WifiError::FirmwareInvalid.code(), 0x0004);
}

#[test]
fn test_error_firmware_load_failed() {
    assert_eq!(WifiError::FirmwareLoadFailed.as_str(), "Firmware load failed");
    assert_eq!(WifiError::FirmwareLoadFailed.code(), 0x0005);
}

#[test]
fn test_error_hardware_error() {
    assert_eq!(WifiError::HardwareError.as_str(), "Hardware error");
    assert_eq!(WifiError::HardwareError.code(), 0x0006);
}

#[test]
fn test_error_timeout() {
    assert_eq!(WifiError::Timeout.as_str(), "Operation timeout");
    assert_eq!(WifiError::Timeout.code(), 0x0007);
}

#[test]
fn test_error_invalid_state() {
    assert_eq!(WifiError::InvalidState.as_str(), "Invalid state");
    assert_eq!(WifiError::InvalidState.code(), 0x0008);
}

#[test]
fn test_error_not_connected() {
    assert_eq!(WifiError::NotConnected.as_str(), "Not connected");
    assert_eq!(WifiError::NotConnected.code(), 0x0009);
}

#[test]
fn test_error_authentication_failed() {
    assert_eq!(WifiError::AuthenticationFailed.as_str(), "Authentication failed");
    assert_eq!(WifiError::AuthenticationFailed.code(), 0x000A);
}

#[test]
fn test_error_association_failed() {
    assert_eq!(WifiError::AssociationFailed.as_str(), "Association failed");
    assert_eq!(WifiError::AssociationFailed.code(), 0x000B);
}

#[test]
fn test_error_scan_failed() {
    assert_eq!(WifiError::ScanFailed.as_str(), "Scan failed");
    assert_eq!(WifiError::ScanFailed.code(), 0x000C);
}

#[test]
fn test_error_no_network() {
    assert_eq!(WifiError::NoNetwork.as_str(), "Network not found");
    assert_eq!(WifiError::NoNetwork.code(), 0x000D);
}

#[test]
fn test_error_invalid_parameter() {
    assert_eq!(WifiError::InvalidParameter.as_str(), "Invalid parameter");
    assert_eq!(WifiError::InvalidParameter.code(), 0x000E);
}

#[test]
fn test_error_buffer_too_small() {
    assert_eq!(WifiError::BufferTooSmall.as_str(), "Buffer too small");
    assert_eq!(WifiError::BufferTooSmall.code(), 0x000F);
}

#[test]
fn test_error_dma_error() {
    assert_eq!(WifiError::DmaError.as_str(), "DMA error");
    assert_eq!(WifiError::DmaError.code(), 0x0010);
}

#[test]
fn test_error_command_failed() {
    assert_eq!(WifiError::CommandFailed.as_str(), "Command failed");
    assert_eq!(WifiError::CommandFailed.code(), 0x0011);
}

#[test]
fn test_error_rf_kill() {
    assert_eq!(WifiError::RfKill.as_str(), "RF kill active");
    assert_eq!(WifiError::RfKill.code(), 0x0012);
}

#[test]
fn test_error_nvm_error() {
    assert_eq!(WifiError::NvmError.as_str(), "NVM error");
    assert_eq!(WifiError::NvmError.code(), 0x0013);
}

#[test]
fn test_error_out_of_memory() {
    assert_eq!(WifiError::OutOfMemory.as_str(), "Out of memory");
    assert_eq!(WifiError::OutOfMemory.code(), 0x0014);
}

#[test]
fn test_error_invalid_frame() {
    assert_eq!(WifiError::InvalidFrame.as_str(), "Invalid EAPOL frame");
    assert_eq!(WifiError::InvalidFrame.code(), 0x0015);
}

#[test]
fn test_error_invalid_key() {
    assert_eq!(WifiError::InvalidKey.as_str(), "Invalid encryption key");
    assert_eq!(WifiError::InvalidKey.code(), 0x0016);
}

#[test]
fn test_error_mic_failure() {
    assert_eq!(WifiError::MicFailure.as_str(), "MIC verification failed");
    assert_eq!(WifiError::MicFailure.code(), 0x0017);
}

#[test]
fn test_error_replay_attack() {
    assert_eq!(WifiError::ReplayAttack.as_str(), "Replay attack detected");
    assert_eq!(WifiError::ReplayAttack.code(), 0x0018);
}

#[test]
fn test_error_integrity_failure() {
    assert_eq!(WifiError::IntegrityFailure.as_str(), "Key integrity check failed");
    assert_eq!(WifiError::IntegrityFailure.code(), 0x0019);
}

#[test]
fn test_error_unsupported_security() {
    assert_eq!(WifiError::UnsupportedSecurity.as_str(), "Unsupported security type");
    assert_eq!(WifiError::UnsupportedSecurity.code(), 0x001A);
}

#[test]
fn test_error_handshake_timeout() {
    assert_eq!(WifiError::HandshakeTimeout.as_str(), "Handshake timeout");
    assert_eq!(WifiError::HandshakeTimeout.code(), 0x001B);
}

#[test]
fn test_error_handshake_failed() {
    assert_eq!(WifiError::HandshakeFailed.as_str(), "4-way handshake failed");
    assert_eq!(WifiError::HandshakeFailed.code(), 0x001C);
}

#[test]
fn test_error_decryption_failed() {
    assert_eq!(WifiError::DecryptionFailed.as_str(), "Data decryption failed");
    assert_eq!(WifiError::DecryptionFailed.code(), 0x001D);
}

#[test]
fn test_error_firmware_timeout() {
    assert_eq!(WifiError::FirmwareTimeout.as_str(), "Firmware init timeout");
    assert_eq!(WifiError::FirmwareTimeout.code(), 0x001E);
}

#[test]
fn test_error_network_not_found() {
    assert_eq!(WifiError::NetworkNotFound.as_str(), "Network not found");
    assert_eq!(WifiError::NetworkNotFound.code(), 0x001F);
}

#[test]
fn test_error_equality() {
    assert_eq!(WifiError::Timeout, WifiError::Timeout);
    assert_ne!(WifiError::Timeout, WifiError::NotConnected);
}

#[test]
fn test_error_copy() {
    let err1 = WifiError::RfKill;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_error_clone() {
    let err1 = WifiError::ScanFailed;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_error_debug() {
    let err = WifiError::Timeout;
    let debug_str = format!("{:?}", err);
    assert_eq!(debug_str, "Timeout");
}

#[test]
fn test_error_display() {
    let err = WifiError::Timeout;
    let display_str = format!("{}", err);
    assert_eq!(display_str, "Operation timeout");
}

#[test]
fn test_error_codes_unique() {
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
            assert_ne!(errors[i].code(), errors[j].code());
        }
    }
}

#[test]
fn test_all_errors_have_message() {
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
        assert!(!err.as_str().is_empty());
    }
}
