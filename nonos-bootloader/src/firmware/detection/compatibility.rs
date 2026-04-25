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

use super::hardware::HardwareDevice;
use super::version::FirmwareVersion;

#[derive(Debug, Clone)]
pub struct FirmwareRequirements { pub min_version: FirmwareVersion, pub max_version: FirmwareVersion, pub required_features: u32, pub hardware_revision_min: u8, pub memory_requirements: u64 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityResult { Compatible, IncompatibleVersion, IncompatibleHardware, InsufficientMemory, MissingFeatures, UnsupportedDevice }

pub fn check_firmware_compatibility(device: &HardwareDevice, firmware_data: &[u8], requirements: &FirmwareRequirements) -> CompatibilityResult {
    if device.revision < requirements.hardware_revision_min { return CompatibilityResult::IncompatibleHardware; }
    let firmware_version = extract_firmware_version(firmware_data);
    if !is_version_compatible(&firmware_version, requirements) { return CompatibilityResult::IncompatibleVersion; }
    let firmware_features = extract_firmware_features(firmware_data);
    if !check_feature_compatibility(firmware_features, requirements.required_features) { return CompatibilityResult::MissingFeatures; }
    if !check_memory_requirements(firmware_data, requirements.memory_requirements) { return CompatibilityResult::InsufficientMemory; }
    if !is_device_supported(device) { return CompatibilityResult::UnsupportedDevice; }
    CompatibilityResult::Compatible
}

impl Default for FirmwareRequirements {
    fn default() -> Self { Self { min_version: FirmwareVersion { major: 1, minor: 0, patch: 0, build: 0 }, max_version: FirmwareVersion { major: 99, minor: 99, patch: 99, build: 9999 }, required_features: 0, hardware_revision_min: 0, memory_requirements: 1024 * 1024 } }
}

fn extract_firmware_version(data: &[u8]) -> FirmwareVersion {
    if data.len() < 16 { return FirmwareVersion::default(); }
    let major = data[8];
    let minor = data[9];
    let patch = u16::from_le_bytes([data[10], data[11]]);
    let build = u16::from_le_bytes([data[12], data[13]]);
    FirmwareVersion { major, minor, patch, build }
}

fn extract_firmware_features(data: &[u8]) -> u32 {
    if data.len() < 20 { return 0; }
    u32::from_le_bytes([data[16], data[17], data[18], data[19]])
}

fn is_version_compatible(version: &FirmwareVersion, requirements: &FirmwareRequirements) -> bool {
    version.major >= requirements.min_version.major && version.major <= requirements.max_version.major && version.minor >= requirements.min_version.minor
}

fn check_feature_compatibility(firmware_features: u32, required_features: u32) -> bool { (firmware_features & required_features) == required_features }
fn check_memory_requirements(firmware_data: &[u8], required_memory: u64) -> bool { firmware_data.len() as u64 <= required_memory }
fn is_device_supported(device: &HardwareDevice) -> bool { device.vendor_id != 0 && device.device_id != 0 }