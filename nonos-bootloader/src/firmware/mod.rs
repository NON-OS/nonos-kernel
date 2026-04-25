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

pub mod cache;
pub mod detection;
pub mod error;
mod loader;
pub mod monitor;
pub mod quirks;
pub mod registry;
pub mod security;
mod types;
pub mod validation;

pub use cache::{MemoryCache, cache_firmware, compress_firmware, CacheResult, CompressionType};
pub use detection::{detect_hardware_devices, check_firmware_compatibility, parse_firmware_version, HardwareDevice, CompatibilityResult};
pub use error::{attempt_error_recovery, report_error, FirmwareError, ErrorSeverity, RecoveryStrategy};
pub use loader::{firmware_count, get_firmware, get_firmware_handoff, has_embedded_firmware};
pub use monitor::{check_firmware_health, collect_metrics, get_firmware_status, HealthStatus, FirmwareMetrics};
pub use quirks::{apply_mmap_quirks, detect_firmware_quirks, FirmwareQuirk, QuirkFlags};
pub use registry::{register_firmware, search_firmware, FirmwareDatabase, FirmwareMetadata, SearchQuery};
pub use security::{detect_threats, create_firmware_sandbox, log_security_event, ThreatLevel, SandboxConfig};
pub use types::{FirmwareEntry, FirmwareHandoff, FirmwareType, MAX_FIRMWARE_ENTRIES};
pub use validation::{validate_firmware_integrity, verify_signature, calculate_sha256, IntegrityResult, SignatureResult};

