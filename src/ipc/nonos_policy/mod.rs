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

//! IPC Policy Engine
//!
//! Capability-based authorization for inter-process communication with:
//! - Per-module policy configuration
//! - Rate limiting
//! - Security level enforcement
//! - Mandatory encryption routes
//! - Audit trail for violations
//!
//! # Policy Enforcement
//!
//! Messages are validated against:
//! 1. Token validity (signature, expiry)
//! 2. Send/receive capabilities
//! 3. Message size limits (global and per-module)
//! 4. Destination restrictions (allow/block lists)
//! 5. Kernel access permissions
//! 6. Security level requirements
//! 7. Encryption requirements for sensitive routes
//! 8. Rate limits
//!
//! # Usage
//!
//! ```ignore
//! // Register a module policy
//! get_policy().register_module("my_module", ModulePolicy::default());
//!
//! // Check message authorization
//! if get_policy().allow_message(&envelope, &token) {
//!     // Send message
//! }
//! ```

mod capability;
mod engine;
mod error;
mod module_policy;
mod violation;

// Re-export public API
pub use capability::IpcCapability;
pub use engine::{get_policy, init_default_policies, IpcPolicy, PolicyStatsSnapshot, ACTIVE_POLICY};
pub use error::PolicyError;
pub use module_policy::ModulePolicy;
pub use violation::PolicyViolation;
