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

mod checks;
mod tokens;

pub use crate::capabilities::{
    Capability, CapabilityToken, create_token, sign_token, verify_token, revoke_token, has_signing_key, roles,
    delegation, audit, resource, multisig, chain,
};

pub use tokens::{
    current_caps, current_caps_or_default, mint_process_token, revoke_process_token, is_token_valid, init_capabilities,
};

pub use delegation::{Delegation, create_delegation, sign_delegation, verify_delegation};
pub use audit::{AuditEntry, log_use, get_log};
pub use resource::{ResourceQuota, ResourceToken, create_resource_token, sign_resource_token, verify_resource_token};
pub use multisig::{MultiSigToken, create_multisig_token, add_signature, verify_multisig};
pub use chain::CapabilityChain;
pub use roles::{KERNEL, SYSTEM_SERVICE, SANDBOXED_MOD};
