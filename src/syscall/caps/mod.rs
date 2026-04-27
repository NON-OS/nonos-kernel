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
    audit, chain, create_token, delegation, has_signing_key, multisig, resource, revoke_token,
    roles, sign_token, verify_token, Capability, CapabilityToken,
};

pub use tokens::{
    current_caps, current_caps_or_default, init_capabilities, is_token_valid, mint_process_token,
    revoke_process_token,
};

pub use audit::{get_log, log_use, AuditEntry};
pub use chain::CapabilityChain;
pub use delegation::{create_delegation, sign_delegation, verify_delegation, Delegation};
pub use multisig::{add_signature, create_multisig_token, verify_multisig, MultiSigToken};
pub use resource::{
    create_resource_token, sign_resource_token, verify_resource_token, ResourceQuota, ResourceToken,
};
pub use roles::{KERNEL, SANDBOXED_MOD, SYSTEM_SERVICE};
