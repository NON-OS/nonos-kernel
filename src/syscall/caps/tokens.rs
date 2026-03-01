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

use crate::capabilities::{Capability, CapabilityToken, create_token, revoke_token, has_signing_key};

pub fn current_caps() -> Option<CapabilityToken> {
    let proc = crate::process::current_process()?;
    Some(proc.capability_token())
}

pub fn current_caps_or_default() -> CapabilityToken {
    current_caps().unwrap_or_else(|| CapabilityToken::empty())
}

pub fn mint_process_token(owner_module: u64, role: &[Capability], ttl_ms: Option<u64>) -> Result<CapabilityToken, &'static str> {
    create_token(owner_module, role, ttl_ms)
}

pub fn revoke_process_token(token: &CapabilityToken) {
    revoke_token(token.owner_module, token.nonce);
}

pub fn is_token_valid(token: &CapabilityToken) -> bool {
    token.is_valid()
}

pub fn init_capabilities() -> Result<(), &'static str> {
    if !has_signing_key() {
        return Err("capabilities: signing key not set; call set_signing_key() at boot");
    }
    Ok(())
}
