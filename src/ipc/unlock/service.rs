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

use super::{cache, request, types::*};

pub fn init() {
    cache::init_cache();
    crate::sys::boot_log::ok("UNLOCK", "IPC service ready");
}

pub fn get_unlock_token(req: &UnlockRequest) -> Result<UnlockResponse, UnlockError> {
    let now = crate::time::unix_timestamp();
    if let Some(cached) = cache::get(&req.capsule_id, &req.wallet_addr) {
        if !cached.is_expired(now) {
            return Ok(cached);
        }
    }
    let response = request::request_unlock(req)?;
    request::verify_token(&response, now)?;
    cache::insert(req.capsule_id, req.wallet_addr, response.clone(), now);
    Ok(response)
}

pub fn refresh_token(
    capsule_id: &[u8; 32],
    wallet: &[u8; 20],
    caps: u64,
) -> Result<UnlockResponse, UnlockError> {
    cache::invalidate(capsule_id, wallet);
    let req = UnlockRequest::new(*capsule_id, *wallet, caps);
    get_unlock_token(&req)
}

pub fn revoke_token(capsule_id: &[u8; 32], wallet: &[u8; 20]) {
    cache::invalidate(capsule_id, wallet);
}

pub fn cleanup() {
    let now = crate::time::unix_timestamp();
    cache::cleanup_expired(now);
}

pub fn token_to_bytes(response: &UnlockResponse) -> [u8; 113] {
    let mut out = [0u8; 113];
    out[0..32].copy_from_slice(&response.token);
    out[32..64].copy_from_slice(&response.capsule_id);
    out[64..96].copy_from_slice(&response.manifest_hash);
    out[96..104].copy_from_slice(&response.approved_caps.to_le_bytes());
    out[104..112].copy_from_slice(&response.expires_at.to_le_bytes());
    out
}
