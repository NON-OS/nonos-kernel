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

use nonos_libc::mk_time_millis;
use spin::Mutex;

use super::error::CredentialError;
use super::types::StoredCredential;
use super::verify;

static CREDENTIAL: Mutex<Option<StoredCredential>> = Mutex::new(None);

pub fn install(body: &[u8]) -> Result<(), CredentialError> {
    let credential = verify::parse(body, now_ms()?)?;
    *CREDENTIAL.lock() = Some(credential);
    Ok(())
}

pub fn material() -> Result<[u8; 32], CredentialError> {
    let now = now_ms()?;
    let mut guard = CREDENTIAL.lock();
    let Some(credential) = *guard else {
        return Err(CredentialError::Missing);
    };
    if credential.expiry_ms <= now {
        *guard = None;
        return Err(CredentialError::Expired);
    }
    match super::super::trusted_authority(&credential.issuer) {
        Some(true) => {}
        Some(false) => return Err(CredentialError::UntrustedAuthority),
        None => return Err(CredentialError::NoAuthority),
    }
    Ok(credential.material)
}

fn now_ms() -> Result<u64, CredentialError> {
    let now = mk_time_millis();
    if now < 0 {
        return Err(CredentialError::Clock);
    }
    Ok(now as u64)
}
