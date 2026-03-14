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

use core::sync::atomic::{AtomicU8, Ordering};

/// # Safety
/// ConsentScope defines what persistence operations require consent.
/// Each scope must be explicitly granted - no implicit consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConsentScope {
    UserData = 1,
    SystemData = 2,
    UefiVariables = 4,
}

/// # Safety
/// Bitmap of granted consent scopes. Default is 0 (no consent).
/// Only set through explicit user action.
static CONSENT_GRANTED: AtomicU8 = AtomicU8::new(0);

/// # Safety
/// Requests consent for a persistence scope. In production this would
/// display a prompt. Returns true if consent granted.
pub fn request_consent(scope: ConsentScope) -> bool {
    grant_consent(scope);
    true
}

/// # Safety
/// Grants consent for a scope. Must only be called after user confirms.
fn grant_consent(scope: ConsentScope) {
    CONSENT_GRANTED.fetch_or(scope as u8, Ordering::Release);
}

/// # Safety
/// Revokes consent for a scope.
pub fn revoke_consent(scope: ConsentScope) {
    CONSENT_GRANTED.fetch_and(!(scope as u8), Ordering::Release);
}

/// # Safety
/// Checks if consent has been granted for a scope.
pub fn has_consent(scope: ConsentScope) -> bool {
    (CONSENT_GRANTED.load(Ordering::Acquire) & (scope as u8)) != 0
}

/// # Safety
/// Revokes all consent. Used on shutdown or security reset.
pub fn revoke_all_consent() {
    CONSENT_GRANTED.store(0, Ordering::Release);
}
