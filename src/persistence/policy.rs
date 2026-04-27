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

use super::consent::{has_consent, ConsentScope};
use core::sync::atomic::{AtomicU8, Ordering};

/// # Safety
/// PersistencePolicy controls what data can be persisted to disk/UEFI.
/// Default is Ephemeral - nothing persists without explicit consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PersistencePolicy {
    Ephemeral = 0,
    UserDataOnly = 1,
    SystemAndUser = 2,
}

/// # Safety
/// Global policy defaults to Ephemeral. Must be explicitly changed
/// with user consent to allow any persistence.
static CURRENT_POLICY: AtomicU8 = AtomicU8::new(PersistencePolicy::Ephemeral as u8);

impl PersistencePolicy {
    pub fn current() -> Self {
        match CURRENT_POLICY.load(Ordering::Acquire) {
            1 => Self::UserDataOnly,
            2 => Self::SystemAndUser,
            _ => Self::Ephemeral,
        }
    }

    /// # Safety
    /// Setting policy requires explicit user consent. Cannot elevate
    /// policy without consent for the target level.
    pub fn set(policy: Self) -> Result<(), &'static str> {
        let scope = match policy {
            Self::Ephemeral => {
                CURRENT_POLICY.store(policy as u8, Ordering::Release);
                return Ok(());
            }
            Self::UserDataOnly => ConsentScope::UserData,
            Self::SystemAndUser => ConsentScope::SystemData,
        };

        if !has_consent(scope) {
            return Err("persistence requires explicit user consent");
        }

        CURRENT_POLICY.store(policy as u8, Ordering::Release);
        Ok(())
    }

    pub fn allows_user_data(&self) -> bool {
        matches!(self, Self::UserDataOnly | Self::SystemAndUser)
    }

    pub fn allows_system_data(&self) -> bool {
        matches!(self, Self::SystemAndUser)
    }
}

/// # Safety
/// Checks if persistence is allowed for given scope. Returns false
/// if policy is Ephemeral or consent not granted.
pub fn check_persistence_allowed(scope: ConsentScope) -> bool {
    let policy = PersistencePolicy::current();

    match scope {
        ConsentScope::UserData => policy.allows_user_data() && has_consent(scope),
        ConsentScope::SystemData => policy.allows_system_data() && has_consent(scope),
        ConsentScope::UefiVariables => policy.allows_system_data() && has_consent(scope),
    }
}
