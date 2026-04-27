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

#[derive(Debug, Clone)]
pub struct SecureBootStatus {
    pub enabled: bool,
    pub setup_mode: bool,
    pub has_pk: bool,
    pub has_kek: bool,
    pub has_db: bool,
    pub has_dbx: bool,
    pub db_entry_count: usize,
    pub dbx_entry_count: usize,
}

impl SecureBootStatus {
    pub fn is_fully_configured(&self) -> bool {
        self.enabled && self.has_pk && self.has_kek && self.has_db
    }

    pub fn can_modify_keys(&self) -> bool {
        self.setup_mode
    }
}

impl Default for SecureBootStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            setup_mode: true,
            has_pk: false,
            has_kek: false,
            has_db: false,
            has_dbx: false,
            db_entry_count: 0,
            dbx_entry_count: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    Allowed,
    NotInDatabase,
    Revoked,
    SecureBootDisabled,
}
