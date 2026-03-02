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


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOperation {
    Create,
    Import,
    Export,
    Use,
    Rotate,
    Delete,
    Derive,
}

#[derive(Debug, Clone)]
pub struct KeyAuditEntry {
    pub timestamp: u64,
    pub operation: KeyOperation,
    pub key_id: u64,
    pub key_fingerprint: [u8; 32],
    pub caller_module: u64,
    pub success: bool,
}

impl KeyAuditEntry {
    pub fn new(
        operation: KeyOperation,
        key_id: u64,
        fingerprint: [u8; 32],
        caller: u64,
        success: bool,
    ) -> Self {
        Self {
            timestamp: crate::time::timestamp_secs(),
            operation,
            key_id,
            key_fingerprint: fingerprint,
            caller_module: caller,
            success,
        }
    }
}
