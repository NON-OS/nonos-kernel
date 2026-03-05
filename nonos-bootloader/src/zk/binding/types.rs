// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

/// Domain separator for capsule commitment
pub const DS_COMMITMENT: &str = "NONOS:CAPSULE:COMMITMENT:v1";

/// Maximum manifest size (128 KB)
pub const MAX_MANIFEST_SIZE: usize = 128 * 1024;

/// Binding input source for commitment computation
#[derive(Debug, Clone)]
pub enum BindingInput<'a> {
    /// Bind to public inputs directly
    PublicInputs(&'a [u8]),
    /// Bind to manifest bytes
    Manifest(&'a [u8]),
}

impl<'a> BindingInput<'a> {
    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            BindingInput::PublicInputs(b) => b,
            BindingInput::Manifest(b) => b,
        }
    }

    /// Check if binding uses manifest
    pub fn is_manifest(&self) -> bool {
        matches!(self, BindingInput::Manifest(_))
    }
}
