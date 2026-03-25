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

/// Full root CA trust anchor with DER-encoded fields for browser-grade
/// chain building (issuer DN matching + signature verification).
#[derive(Clone, Copy)]
pub struct TrustedRootCa {
    /// Human-readable CA name (e.g. "ISRG Root X1")
    pub name: &'static str,
    /// DER-encoded Subject Distinguished Name (for issuer DN matching)
    pub subject_der: &'static [u8],
    /// DER-encoded SubjectPublicKeyInfo (for signature verification)
    pub spki_der: &'static [u8],
    /// SHA-256 hash of spki_der (backward compat / fast pre-filter)
    pub spki_sha256: [u8; 32],
    /// Subject Key Identifier extension value (for AKI→SKI matching)
    pub ski: Option<&'static [u8]>,
}
