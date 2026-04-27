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

use super::super::types::X509Certificate;
use super::super::x509_core::X509;
use alloc::string::String;
use alloc::vec::Vec;

impl X509 {
    /// Returns DNS names from the parsed SAN extension, or None if absent.
    pub fn get_san_dns_names(cert: &X509Certificate) -> Option<Vec<String>> {
        if cert.extensions.san_dns_names.is_empty() {
            None
        } else {
            Some(cert.extensions.san_dns_names.clone())
        }
    }

    /// Returns true if the certificate has a SAN extension (even if empty).
    /// Used to implement RFC 6125: when SAN is present, CN must not be checked.
    pub fn has_san_extension(cert: &X509Certificate) -> bool {
        !cert.extensions.san_dns_names.is_empty()
    }
}
