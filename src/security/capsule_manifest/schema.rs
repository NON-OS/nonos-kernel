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

extern crate alloc;

use alloc::vec::Vec;

// Bumped when the wire format changes. The kernel refuses any other
// version; the userland installer is responsible for translation.
pub const MANIFEST_SCHEMA_VERSION: u16 = 1;

// Maximum sizes the kernel will accept. Keep them small — capsules
// declaring more endpoints than this almost certainly want a broker
// capsule between them and the rest of the system.
pub const MAX_NAMESPACE_LEN: usize = 96;
pub const MAX_ENDPOINTS: usize = 16;
pub const MAX_ENDPOINT_NAME_LEN: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Debug, Clone)]
pub struct EndpointDecl {
    pub name: [u8; MAX_ENDPOINT_NAME_LEN],
    pub name_len: u8,
}

impl EndpointDecl {
    pub fn as_str(&self) -> &str {
        let n = self.name_len as usize;
        // Decode rejects non-UTF8 endpoint names, so this is safe at
        // construction time.
        core::str::from_utf8(&self.name[..n]).unwrap_or("")
    }
}

// The fields the kernel verifies and acts on. `app_namespace` and
// `version` participate in `capsule_id` derivation but are otherwise
// opaque to the kernel.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub schema_version: u16,
    pub publisher_pubkey: [u8; 32],
    pub app_namespace: [u8; MAX_NAMESPACE_LEN],
    pub app_namespace_len: u8,
    pub version: Version,
    pub package_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub required_caps: u64,
    pub optional_caps: u64,
    pub endpoints: Vec<EndpointDecl>,
    pub signature: [u8; 64],
}

impl Manifest {
    pub fn namespace_str(&self) -> &str {
        let n = self.app_namespace_len as usize;
        core::str::from_utf8(&self.app_namespace[..n]).unwrap_or("")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    SchemaVersion,
    NamespaceTooLong,
    TooManyEndpoints,
    EndpointNameTooLong,
    EndpointNameNotUtf8,
    DuplicateEndpoint,
    OverlappingCaps,
    UnknownCap,
}
