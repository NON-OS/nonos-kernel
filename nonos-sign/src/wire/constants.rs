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

pub const SCHEMA_TRUST_ANCHOR_POLICY: u16 = 1;
pub const SCHEMA_NONOS_ID_CERT: u16 = 2;
pub const SCHEMA_CAPSULE_MANIFEST: u16 = 3;

pub const NONOS_ID_LEN: usize = 32;
pub const PUBLISHER_KEY_ID_LEN: usize = 16;
pub const PAYLOAD_HASH_LEN: usize = 32;
pub const NONOS_ID_CERT_ID_LEN: usize = 32;

pub const MAX_TRUST_ANCHOR_KEYS: usize = 4;
pub const MAX_REVOKED_CERT_SERIALS: usize = 256;
pub const MAX_REVOKED_NONOS_IDS: usize = 64;
pub const MAX_REVOKED_PUBLISHER_KEY_IDS: usize = 256;

pub const MAX_NAMESPACE_GLOBS: usize = 8;
pub const MAX_NAMESPACE_GLOB_LEN: usize = 96;
pub const MAX_METADATA_LEN: usize = 256;
pub const MAX_PUBLISHER_KEYS: usize = 4;
pub const MAX_KEYS_PER_ALG: usize = 2;
pub const MAX_TRUST_ANCHOR_SIGNATURES: usize = 4;

pub const MAX_NAMESPACE_LEN: usize = 96;
pub const MAX_TARGET_TRIPLE_LEN: usize = 64;
pub const MAX_ENDPOINTS: usize = 16;
pub const MAX_ENDPOINT_NAME_LEN: usize = 48;
pub const MAX_PUBLISHER_SIGNATURES: usize = 4;
