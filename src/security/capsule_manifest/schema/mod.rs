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

mod constants;
mod endpoint;
mod manifest;
mod publisher_sig;
mod version;

pub use constants::{
    MANIFEST_SCHEMA_VERSION, MAX_ENDPOINTS, MAX_ENDPOINT_NAME_LEN, MAX_NAMESPACE_LEN,
    MAX_PUBLISHER_SIGNATURES, MAX_TARGET_TRIPLE_LEN, NONOS_ID_CERT_ID_LEN, PAYLOAD_HASH_LEN,
    PUBLISHER_KEY_ID_LEN,
};
pub use endpoint::{EndpointDecl, EndpointKind};
pub use manifest::{CapsuleManifest, VerifiedManifest};
pub use publisher_sig::PublisherSignature;
pub use version::Version;
