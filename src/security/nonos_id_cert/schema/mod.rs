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

mod cert;
mod constants;
mod glob_match;
mod sub;

pub use cert::{NonosIdCertificate, VerifiedNonosId};
pub use constants::{
    ID_CERT_SCHEMA_VERSION, MAX_KEYS_PER_ALG, MAX_METADATA_LEN, MAX_NAMESPACE_GLOBS,
    MAX_NAMESPACE_GLOB_LEN, MAX_PUBLISHER_KEYS, MAX_TRUST_ANCHOR_SIGNATURES, NONOS_ID_LEN,
    PUBLISHER_KEY_ID_LEN,
};
pub use sub::{NamespaceGlob, PublisherKey, TrustAnchorSignature};
