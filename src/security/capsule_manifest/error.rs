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

use crate::crypto::asymmetric::alg_id::{AlgId, AlgIdError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestDecodeError {
    UnexpectedEof,
    TrailingBytes,
    SchemaVersion,
    NamespaceLen,
    NamespaceNotUtf8,
    TargetTripleLen,
    TargetTripleNotUtf8,
    OverlappingCaps,
    EndpointCount,
    EndpointKind(u8),
    EndpointNameLen,
    EndpointNameNotUtf8,
    DuplicateEndpoint,
    PublisherSignatureCount,
    SigLen { expected: usize, got: usize },
    Alg(AlgIdError),
}

impl From<AlgIdError> for ManifestDecodeError {
    fn from(e: AlgIdError) -> Self {
        Self::Alg(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestVerifyError {
    Decode(ManifestDecodeError),
    NonosIdCertIdMismatch,
    NamespaceOutsideCert,
    CapsExceedCeiling,
    PublisherPolicy,
    PublisherKeyRevoked,
    PublisherBadSig(AlgId),
    PayloadHashMismatch,
    TargetTripleMismatch,
    EndpointDeclDrift,
    GrantOutsideManifest,
}

impl From<ManifestDecodeError> for ManifestVerifyError {
    fn from(e: ManifestDecodeError) -> Self {
        Self::Decode(e)
    }
}
