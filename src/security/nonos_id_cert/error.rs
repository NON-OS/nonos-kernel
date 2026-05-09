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
pub enum IdCertDecodeError {
    UnexpectedEof,
    TrailingBytes,
    SchemaVersion,
    NamespaceGlobCount,
    NamespaceGlobLen,
    NamespaceGlobNotUtf8,
    MetadataLen,
    MetadataNotUtf8,
    ValidityWindow,
    PublisherKeyCount,
    PublisherKeysPerAlg,
    TrustAnchorSignatureCount,
    PubkeyLen { expected: usize, got: usize },
    SigLen { expected: usize, got: usize },
    Alg(AlgIdError),
}

impl From<AlgIdError> for IdCertDecodeError {
    fn from(e: AlgIdError) -> Self {
        Self::Alg(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdCertVerifyError {
    Decode(IdCertDecodeError),
    TrustAnchorPolicy,
    TrustAnchorBadSig(AlgId),
    EpochStale,
    Revoked,
    NonosIdRevoked,
    Expired,
    NotYetValid,
}

impl From<IdCertDecodeError> for IdCertVerifyError {
    fn from(e: IdCertDecodeError) -> Self {
        Self::Decode(e)
    }
}
