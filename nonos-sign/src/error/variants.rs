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

#[derive(Debug)]
pub enum SignError {
    Usage(String),
    Io(std::io::Error),
    InvalidHex(String),
    Base64(String),

    UnknownAlgId(u8),
    UnsupportedAlg(String),
    SeedKeygenUnsupported(&'static str),
    PqcleanFailed(&'static str),
    PubkeyDecode,
    InvalidSeedLength { alg: &'static str, expected: usize, actual: usize },
    InvalidPubkeyLength { alg: &'static str, expected: usize, actual: usize },
    InvalidSignatureLength { alg: &'static str, expected: usize, actual: usize },

    DeriveFieldTooLong { field: &'static str, len: usize },

    TaKeyCount(usize),
    TaPubkeyLen { alg: &'static str, expected: usize, got: usize },
    TaValidFromZero,
    TaValidWindow { from: u64, until: u64 },
    TaRevokedCertSerialCount(usize),
    TaRevokedNonosIdCount(usize),
    TaRevokedPublisherKeyIdCount(usize),

    CertNamespaceGlobCount(usize),
    CertNamespaceGlobLen(usize),
    CertMetadataLen(usize),
    CertValidWindow { from: u64, until: u64 },
    CertPublisherKeyCount(usize),
    CertPubkeyLen { alg: &'static str, expected: usize, got: usize },
    CertKeysPerAlg(&'static str),
    CertTrustAnchorSigCount(usize),
    CertSigLen { alg: &'static str, expected: usize, got: usize },

    ManifestNamespaceLen(usize),
    ManifestTargetTripleLen(usize),
    ManifestOverlappingCaps,
    ManifestEndpointCount(usize),
    ManifestEndpointNameLen(usize),
    ManifestDuplicateEndpoint(String),
    ManifestPublisherSigCount(usize),
    ManifestSigLen { alg: &'static str, expected: usize, got: usize },

    KeyFileShape(String),
    SeedSourceMissing(String),
    EndpointSpec(String),

    VerifyTrustAnchorPolicy,
    VerifyTrustAnchorBadSig(&'static str),
    VerifyEpochStale,
    VerifyCertRevoked,
    VerifyNonosIdRevoked,
    VerifyExpired,
    VerifyNotYetValid,
    VerifyNonosIdCertIdMismatch,
    VerifyNamespaceOutsideCert,
    VerifyCapsExceedCeiling,
    VerifyPublisherPolicy,
    VerifyPublisherKeyRevoked,
    VerifyPublisherBadSig(&'static str),
    VerifyPayloadHashMismatch,
    VerifyTargetTripleMismatch,
    VerifyEndpointDeclDrift,
}

impl From<std::io::Error> for SignError {
    fn from(e: std::io::Error) -> Self {
        SignError::Io(e)
    }
}
