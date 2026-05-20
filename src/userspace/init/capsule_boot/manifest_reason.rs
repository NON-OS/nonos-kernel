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

use crate::security::capsule_manifest::ManifestVerifyError;

pub(super) fn message(prefix: &str, reason: ManifestVerifyError) -> alloc::string::String {
    let why = match reason {
        ManifestVerifyError::Decode(d) => {
            return alloc::format!("{}: capsule manifest decode failed ({:?})", prefix, d);
        }
        ManifestVerifyError::NonosIdCertIdMismatch => {
            "manifest references a different cert than the one provided"
        }
        ManifestVerifyError::NamespaceOutsideCert => {
            "manifest namespace is not authorised by the cert's namespace globs"
        }
        ManifestVerifyError::CapsExceedCeiling => {
            "requested capability mask exceeds the cert's caps ceiling"
        }
        ManifestVerifyError::PublisherPolicy => "publisher signature policy not satisfied",
        ManifestVerifyError::PublisherKeyRevoked => "publisher key appears on the revocation list",
        ManifestVerifyError::PublisherBadSig(alg) => {
            return alloc::format!(
                "{}: publisher signature on manifest is bad ({:?})",
                prefix,
                alg,
            );
        }
        ManifestVerifyError::PayloadHashMismatch => {
            "embedded ELF hash differs from manifest expected hash (rebuild + re-sign)"
        }
        ManifestVerifyError::TargetTripleMismatch => {
            "target triple in manifest does not match the running capsule binary"
        }
        ManifestVerifyError::EndpointDeclDrift => {
            "endpoint declarations drifted between manifest and spawn spec"
        }
        ManifestVerifyError::GrantOutsideManifest => {
            "broker grant lives outside the manifest's allowed surface"
        }
    };
    alloc::format!("{}: capsule manifest rejected ({})", prefix, why)
}
