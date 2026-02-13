// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkError {
    ProofTooLarge,
    ProofSizeInvalid,
    InputsTooLarge,
    InputsMisaligned,
    InputsCountMismatch,
    ManifestMissing,
    ManifestTooLarge,
    CommitmentMismatch,
    UnknownProgramHash,
    VerifyingKeyEmpty,
    VerifyingKeyDeserialize,
    ProofDeserializeA,
    ProofDeserializeB,
    ProofDeserializeC,
    BackendVerifyFailed,
    BackendUnsupported,
    SectionTooSmall,
    HeaderTruncated,
    OffsetRange,
    HashOffsets,
    Internal,
}

impl ZkError {
    pub fn as_str(self) -> &'static str {
        use ZkError::*;
        match self {
            ProofTooLarge => "zk: proof too large",
            ProofSizeInvalid => "zk: proof size invalid",
            InputsTooLarge => "zk: inputs too large",
            InputsMisaligned => "zk: inputs not multiple of 32",
            InputsCountMismatch => "zk: public inputs count mismatch",
            ManifestMissing => "zk: manifest missing for binding",
            ManifestTooLarge => "zk: manifest too large",
            CommitmentMismatch => "zk: commitment mismatch",
            UnknownProgramHash => "zk: unknown program hash (no VK)",
            VerifyingKeyEmpty => "zk: VK empty",
            VerifyingKeyDeserialize => "zk: VK deserialize failed",
            ProofDeserializeA => "zk: A deserialize failed",
            ProofDeserializeB => "zk: B deserialize failed",
            ProofDeserializeC => "zk: C deserialize failed",
            BackendVerifyFailed => "zk: groth16 verify failed",
            BackendUnsupported => "zk: no backend (enable zk-groth16)",
            SectionTooSmall => "zk: section too small",
            HeaderTruncated => "zk: header truncated",
            OffsetRange => "zk: offset range invalid",
            HashOffsets => "zk: hash offsets out of range",
            Internal => "zk: internal error",
        }
    }

    pub fn category(self) -> &'static str {
        use ZkError::*;
        match self {
            ProofTooLarge | ProofSizeInvalid => "proof",
            InputsTooLarge | InputsMisaligned | InputsCountMismatch => "inputs",
            ManifestMissing | ManifestTooLarge => "manifest",
            CommitmentMismatch => "commitment",
            UnknownProgramHash | VerifyingKeyEmpty | VerifyingKeyDeserialize => "vk",
            ProofDeserializeA | ProofDeserializeB | ProofDeserializeC => "deserialize",
            BackendVerifyFailed | BackendUnsupported => "backend",
            SectionTooSmall | HeaderTruncated | OffsetRange | HashOffsets => "parse",
            Internal => "internal",
        }
    }

    pub fn is_recoverable(self) -> bool {
        use ZkError::*;
        match self {
            UnknownProgramHash | ManifestMissing => true,
            // Most errors are not recoverable
            _ => false,
        }
    }
}
