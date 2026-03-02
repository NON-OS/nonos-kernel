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


use alloc::string::String;
use crate::crypto::nonos_zk::AttestationProof;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Verified,
    VerifiedPqc,
    Attested,
    Failed(String),
}

impl AuthResult {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Verified | Self::VerifiedPqc | Self::Attested)
    }

    pub fn security_level(&self) -> SecurityLevel {
        match self {
            Self::VerifiedPqc => SecurityLevel::PostQuantum,
            Self::Attested => SecurityLevel::Attested,
            Self::Verified => SecurityLevel::Classical,
            Self::Failed(_) => SecurityLevel::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    None = 0,
    Classical = 1,
    PostQuantum = 2,
    Attested = 3,
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub verified: bool,
    pub pqc_verified: bool,
    pub attestation_chain: Option<AttestationProof>,
    pub failure_reason: Option<String>,
}

impl AuthContext {
    pub fn new() -> Self {
        Self {
            verified: false,
            pqc_verified: false,
            attestation_chain: None,
            failure_reason: None,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.verified || self.pqc_verified || self.attestation_chain.is_some()
    }

    pub fn security_level(&self) -> SecurityLevel {
        if self.attestation_chain.is_some() {
            SecurityLevel::Attested
        } else if self.pqc_verified {
            SecurityLevel::PostQuantum
        } else if self.verified {
            SecurityLevel::Classical
        } else {
            SecurityLevel::None
        }
    }

    pub fn with_failure(mut self, reason: impl Into<String>) -> Self {
        self.failure_reason = Some(reason.into());
        self
    }

    pub fn with_classical_verified(mut self) -> Self {
        self.verified = true;
        self
    }

    pub fn with_pqc_verified(mut self) -> Self {
        self.pqc_verified = true;
        self
    }

    pub fn with_attestation(mut self, proof: AttestationProof) -> Self {
        self.attestation_chain = Some(proof);
        self
    }
}

impl Default for AuthContext {
    fn default() -> Self {
        Self::new()
    }
}
