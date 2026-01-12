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
use super::super::manifest::PrivacyPolicy;
use super::super::sandbox::SandboxConfig;

#[derive(Debug, Clone)]
pub struct LoaderPolicy {
    pub privacy_enforced: bool,
    pub required_privacy: PrivacyPolicy,
    pub enforce_attestation: bool,
    pub enforce_capabilities: bool,
    pub sandbox_config: Option<SandboxConfig>,
}

impl Default for LoaderPolicy {
    fn default() -> Self {
        Self {
            privacy_enforced: true,
            required_privacy: PrivacyPolicy::ZeroStateOnly,
            enforce_attestation: false,
            enforce_capabilities: false,
            sandbox_config: None,
        }
    }
}

impl LoaderPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_privacy(mut self, policy: PrivacyPolicy) -> Self {
        self.required_privacy = policy;
        self
    }

    pub fn with_attestation(mut self) -> Self {
        self.enforce_attestation = true;
        self
    }

    pub fn with_capabilities(mut self) -> Self {
        self.enforce_capabilities = true;
        self
    }

    pub fn with_sandbox(mut self, config: SandboxConfig) -> Self {
        self.sandbox_config = Some(config);
        self
    }

    pub fn without_privacy_enforcement(mut self) -> Self {
        self.privacy_enforced = false;
        self
    }
}

#[derive(Debug, Clone)]
pub struct LoaderRequest {
    pub name: alloc::string::String,
    pub code: Vec<u8>,
    pub params: Option<alloc::string::String>,
    pub signature: Option<[u8; 64]>,
    pub pubkey: Option<[u8; 32]>,
    pub pqc_signature: Option<Vec<u8>>,
    pub pqc_pubkey: Option<Vec<u8>>,
}

impl LoaderRequest {
    pub fn new(name: &str, code: Vec<u8>) -> Self {
        Self {
            name: alloc::string::String::from(name),
            code,
            params: None,
            signature: None,
            pubkey: None,
            pqc_signature: None,
            pqc_pubkey: None,
        }
    }

    pub fn with_params(mut self, params: &str) -> Self {
        self.params = Some(alloc::string::String::from(params));
        self
    }

    pub fn with_signature(mut self, signature: [u8; 64], pubkey: [u8; 32]) -> Self {
        self.signature = Some(signature);
        self.pubkey = Some(pubkey);
        self
    }

    pub fn with_pqc_signature(mut self, signature: Vec<u8>, pubkey: Vec<u8>) -> Self {
        self.pqc_signature = Some(signature);
        self.pqc_pubkey = Some(pubkey);
        self
    }

    pub fn code_size(&self) -> usize {
        self.code.len()
    }

    pub fn is_signed(&self) -> bool {
        self.signature.is_some() && self.pubkey.is_some()
    }
}
