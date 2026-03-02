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


use alloc::vec::Vec;
use crate::modules::nonos_manifest::{ModuleManifest, PrivacyPolicy};
use crate::modules::nonos_sandbox::SandboxConfig;

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
            enforce_attestation: true,
            enforce_capabilities: false,
            sandbox_config: None,
        }
    }
}

impl LoaderPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_privacy(mut self, required: PrivacyPolicy) -> Self {
        self.privacy_enforced = true;
        self.required_privacy = required;
        self
    }

    pub fn without_privacy_enforcement(mut self) -> Self {
        self.privacy_enforced = false;
        self
    }

    pub fn with_attestation(mut self) -> Self {
        self.enforce_attestation = true;
        self
    }

    pub fn without_attestation(mut self) -> Self {
        self.enforce_attestation = false;
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
}

#[derive(Debug, Clone)]
pub struct LoaderRequest {
    pub manifest: ModuleManifest,
    pub code: Vec<u8>,
    pub ed25519_signature: [u8; 64],
    pub ed25519_pubkey: [u8; 32],
    pub pqc_signature: Option<Vec<u8>>,
    pub pqc_pubkey: Option<Vec<u8>>,
}

impl LoaderRequest {
    pub fn new(
        manifest: ModuleManifest,
        code: Vec<u8>,
        ed25519_signature: [u8; 64],
        ed25519_pubkey: [u8; 32],
    ) -> Self {
        Self {
            manifest,
            code,
            ed25519_signature,
            ed25519_pubkey,
            pqc_signature: None,
            pqc_pubkey: None,
        }
    }

    pub fn with_pqc(mut self, signature: Vec<u8>, pubkey: Vec<u8>) -> Self {
        self.pqc_signature = Some(signature);
        self.pqc_pubkey = Some(pubkey);
        self
    }
}
