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


use crate::modules::nonos_module_loader::{load_module, unload_module, NonosModuleType};
use crate::modules::nonos_auth::authenticate_module;
use crate::modules::nonos_sandbox::setup_sandbox;
use crate::modules::nonos_registry::register_module;
use crate::modules::nonos_mod_runner::{stop_module_runtime, start_module_runtime};
use super::types::{LoaderPolicy, LoaderRequest};
use super::error::{LoaderError, LoaderResult};

pub fn load(request: LoaderRequest, policy: &LoaderPolicy) -> LoaderResult<u64> {
    if policy.privacy_enforced && request.manifest.privacy_policy != policy.required_privacy {
        return Err(LoaderError::PrivacyPolicyMismatch);
    }

    if policy.enforce_attestation && !request.manifest.verify_attestation() {
        return Err(LoaderError::AttestationFailed);
    }

    if policy.enforce_capabilities && request.manifest.capabilities.is_empty() {
        return Err(LoaderError::NoCapabilities);
    }

    let auth = authenticate_module(
        &request.code,
        &request.ed25519_signature,
        &request.ed25519_pubkey,
        request.pqc_signature.as_deref(),
        request.pqc_pubkey.as_deref(),
        None, // Attestation handled above via manifest
    );

    if !auth.verified && !auth.pqc_verified {
        return Err(LoaderError::AuthenticationFailed);
    }

    register_module(&request.manifest).map_err(|_| LoaderError::RegistrationFailed)?;

    let module_id = load_module(
        &request.manifest.name,
        NonosModuleType::Application,
        request.code,
        &request.ed25519_signature,
    )
    .map_err(|_| LoaderError::LoadFailed)?;

    if let Some(ref sandbox_cfg) = policy.sandbox_config {
        setup_sandbox(module_id, sandbox_cfg).map_err(|_| LoaderError::SandboxSetupFailed)?;
    }

    start_module_runtime(module_id).map_err(|_| LoaderError::RuntimeStartFailed)?;

    Ok(module_id)
}

pub fn unload(module_id: u64) -> LoaderResult<()> {
    stop_module_runtime(module_id).map_err(|_| LoaderError::RuntimeStopFailed)?;
    unload_module(module_id).map_err(|_| LoaderError::UnloadFailed)?;
    Ok(())
}
