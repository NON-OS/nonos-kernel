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

use core::sync::atomic::{AtomicBool, Ordering};
use super::constants::*;
use super::error::{LoaderError, LoaderResult};
use super::types::{LoaderPolicy, LoaderRequest};
use super::super::auth::authenticate_module;
use super::super::manifest::ModuleManifest;
use super::super::registry::{register_module, unregister_module};
use super::super::runner::{start_module, stop_module};
use super::super::sandbox::setup_sandbox;

static LOADER_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_loader() {
    LOADER_INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn load_module(image: &[u8], params: Option<&str>) -> LoaderResult<u64> {
    if image.len() < MODULE_HEADER_SIZE {
        return Err(LoaderError::ImageTooSmall);
    }

    if image.len() > MAX_MODULE_SIZE {
        return Err(LoaderError::ImageTooLarge);
    }

    let name_bytes = &image[MODULE_NAME_OFFSET..MODULE_NAME_OFFSET + MODULE_NAME_SIZE];
    let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(MODULE_NAME_SIZE);
    let name = core::str::from_utf8(&name_bytes[..name_len])
        .map_err(|_| LoaderError::InvalidName)?;

    if name.is_empty() {
        return Err(LoaderError::EmptyName);
    }

    let signature: [u8; 64] = image[MODULE_SIGNATURE_OFFSET..MODULE_SIGNATURE_OFFSET + MODULE_SIGNATURE_SIZE]
        .try_into()
        .map_err(|_| LoaderError::InvalidSignature)?;

    let code = &image[MODULE_HEADER_SIZE..];
    if code.is_empty() {
        return Err(LoaderError::EmptyCode);
    }

    let pubkey = extract_pubkey_from_header(image);
    let mut request = LoaderRequest::new(name, code.to_vec())
        .with_signature(signature, pubkey);

    if let Some(p) = params {
        request = request.with_params(p);
    }

    let policy = LoaderPolicy::default();

    load_with_policy(request, &policy)
}

pub fn load_with_policy(request: LoaderRequest, policy: &LoaderPolicy) -> LoaderResult<u64> {
    let manifest = ModuleManifest::new(&request.name, &request.code);
    if policy.privacy_enforced && manifest.privacy_policy != policy.required_privacy {
        return Err(LoaderError::PrivacyPolicyMismatch);
    }

    let auth = authenticate_module(
        &request.code,
        request.signature.as_ref(),
        request.pubkey.as_ref(),
        request.pqc_signature.as_deref(),
        request.pqc_pubkey.as_deref(),
        None,
    );

    if !auth.verified && request.is_signed() {
        return Err(LoaderError::AuthenticationFailed);
    }

    let module_id = register_module(&request.name, None)
        .map_err(|_| LoaderError::RegistrationFailed)?;

    if let Some(params) = request.params {
        super::super::registry::set_module_params(module_id, params).ok();
    }

    if let Some(ref sandbox_cfg) = policy.sandbox_config {
        setup_sandbox(module_id, sandbox_cfg)
            .map_err(|_| LoaderError::SandboxSetupFailed)?;
    }

    start_module(module_id)
        .map_err(|_| LoaderError::StartFailed)?;

    crate::log::logger::log_info!("Module loaded: {} (id={})", request.name, module_id);
    Ok(module_id)
}

fn extract_pubkey_from_header(image: &[u8]) -> [u8; 32] {
    let mut pubkey = [0u8; 32];
    if image.len() >= MODULE_PUBKEY_OFFSET + MODULE_PUBKEY_SIZE {
        pubkey.copy_from_slice(&image[MODULE_PUBKEY_OFFSET..MODULE_PUBKEY_OFFSET + MODULE_PUBKEY_SIZE]);
    }
    pubkey
}

pub fn unload_module(name: &str, _force: bool) -> LoaderResult<()> {
    let info = super::super::registry::get_module_info(name)
        .map_err(|_| LoaderError::ModuleNotFound)?;
    if info.state.is_active() {
        stop_module(info.id)
            .map_err(|_| LoaderError::StopFailed)?;
    }

    let _ = super::super::sandbox::destroy_sandbox(info.id);
    unregister_module(name)
        .map_err(|_| LoaderError::ModuleNotFound)?;

    crate::log::logger::log_info!("Module unloaded: {} (id={})", name, info.id);
    Ok(())
}
