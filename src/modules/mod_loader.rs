//! NØNOS Secure Modular Loader
//!
//! Zero-trust module loader for NØNOS runtime.
//! Responsible for manifest validation, signer auth, capability tokenization,
//! queueing, and secure capsule admission into the ZeroState VM.

use crate::log::logger::{log_info, log_warn};
use crate::modules::auth::{authenticate_manifest, AuthResult};
use crate::modules::manifest::ModuleManifest;
use crate::modules::mod_runner::launch_module;
use crate::modules::registry::register_module_instance;
use crate::syscall::capabilities::CapabilityToken;

use crate::time::current_uptime;
use alloc::{format, vec::Vec};
use core::time::Duration;
use spin::Mutex;

const MAX_VERIFIED_QUEUE: usize = 32;

/// Verified module queue entry
struct VerifiedModule {
    manifest: &'static ModuleManifest,
    token: CapabilityToken,
    timestamp: Duration,
}

/// Global loader state (mutex-protected)
struct LoaderState {
    queue: Vec<VerifiedModule>,
    rejected_count: usize,
}

static MODULE_LOADER: Mutex<LoaderState> =
    Mutex::new(LoaderState { queue: Vec::new(), rejected_count: 0 });

/// Initialize secure loader
pub fn init_module_loader() {
    log_info!("{}: {}", "mod_loader", "Secure loader initialized");
}

/// Perform secure manifest verification and queue module
pub fn verify_and_queue(manifest: &'static ModuleManifest) -> Result<(), &'static str> {
    let mut state = MODULE_LOADER.lock();

    if state.queue.len() >= MAX_VERIFIED_QUEUE {
        return Err("Queue full — denial of service guard");
    }

    match authenticate_manifest(manifest) {
        AuthResult::Verified(token) => {
            let cap_count = token.permissions.len();
            let entry = VerifiedModule {
                manifest,
                token,
                timestamp: Duration::from_secs(current_uptime()),
            };
            state.queue.push(entry);

            log_info!(
                "mod_loader: Accepted module '{}' queued with {} caps",
                manifest.name,
                cap_count
            );

            Ok(())
        }
        AuthResult::Rejected(reason) => {
            state.rejected_count += 1;
            log_warn!("{}: {}", "mod_loader", &format!("Rejected '{}': {}", manifest.name, reason));
            Err(reason)
        }
    }
}

/// Attempt to launch oldest queued verified module
pub fn admit_next_module() -> Result<(), &'static str> {
    let mut state = MODULE_LOADER.lock();

    if state.queue.is_empty() {
        return Err("No verified modules pending");
    }

    let VerifiedModule { manifest, token, .. } = state.queue.remove(0);
    let instance = launch_module(manifest, token.clone())?;

    register_module_instance(manifest.name, &instance);
    Ok(())
}

/// For CLI telemetry: get number of rejections so far
pub fn rejected_count() -> usize {
    MODULE_LOADER.lock().rejected_count
}

/// For CLI/REPL usage: get snapshot of pending queue
pub fn queued_modules() -> Vec<&'static str> {
    MODULE_LOADER.lock().queue.iter().map(|entry| entry.manifest.name).collect()
}

/// Result of module load operation
pub enum ModuleLoadResult {
    Queued,
    Launched,
    Rejected(&'static str),
}

/// Load a core module (used during boot)
pub fn load_core_module(
    manifest: &'static ModuleManifest,
) -> Result<ModuleLoadResult, &'static str> {
    verify_and_queue(manifest)?;

    // For core modules, immediately admit them
    match admit_next_module() {
        Ok(_) => Ok(ModuleLoadResult::Launched),
        Err(_) => Ok(ModuleLoadResult::Queued),
    }
}
