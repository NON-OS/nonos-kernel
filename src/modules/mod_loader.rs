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
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;
use super::manifest::ModuleManifest;
use super::loader::{LoaderError, LoaderPolicy, load_with_policy, LoaderRequest};

static MODULE_LOADER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PENDING_MODULES: RwLock<Vec<&'static ModuleManifest>> = RwLock::new(Vec::new());

pub fn init_module_loader() {
    MODULE_LOADER_INITIALIZED.store(true, Ordering::SeqCst);
    super::loader::init_loader();
    super::runner::init_executor();
}

pub fn is_initialized() -> bool {
    MODULE_LOADER_INITIALIZED.load(Ordering::SeqCst)
}

pub fn verify_and_queue(manifest: &'static ModuleManifest) -> Result<(), LoaderError> {
    if manifest.name.is_empty() {
        return Err(LoaderError::EmptyName);
    }

    if !manifest.verify_attestation_chain() {
        return Err(LoaderError::AuthenticationFailed);
    }

    let mut pending = PENDING_MODULES.write();
    pending.push(manifest);

    Ok(())
}

pub fn load_queued_modules() -> Result<usize, LoaderError> {
    let pending: Vec<&'static ModuleManifest> = {
        let mut p = PENDING_MODULES.write();
        core::mem::take(&mut *p)
    };

    let mut loaded = 0;
    for manifest in pending {
        let request = LoaderRequest::new(&manifest.name, Vec::new());
        let policy = LoaderPolicy::default()
            .with_privacy(manifest.privacy_policy.clone());

        match load_with_policy(request, &policy) {
            Ok(_) => loaded += 1,
            Err(e) => {
                crate::log::logger::log_warn!("Failed to load module '{}': {:?}", manifest.name, e);
            }
        }
    }

    Ok(loaded)
}

pub fn get_pending_count() -> usize {
    PENDING_MODULES.read().len()
}
