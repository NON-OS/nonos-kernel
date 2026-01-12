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

extern crate alloc;

use super::serial::serial_print;
/// Initializes core kernel subsystems.
/// # SAFETY: Caller guarantees memory and interrupts are initialized
pub unsafe fn init_core_subsystems() -> Result<(), &'static str> {
    crate::log::logger::init();
    crate::log::info!("[BOOT] Logger initialized");
    crate::crypto::vault::init_vault();
    crate::log::info!("[BOOT] Crypto vault initialized");
    crate::sched::init();
    crate::log::info!("[BOOT] Scheduler initialized");
    crate::ipc::init_ipc();
    crate::log::info!("[BOOT] IPC initialized");
    crate::ui::cli::spawn();
    crate::log::info!("[BOOT] CLI spawned");

    Ok(())
}


pub unsafe fn init_module_system() -> Result<(), &'static str> {
    // # SAFETY: Caller guarantees core subsystems are initialized
    crate::modules::mod_loader::init_module_loader();
    crate::syscall::capabilities::init_capabilities();
    // # SAFETY: Module loader initialized above
    unsafe { load_initial_modules() }
}

/// # Safety: After module loader is initialized.
unsafe fn load_initial_modules() -> Result<(), &'static str> {
    let test_manifest = crate::modules::manifest::ModuleManifest {
        name: "init".into(),
        version: "1.0.0".into(),
        author: "NONOS".into(),
        description: "Initial boot module".into(),
        module_type: crate::modules::manifest::ModuleType::System,
        privacy_policy: crate::modules::manifest::PrivacyPolicy::ZeroStateOnly,
        memory: crate::modules::manifest::MemoryRequirements::default(),
        capabilities: alloc::vec![
            crate::process::capabilities::Capability::CoreExec,
            crate::process::capabilities::Capability::IO,
        ],
        attestation_chain: alloc::vec![],
        hash: [0; 32],
    };

    let manifest_ref = alloc::boxed::Box::leak(alloc::boxed::Box::new(test_manifest));
    crate::modules::mod_loader::verify_and_queue(manifest_ref).map_err(|e| {
        serial_print(format_args!("[BOOT] Failed to queue module 'init': {:?}\n", e));
        "Failed to load initial module"
    })?;

    serial_print(format_args!("[BOOT] Initial module 'init' queued successfully\n"));
    Ok(())
}
/// # Safety: final boot step. 
pub unsafe fn start_scheduler() -> ! {
    crate::sched::enter()
}
