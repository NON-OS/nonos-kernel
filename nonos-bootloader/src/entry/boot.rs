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

use uefi::prelude::*;
use nonos_boot::boot::{
    initialize_zk_replay_protection, run_crypto_verification, run_elf_parse,
    run_handoff_prepare, run_hardware_discovery, run_kernel_load,
    run_security_checks, run_uefi_init, run_zk_attestation,
};
use nonos_boot::boot::prepare::HandoffParams;
use nonos_boot::menu::{check_dev_key_held, run_boot_menu, MenuState, SecurityMode};
use super::action::resolve_action;

pub fn boot_entry(_handle: Handle, mut st: SystemTable<Boot>) -> Status {
    let _ = st.stdout().reset(false);
    let _ = st.stdout().output_string(uefi::cstr16!("[BOOT] NONOS Bootloader v1.0\r\n"));

    if uefi_services::init(&mut st).is_err() {
        let _ = st.stdout().output_string(uefi::cstr16!("[FATAL] UEFI init failed\r\n"));
        loop { core::hint::spin_loop(); }
    }

    let _ = st.boot_services().set_watchdog_timer(0, 0x10000, None);
    let uefi_result = run_uefi_init(&mut st);
    let gop = uefi_result.gop_available;
    // SECURITY: Development mode bypass is disabled in production builds
    // F12 can only activate development mode if:
    // 1. The "dev-mode" feature is enabled at compile time, AND
    // 2. Secure Boot is NOT enabled (development environments typically have it disabled)
    #[cfg(feature = "dev-mode")]
    let dev_override = {
        let f12_pressed = check_dev_key_held(st.boot_services());
        if f12_pressed {
            // Check if Secure Boot is disabled - development mode only allowed without Secure Boot
            let secure_boot_on = st.runtime_services()
                .get_variable(
                    uefi::cstr16!("SecureBoot"),
                    &uefi::table::runtime::VariableVendor::GLOBAL_VARIABLE
                )
                .map(|(data, _)| data.first().copied().unwrap_or(0) == 1)
                .unwrap_or(false);

            if secure_boot_on {
                let _ = st.stdout().output_string(uefi::cstr16!("[SECURITY] F12 dev mode blocked: Secure Boot is enabled\r\n"));
                false
            } else {
                let _ = st.stdout().output_string(uefi::cstr16!("[WARN] F12 pressed - development mode (Secure Boot disabled)\r\n"));
                true
            }
        } else {
            false
        }
    };
    #[cfg(not(feature = "dev-mode"))]
    let dev_override = false; // Development mode completely disabled in production builds

    let mut menu_state = MenuState::default();
    let menu_action = run_boot_menu(st.boot_services(), &mut menu_state);

    let security_mode = if dev_override {
        let _ = st.stdout().output_string(uefi::cstr16!("[WARN] DEV MODE - SECURITY BYPASSED\r\n"));
        SecurityMode::Development
    } else {
        match resolve_action(&mut st, menu_action) {
            Ok(mode) => mode,
            Err(status) => return status,
        }
    };

    let security = run_security_checks(&mut st, gop);
    initialize_zk_replay_protection(&st);
    let _hw = run_hardware_discovery(&mut st, gop);
    let kernel_data = run_kernel_load(&mut st, gop);
    let (crypto_result, mut crypto_state) =
        run_crypto_verification(&mut st, &kernel_data, gop, security_mode);

    let zk_result = run_zk_attestation(
        &mut st, &kernel_data, &crypto_result.kernel_hash_full,
        &mut crypto_state, gop, security.measured_boot_active, security_mode,
    );

    let kernel_image = run_elf_parse(&mut st, &kernel_data, &crypto_result, gop);
    let params = HandoffParams {
        signature_valid: crypto_result.signature_valid,
        secure_boot: security.secure_boot_enabled,
        kernel_hash: crypto_result.kernel_hash_full,
        zk_result,
        tpm_measured: security.measured_boot_active,
    };
    run_handoff_prepare(st, &kernel_image, params, gop);
}
