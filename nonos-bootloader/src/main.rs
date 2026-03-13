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

#![no_std]
#![no_main]

extern crate alloc;

use uefi::prelude::*;

use nonos_boot::boot::{
    run_crypto_verification, run_elf_parse, run_handoff_prepare,
    run_hardware_discovery, run_kernel_load, run_security_checks,
    run_uefi_init, run_zk_attestation,
};
use nonos_boot::boot::prepare::HandoffParams;

#[entry]
fn efi_main(_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    let _ = system_table.stdout().reset(false);
    let _ = system_table
        .stdout()
        .output_string(uefi::cstr16!("[BOOT] NONOS Bootloader v1.0\r\n"));

    if uefi_services::init(&mut system_table).is_err() {
        let _ = system_table
            .stdout()
            .output_string(uefi::cstr16!("[FATAL] UEFI services init failed\r\n"));
        loop { core::hint::spin_loop(); }
    }

    /*
     * Disable UEFI watchdog timer (issue #8)
     *
     * UEFI firmware sets a default 5min watchdog. Our boot process
     * can take a while due to ZK proof verification on slower CPUs.
     * Without this, some machines randomly reboot during boot.
     *
     * Seen on Acer Nitro, HP EliteDesk.
     */
    let _ = system_table
        .boot_services()
        .set_watchdog_timer(0, 0x10000, None);

    let uefi_result = run_uefi_init(&mut system_table);
    let gop = uefi_result.gop_available;

    let security = run_security_checks(&mut system_table, gop);

    let _hw = run_hardware_discovery(&mut system_table, gop);

    let kernel_data = run_kernel_load(&mut system_table, gop);

    let (crypto_result, mut crypto_state) =
        run_crypto_verification(&mut system_table, &kernel_data, gop);

    let zk_result = run_zk_attestation(
        &mut system_table,
        &kernel_data,
        &crypto_result.kernel_hash_full,
        &mut crypto_state,
        gop,
        security.measured_boot_active,
    );

    let kernel_image = run_elf_parse(
        &mut system_table,
        &kernel_data,
        &crypto_result,
        gop,
    );

    let params = HandoffParams {
        signature_valid: crypto_result.signature_valid,
        secure_boot: security.secure_boot_enabled,
        kernel_hash: crypto_result.kernel_hash_full,
        zk_result,
        tpm_measured: security.measured_boot_active,
    };

    run_handoff_prepare(system_table, &kernel_image, params, gop);
}
