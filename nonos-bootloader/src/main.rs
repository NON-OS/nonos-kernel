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
use uefi::table::runtime::ResetType;
use uefi_services::init;

use nonos_boot::config::load_bootloader_config;
use nonos_boot::display::{
    animate_hash_reveal, draw_boot_progress, init_boot_screen, init_gop, log_error as panel_error,
    log_hash, log_hex, log_info as panel_info, log_ok, log_size, log_u32, show_crypto_verification,
    show_error_screen, show_handoff_message, update_stage, BootCryptoState, StageStatus,
    STAGE_BLAKE3_HASH, STAGE_COMPLETE, STAGE_ED25519_VERIFY, STAGE_ELF_PARSE, STAGE_HANDOFF,
    STAGE_HARDWARE, STAGE_KERNEL_LOAD, STAGE_SECURITY, STAGE_UEFI, STAGE_ZK_VERIFY,
};
use nonos_boot::entropy::collect_boot_entropy_64;
use nonos_boot::handoff::{exit_and_jump, CryptoHandoff};
use nonos_boot::hardware::discover_system_hardware;
use nonos_boot::loader::{load_kernel, load_kernel_binary};
use nonos_boot::log::logger::{init_logger, log_error, log_info, log_warn};
use nonos_boot::security::{
    enforce_security_policy, extend_boot_measurements, initialize_security_subsystem,
    verify_secure_boot_chain,
};
use nonos_boot::zk::{has_zk_proof, verify_boot_attestation};

const TOTAL_BOOT_STAGES: u32 = 10;

#[entry]
fn efi_main(_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Minimal startup
    let _ = system_table.stdout().reset(false);
    let _ = system_table
        .stdout()
        .output_string(uefi::cstr16!("[BOOT] NONOS Bootloader v1.0\r\n"));

    // Initialize UEFI services
    if init(&mut system_table).is_err() {
        let _ = system_table
            .stdout()
            .output_string(uefi::cstr16!("[FATAL] UEFI init failed\r\n"));
        loop {}
    }

    // Initialize graphical display
    let gop_available = init_gop(&mut system_table);
    if gop_available {
        init_boot_screen();
        draw_boot_progress(1, TOTAL_BOOT_STAGES);
        log_ok(b"GOP framebuffer initialized");
    }

    init_logger(&mut system_table);
    log_info("boot", "UEFI services initialized");

    // ## Stage 1: UEFI, log REAL addresses ##
    update_stage(STAGE_UEFI, StageStatus::Success);
    draw_boot_progress(1, TOTAL_BOOT_STAGES);
    if gop_available {
        log_hex(b"SystemTable     ", &system_table as *const _ as u64);
        log_hex(
            b"BootServices    ",
            system_table.boot_services() as *const _ as u64,
        );
        log_hex(
            b"RuntimeServices ",
            system_table.runtime_services() as *const _ as u64,
        );
        log_hex(
            b"ConfigTable     ",
            system_table.config_table().as_ptr() as u64,
        );
        log_u32(
            b"ConfigTableCount ",
            system_table.config_table().len() as u32,
        );
    }

    // ## Stage 2: Configuration ##
    let _config = load_bootloader_config(&mut system_table);
    if gop_available {
        log_ok(b"boot.toml loaded");
    }

    // ## Stage 3: Security ##
    update_stage(STAGE_SECURITY, StageStatus::Running);
    draw_boot_progress(2, TOTAL_BOOT_STAGES);
    let security = initialize_security_subsystem(&mut system_table);

    if gop_available {
        if security.secure_boot_enabled {
            log_ok(b"SecureBoot ENABLED");
        } else {
            panel_info(b"SecureBoot disabled");
        }
        if security.measured_boot_active {
            log_ok(b"TPM2 MeasuredBoot active");
        } else {
            panel_info(b"TPM2 not available");
        }
    }

    let enforcement = enforce_security_policy(&security, &mut system_table);
    if !enforcement.allow_boot {
        log_error("security", enforcement.reason);
        update_stage(STAGE_SECURITY, StageStatus::Failed);
        if gop_available {
            show_error_screen(b"Security policy enforcement failed");
        }
        fatal_reset(&mut system_table, enforcement.reason);
    }

    if gop_available {
        log_ok(b"Security policy: ALLOW_BOOT");
    }

    if security.secure_boot_enabled && !verify_secure_boot_chain(&security, &mut system_table) {
        log_warn("security", "Secure Boot chain verification warning");
    }

    update_stage(STAGE_SECURITY, StageStatus::Success);
    draw_boot_progress(3, TOTAL_BOOT_STAGES);

    // ## Stage 4: Hardware discovery ##
    update_stage(STAGE_HARDWARE, StageStatus::Running);
    let hw = discover_system_hardware(&mut system_table);

    if gop_available {
        // ## Log ACPI addresses ##
        if let Some(rsdp) = hw.rsdp_address {
            log_hex(b"ACPI RSDP @ ", rsdp);
        }
        log_ok(b"ACPI tables parsed");
        log_ok(b"PCI bus enumerated");
        // ## Log a few memory map entries to show real data ##
        let bs = system_table.boot_services();
        let mmap_size = bs.memory_map_size().map_size;
        log_size(b"MemoryMap size ", mmap_size);
    }

    update_stage(STAGE_HARDWARE, StageStatus::Success);
    draw_boot_progress(4, TOTAL_BOOT_STAGES);

    // ## Stage 5: Load kernel binary ##
    update_stage(STAGE_KERNEL_LOAD, StageStatus::Running);
    draw_boot_progress(4, TOTAL_BOOT_STAGES);

    let kernel_data = match load_kernel_binary(&system_table) {
        Ok(data) => {
            log_info("loader", "kernel binary loaded");
            update_stage(STAGE_KERNEL_LOAD, StageStatus::Success);
            draw_boot_progress(5, TOTAL_BOOT_STAGES);
            if gop_available {
                // ## actual addresses and sizes ##
                log_size(b"kernel.bin ", data.len());
                log_hex(b"kernel base ", data.as_ptr() as u64);
                log_hex(
                    b"kernel end  ",
                    (data.as_ptr() as u64) + (data.len() as u64),
                );
                // ## first 8 bytes of kernel (ELF magic + class) ##
                if data.len() >= 8 {
                    let mut magic = [0u8; 8];
                    magic.copy_from_slice(&data[..8]);
                    log_hash(b"ELF header  ", &magic);
                }
            }
            data
        }
        Err(_) => {
            log_error("loader", "kernel load failed");
            update_stage(STAGE_KERNEL_LOAD, StageStatus::Failed);
            if gop_available {
                panel_error(b"FATAL: kernel.bin not found");
                show_error_screen(b"Kernel not found at \\EFI\\nonos\\kernel.bin");
            }
            fatal_reset(&mut system_table, "kernel not found");
        }
    };

    // ## Prepare crypto state for stage 6-7-8 ##
    let mut crypto_state = BootCryptoState::new();

    // ## Stage 6: BLAKE3 hash computation ##
    update_stage(STAGE_BLAKE3_HASH, StageStatus::Running);
    draw_boot_progress(5, TOTAL_BOOT_STAGES);

    let crypto_result =
        nonos_boot::kernel_verify::verify_kernel_crypto(&kernel_data, &mut system_table);

    crypto_state
        .kernel_hash
        .copy_from_slice(&crypto_result.kernel_hash_full);
    // ## hash reveal ##
    if gop_available {
        for _ in 0..32 {
            animate_hash_reveal();
            show_crypto_verification(&crypto_state);
            micro_delay();
        }
    }

    update_stage(STAGE_BLAKE3_HASH, StageStatus::Success);
    draw_boot_progress(6, TOTAL_BOOT_STAGES);
    if gop_available {
        // ## FULL 32-byte BLAKE3 hash ##
        log_ok(b"BLAKE3-256 hash computed");
        log_hash(b"BLAKE3 ", &crypto_result.kernel_hash_full);
    }

    // ## Stage 7: Ed25519 signature verification ##
    update_stage(STAGE_ED25519_VERIFY, StageStatus::Running);
    draw_boot_progress(6, TOTAL_BOOT_STAGES);
    // ## Extract signature bytes from kernel ##
    if kernel_data.len() >= 64 {
        let sig_end = find_signature_end(&kernel_data);
        let sig_offset = sig_end - 64;
        crypto_state
            .signature_r
            .copy_from_slice(&kernel_data[sig_offset..sig_offset + 32]);
        crypto_state
            .signature_s
            .copy_from_slice(&kernel_data[sig_offset + 32..sig_offset + 64]);

        if gop_available {
            // ## Show signature bytes ##
            log_ok(b"Ed25519 signature extracted");
            log_hash(b"sig.R  ", &crypto_state.signature_r);
            log_hash(b"sig.S  ", &crypto_state.signature_s);
        }
    }

    crypto_state.signature_valid = Some(crypto_result.signature_valid);

    if gop_available {
        show_crypto_verification(&crypto_state);
    }

    if !crypto_result.signature_valid {
        log_error("crypto", "kernel signature verification FAILED");
        update_stage(STAGE_ED25519_VERIFY, StageStatus::Failed);
        if gop_available {
            panel_error(b"Ed25519 signature INVALID");
            show_error_screen(b"Kernel signature invalid - refusing to boot");
        }
        fatal_reset(&mut system_table, "kernel signature invalid");
    }

    update_stage(STAGE_ED25519_VERIFY, StageStatus::Success);
    draw_boot_progress(7, TOTAL_BOOT_STAGES);
    if gop_available {
        log_ok(b"Ed25519 signature VALID");
    }

    // ## Stage 8: ZK attestation - MANDATORY ##
    update_stage(STAGE_ZK_VERIFY, StageStatus::Running);
    draw_boot_progress(7, TOTAL_BOOT_STAGES);

    let has_proof = has_zk_proof(&kernel_data);
    let zk_result = verify_boot_attestation(&kernel_data);
    if gop_available {
        if has_proof {
            log_ok(b"ZK proof block found");
        } else {
            panel_info(b"ZK proof not present");
        }
    }

    crypto_state.zk_present = has_proof;
    crypto_state
        .zk_program_hash
        .copy_from_slice(&zk_result.program_hash);
    crypto_state.zk_verified = Some(zk_result.zk_verified);

    if gop_available {
        show_crypto_verification(&crypto_state);
    }

    // ## *ZK attestation is MANDATORY - boot fails without valid proof* ##
    if !has_proof {
        log_error("zk", "ZK attestation REQUIRED - no proof found in kernel");
        update_stage(STAGE_ZK_VERIFY, StageStatus::Failed);
        if gop_available {
            panel_error(b"ZK proof MISSING");
            show_error_screen(b"ZK attestation required - use embed-zk-proof tool");
        }
        fatal_reset(&mut system_table, "ZK proof missing - attestation required");
    }

    if !zk_result.zk_verified {
        log_error("zk", "ZK attestation verification FAILED");
        log_error("zk", zk_result.status_message);
        update_stage(STAGE_ZK_VERIFY, StageStatus::Failed);
        if gop_available {
            panel_error(b"ZK attestation FAILED");
            show_error_screen(b"ZK attestation invalid - Groth16 verification failed");
        }
        fatal_reset(&mut system_table, zk_result.status_message);
    }

    log_info("zk", "ZK attestation VERIFIED (Groth16/BLS12-381)");
    update_stage(STAGE_ZK_VERIFY, StageStatus::Success);
    draw_boot_progress(8, TOTAL_BOOT_STAGES);
    if gop_available {
        log_ok(b"Groth16/BLS12-381 VERIFIED");
        // ## Show ZK program hash and commitment ##
        log_hash(b"ZK prog ", &zk_result.program_hash);
        log_hash(b"capsule ", &zk_result.capsule_commitment);
    }

    // ## Extend TPM measurements with verified boot state ##
    if security.measured_boot_active {
        let mut sig_bytes = [0u8; 64];
        if kernel_data.len() >= 64 {
            sig_bytes.copy_from_slice(&kernel_data[kernel_data.len() - 64..]);
        }
        extend_boot_measurements(
            &mut system_table,
            &crypto_result.kernel_hash_full,
            &sig_bytes,
            &zk_result.program_hash,
        );
        log_info("tpm", "boot measurements extended to TPM");
    }

    // ## Stage 9: Parse ELF ##
    update_stage(STAGE_ELF_PARSE, StageStatus::Running);
    draw_boot_progress(8, TOTAL_BOOT_STAGES);

    let kernel_elf = if kernel_data.len() > 64 {
        &kernel_data[..kernel_data.len() - 64]
    } else {
        &kernel_data[..]
    };

    let kernel_image = match load_kernel(&mut system_table, kernel_elf) {
        Ok(image) => {
            log_info("loader", "kernel loaded and verified");
            update_stage(STAGE_ELF_PARSE, StageStatus::Success);
            draw_boot_progress(9, TOTAL_BOOT_STAGES);
            if gop_available {
                // ## REAL ELF addresses ##
                log_ok(b"ELF64 parsed successfully");
                log_hex(b"entry   ", image.entry_point as u64);
                log_hex(b"base    ", image.address as u64);
                log_size(b"size    ", image.size);
                log_u32(b"segments ", image.alloc_count as u32);
            }
            image
        }
        Err(_) => {
            log_error("loader", "ELF parsing failed");
            update_stage(STAGE_ELF_PARSE, StageStatus::Failed);
            if gop_available {
                panel_error(b"ELF parse failed");
                show_error_screen(b"Kernel ELF parsing failed");
            }
            fatal_reset(&mut system_table, "kernel ELF parsing failed");
        }
    };

    // ## Stage 10: Handoff ##
    update_stage(STAGE_HANDOFF, StageStatus::Running);
    draw_boot_progress(10, TOTAL_BOOT_STAGES);

    let crypto_handoff = CryptoHandoff {
        signature_valid: crypto_result.signature_valid,
        secure_boot: security.secure_boot_enabled,
        kernel_hash: crypto_result.kernel_hash_full,
        zk_attested: zk_result.zk_verified,
        zk_program_hash: zk_result.program_hash,
        zk_capsule_commitment: zk_result.capsule_commitment,
    };

    let entropy = match collect_boot_entropy_64() {
        Ok(e) => e,
        Err(msg) => {
            log_error("entropy", msg);
            if gop_available {
                panel_error(b"Entropy collection failed");
                show_error_screen(b"Insufficient entropy for secure boot");
            }
            fatal_reset(&mut system_table, "entropy collection failed");
        }
    };
    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(&entropy[..32]);

    if gop_available {
        log_ok(b"Entropy collected");
        log_hash(b"RNGseed ", &rng_seed);
        log_ok(b"CryptoHandoff prepared");
    }

    update_stage(STAGE_HANDOFF, StageStatus::Success);
    update_stage(STAGE_COMPLETE, StageStatus::Success);
    draw_boot_progress(TOTAL_BOOT_STAGES, TOTAL_BOOT_STAGES);

    if gop_available {
        log_ok(b"All boot stages COMPLETE");
        log_hex(b"jumping ", kernel_image.entry_point as u64);
        show_handoff_message();
    }
    mini_delay();

    log_info("handoff", "transferring control to kernel");

    exit_and_jump(
        system_table,
        &kernel_image,
        None,
        crypto_handoff,
        rng_seed,
        security.measured_boot_active,
    );
}

/// ## ZK proof block magic bytes ##
const ZK_PROOF_MAGIC: [u8; 4] = [0x4E, 0xC3, 0x5A, 0x50];
/// _* Find where the Ed25519 signature ends in the kernel binary.
/// Returns kernel_data.len() if no ZK block, or ZK block offset if present.
/// Kernel structure: [kernel_code][64-byte signature][optional ZK block]_*
fn find_signature_end(kernel_data: &[u8]) -> usize {
    // ## Minimum ZK block size: header(80) + proof(192) = 272 bytes ##
    const MIN_ZK_SIZE: usize = 272;
    if kernel_data.len() < 64 + MIN_ZK_SIZE {
        return kernel_data.len();
    }

    // ## Search in the last 4KB for ZK magic ##
    let search_start = kernel_data.len().saturating_sub(4096);
    for i in (search_start..kernel_data.len().saturating_sub(MIN_ZK_SIZE)).rev() {
        if kernel_data.len() - i >= 4 && &kernel_data[i..i + 4] == &ZK_PROOF_MAGIC {
            return i;
        }
    }

    kernel_data.len()
}

/// ## Delay for visual (approx 80ms) ##
fn mini_delay() {
    for _ in 0..8_000_000 {
        core::hint::spin_loop();
    }
}

/// ## Short delay (approx 15ms) ##
fn micro_delay() {
    for _ in 0..1_500_000 {
        core::hint::spin_loop();
    }
}

fn fatal_reset(st: &mut SystemTable<Boot>, reason: &str) -> ! {
    log_error("fatal", reason);
    let _ = st.stdout().reset(false);
    let _ = st.stdout().output_string(cstr16!("\r\n[FATAL] "));
    if let Ok(s) = uefi::CString16::try_from(reason) {
        let _ = st.stdout().output_string(&s);
    }
    let _ = st
        .stdout()
        .output_string(cstr16!("\r\nSystem will restart...\r\n"));
    // Wait a bit before reset
    for _ in 0..10_000_000 {
        core::hint::spin_loop();
    }

    st.runtime_services()
        .reset(ResetType::WARM, Status::LOAD_ERROR, Some(reason.as_bytes()))
}
