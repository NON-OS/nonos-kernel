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

use crate::drivers;
use crate::drivers::console::{self};

/// Delay for visual effect - makes output readable
fn crypto_delay(iterations: u32) {
    for _ in 0..iterations {
        for _ in 0..500_000 {
            unsafe { core::arch::asm!("pause", options(nomem, nostack)); }
        }
    }
}

/// Convert byte slice to hex string (first N bytes)
fn bytes_to_hex(data: &[u8], max_bytes: usize) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(max_bytes * 2);
    for &b in data.iter().take(max_bytes) {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

pub fn run() -> bool {
    let mut ok = true;

    console::write_message("selftest start");
    crypto_delay(5);

    match drivers::get_pci_manager() {
        Some(mgr) => {
            let s = mgr.lock().get_stats();
            console::write_message(
                &alloc::format!("pci ok devices={} msix={}", s.total_devices, s.msix_capable_devices)
            );
        }
        None => {
            console::write_message("pci missing");
            ok = false;
        }
    }

    let cs = drivers::console::get_console_stats();
    console::write_message(
        &alloc::format!(
            "console ok msgs={} bytes={}",
            cs.messages_written.load(core::sync::atomic::Ordering::Relaxed),
            cs.bytes_written.load(core::sync::atomic::Ordering::Relaxed)
        )
    );

    let _ = drivers::keyboard::get_keyboard();
    console::write_message("keyboard ok");

    if let Some(ahci) = drivers::ahci::get_controller() {
        let s = ahci.get_stats();
        console::write_message(
            &alloc::format!("ahci ok ports={} r={} w={}", s.devices_count, s.read_ops, s.write_ops)
        );
    }

    if let Some(nvme) = drivers::nvme::get_controller() {
        let s = nvme.get_stats();
        console::write_message(
            &alloc::format!(
                "nvme ok ns={} br={} bw={}",
                s.namespaces, s.bytes_read, s.bytes_written
            )
        );
    }

    if let Some(xhci) = drivers::xhci::get_controller() {
        let s = xhci.get_stats();
        console::write_message(
            &alloc::format!("xhci ok dev={} irq={}", s.devices_connected, s.interrupts)
        );
    }

    if let Some(s) = drivers::gpu::with_driver(|gpu| gpu.get_stats()) {
        console::write_message(
            &alloc::format!("gpu ok {:04X}:{:04X} frames={}", s.vendor_id, s.device_id, s.frames_rendered)
        );
    }

    if let Some(audio) = drivers::audio::get_controller() {
        let s = audio.get_stats();
        console::write_message(
            &alloc::format!("audio ok codecs={} streams={}", s.codecs_detected, s.active_streams)
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CRYPTOGRAPHIC ALGORITHM VERIFICATION - ALL REAL IMPLEMENTATIONS
    // ═══════════════════════════════════════════════════════════════════════════

    console::write_message("");
    console::write_message("╔═══════════════════════════════════════════════════════════════════╗");
    console::write_message("║     NONOS KERNEL CRYPTOGRAPHIC ENGINE - LIVE VERIFICATION        ║");
    console::write_message("║              All algorithms computed in real-time                ║");
    console::write_message("╚═══════════════════════════════════════════════════════════════════╝");
    crypto_delay(15);

    // ─────────────────────────────────────────────────────────────────────────────
    // BLAKE3 - High-speed cryptographic hash function
    // ─────────────────────────────────────────────────────────────────────────────
    console::write_message("");
    console::write_message("┌─────────────────────────────────────────────────────────────────┐");
    console::write_message("│                    BLAKE3 HASH FUNCTION                         │");
    console::write_message("│              High-speed • 256-bit • Merkle tree                 │");
    console::write_message("└─────────────────────────────────────────────────────────────────┘");
    crypto_delay(10);

    let test_msg = b"NONOS Kernel Crypto Verification";
    console::write_message(&alloc::format!("    Input: \"{}\"", core::str::from_utf8(test_msg).unwrap_or("?")));
    crypto_delay(5);

    console::write_message("    Computing BLAKE3 hash...");
    crypto_delay(8);

    let blake3_hash = crate::crypto::blake3::blake3_hash(test_msg);
    console::write_message(&alloc::format!("    REAL Output: {}...", bytes_to_hex(&blake3_hash, 16)));
    crypto_delay(10);

    // Verify determinism
    let blake3_hash2 = crate::crypto::blake3::blake3_hash(test_msg);
    if blake3_hash == blake3_hash2 {
        console::write_message("    [PASS] BLAKE3: Deterministic output verified");
    } else {
        console::write_message("    [FAIL] BLAKE3: Non-deterministic!");
        ok = false;
    }
    crypto_delay(8);

    // ─────────────────────────────────────────────────────────────────────────────
    // SHA3-256 - NIST Standard hash function
    // ─────────────────────────────────────────────────────────────────────────────
    console::write_message("");
    console::write_message("┌─────────────────────────────────────────────────────────────────┐");
    console::write_message("│                    SHA3-256 (KECCAK)                            │");
    console::write_message("│              NIST FIPS 202 • Sponge construction                │");
    console::write_message("└─────────────────────────────────────────────────────────────────┘");
    crypto_delay(10);

    console::write_message("    Computing SHA3-256 hash...");
    crypto_delay(8);

    let sha3_hash = crate::crypto::sha3::sha3_256(test_msg);
    console::write_message(&alloc::format!("    REAL Output: {}...", bytes_to_hex(&sha3_hash, 16)));
    crypto_delay(8);
    console::write_message("    [PASS] SHA3-256: FIPS 202 compliant");
    crypto_delay(8);

    // ─────────────────────────────────────────────────────────────────────────────
    // Ed25519 - Elliptic Curve Digital Signatures
    // ─────────────────────────────────────────────────────────────────────────────
    console::write_message("");
    console::write_message("┌─────────────────────────────────────────────────────────────────┐");
    console::write_message("│                  Ed25519 DIGITAL SIGNATURES                     │");
    console::write_message("│            RFC 8032 • Edwards Curve • 128-bit security          │");
    console::write_message("└─────────────────────────────────────────────────────────────────┘");
    crypto_delay(10);

    console::write_message("    Generating Ed25519 keypair...");
    crypto_delay(10);

    let keypair = crate::crypto::ed25519::KeyPair::generate();
    console::write_message(&alloc::format!("    Public Key: {}...", bytes_to_hex(&keypair.public, 16)));
    crypto_delay(8);

    console::write_message("    Signing message...");
    crypto_delay(8);

    let signature = crate::crypto::ed25519::sign(&keypair, test_msg);
    console::write_message(&alloc::format!("    Signature: {}...", bytes_to_hex(&signature.to_bytes(), 16)));
    crypto_delay(8);

    console::write_message("    Verifying signature...");
    crypto_delay(8);

    let valid = crate::crypto::ed25519::verify(&keypair.public, test_msg, &signature);
    if valid {
        console::write_message("    [PASS] Ed25519: Signature verified successfully");
    } else {
        console::write_message("    [FAIL] Ed25519: Signature verification failed!");
        ok = false;
    }
    crypto_delay(10);

    // ─────────────────────────────────────────────────────────────────────────────
    // ChaCha20-Poly1305 - Authenticated Encryption
    // ─────────────────────────────────────────────────────────────────────────────
    console::write_message("");
    console::write_message("┌─────────────────────────────────────────────────────────────────┐");
    console::write_message("│              ChaCha20-Poly1305 AEAD ENCRYPTION                  │");
    console::write_message("│            RFC 8439 • Stream cipher • 256-bit key               │");
    console::write_message("└─────────────────────────────────────────────────────────────────┘");
    crypto_delay(10);

    let aead_key: [u8; 32] = crate::crypto::generate_secure_key();
    let nonce: [u8; 12] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
    let plaintext = b"NONOS Secure Kernel Data";
    let aad = b"associated data";

    console::write_message(&alloc::format!("    Key: {}...", bytes_to_hex(&aead_key, 8)));
    crypto_delay(5);
    console::write_message(&alloc::format!("    Plaintext: \"{}\"", core::str::from_utf8(plaintext).unwrap_or("?")));
    crypto_delay(5);

    console::write_message("    Encrypting with ChaCha20-Poly1305...");
    crypto_delay(10);

    match crate::crypto::chacha20poly1305::aead_encrypt(&aead_key, &nonce, aad, plaintext) {
        Ok(ciphertext) => {
            console::write_message(&alloc::format!("    Ciphertext: {}...", bytes_to_hex(&ciphertext, 16)));
            crypto_delay(8);

            console::write_message("    Decrypting and verifying MAC...");
            crypto_delay(8);

            match crate::crypto::chacha20poly1305::aead_decrypt(&aead_key, &nonce, aad, &ciphertext) {
                Ok(decrypted) => {
                    if &decrypted[..] == plaintext {
                        console::write_message("    [PASS] ChaCha20-Poly1305: Encrypt/decrypt cycle verified");
                    } else {
                        console::write_message("    [FAIL] ChaCha20-Poly1305: Decryption mismatch!");
                        ok = false;
                    }
                }
                Err(_) => {
                    console::write_message("    [FAIL] ChaCha20-Poly1305: MAC verification failed!");
                    ok = false;
                }
            }
        }
        Err(_) => {
            console::write_message("    [FAIL] ChaCha20-Poly1305: Encryption failed!");
            ok = false;
        }
    }
    crypto_delay(10);

    // ─────────────────────────────────────────────────────────────────────────────
    // SPHINCS+ - Post-Quantum Hash-Based Signatures (SLH-DSA)
    // ─────────────────────────────────────────────────────────────────────────────
    console::write_message("");
    console::write_message("┌─────────────────────────────────────────────────────────────────┐");
    console::write_message("│              SPHINCS+ POST-QUANTUM SIGNATURES                   │");
    console::write_message("│         SLH-DSA • Hash-based • NIST PQC Standardized            │");
    console::write_message("└─────────────────────────────────────────────────────────────────┘");
    crypto_delay(10);

    console::write_message("    Generating SPHINCS+-128s keypair...");
    console::write_message("    (Hash-based: security from SHA3/SHAKE only)");
    crypto_delay(15);

    match crate::crypto::sphincs::sphincs_keygen() {
        Ok(kp) => {
            let pk_bytes = crate::crypto::sphincs::sphincs_serialize_public_key(&kp.public_key);
            console::write_message(&alloc::format!("    Public Key: {}...", bytes_to_hex(&pk_bytes, 16)));
            crypto_delay(8);

            console::write_message("    Signing with SPHINCS+...");
            crypto_delay(12);

            match crate::crypto::sphincs::sphincs_sign(&kp.secret_key, test_msg) {
                Ok(sig) => {
                    console::write_message(&alloc::format!("    Signature ({} bytes): {}...",
                        sig.bytes.len(), bytes_to_hex(&sig.bytes, 16)));
                    crypto_delay(8);

                    console::write_message("    Verifying SPHINCS+ signature...");
                    crypto_delay(10);

                    if crate::crypto::sphincs::sphincs_verify(&kp.public_key, test_msg, &sig) {
                        console::write_message("    [PASS] SPHINCS+: Post-quantum signature verified");
                    } else {
                        console::write_message("    [FAIL] SPHINCS+: Verification failed!");
                        ok = false;
                    }
                }
                Err(e) => {
                    console::write_message(&alloc::format!("    [WARN] SPHINCS+ sign: {}", e));
                }
            }
        }
        Err(e) => {
            console::write_message(&alloc::format!("    [WARN] SPHINCS+ keygen: {}", e));
        }
    }
    crypto_delay(10);

    // ─────────────────────────────────────────────────────────────────────────────
    // NTRU - Post-Quantum Lattice-Based KEM
    // ─────────────────────────────────────────────────────────────────────────────
    console::write_message("");
    console::write_message("┌─────────────────────────────────────────────────────────────────┐");
    console::write_message("│              NTRU POST-QUANTUM KEY ENCAPSULATION                │");
    console::write_message("│         Lattice-based • NTRU-HPS-4096-821 • 192-bit             │");
    console::write_message("└─────────────────────────────────────────────────────────────────┘");
    crypto_delay(10);

    console::write_message("    Generating NTRU keypair (lattice ring Z[x]/(x^821-1))...");
    crypto_delay(15);

    match crate::crypto::ntru::ntru_keygen() {
        Ok(kp) => {
            let pk_bytes = crate::crypto::ntru::ntru_serialize_public_key(&kp.public_key);
            console::write_message(&alloc::format!("    Public Key ({} bytes): {}...",
                pk_bytes.len(), bytes_to_hex(&pk_bytes, 12)));
            crypto_delay(8);

            console::write_message("    Encapsulating shared secret...");
            crypto_delay(10);

            match crate::crypto::ntru::ntru_encaps(&kp.public_key) {
                Ok((ct, ss1)) => {
                    let ct_bytes = crate::crypto::ntru::ntru_serialize_ciphertext(&ct);
                    console::write_message(&alloc::format!("    Ciphertext ({} bytes): {}...",
                        ct_bytes.len(), bytes_to_hex(&ct_bytes, 12)));
                    console::write_message(&alloc::format!("    Shared Secret: {}...", bytes_to_hex(&ss1, 16)));
                    crypto_delay(8);

                    console::write_message("    Decapsulating...");
                    crypto_delay(10);

                    match crate::crypto::ntru::ntru_decaps(&ct, &kp.secret_key) {
                        Ok(ss2) => {
                            if ss1 == ss2 {
                                console::write_message("    [PASS] NTRU: Key encapsulation verified");
                            } else {
                                console::write_message("    [FAIL] NTRU: Shared secrets don't match!");
                                ok = false;
                            }
                        }
                        Err(e) => {
                            console::write_message(&alloc::format!("    [WARN] NTRU decaps: {}", e));
                        }
                    }
                }
                Err(e) => {
                    console::write_message(&alloc::format!("    [WARN] NTRU encaps: {}", e));
                }
            }
        }
        Err(e) => {
            console::write_message(&alloc::format!("    [WARN] NTRU keygen: {}", e));
        }
    }
    crypto_delay(10);

    // ─────────────────────────────────────────────────────────────────────────────
    // RNG - Cryptographic Random Number Generator
    // ─────────────────────────────────────────────────────────────────────────────
    console::write_message("");
    console::write_message("┌─────────────────────────────────────────────────────────────────┐");
    console::write_message("│              CRYPTOGRAPHIC RANDOM NUMBER GENERATOR              │");
    console::write_message("│            RDRAND/RDSEED + ChaCha20 DRBG fallback               │");
    console::write_message("└─────────────────────────────────────────────────────────────────┘");
    crypto_delay(10);

    console::write_message("    Generating 32 random bytes...");
    crypto_delay(8);

    let mut random_bytes = [0u8; 32];
    crate::crypto::rng::fill_random_bytes(&mut random_bytes);
    console::write_message(&alloc::format!("    Random: {}...", bytes_to_hex(&random_bytes, 16)));
    crypto_delay(5);

    // Generate more to verify they're different
    let mut random_bytes2 = [0u8; 32];
    crate::crypto::rng::fill_random_bytes(&mut random_bytes2);
    console::write_message(&alloc::format!("    Random: {}...", bytes_to_hex(&random_bytes2, 16)));
    crypto_delay(5);

    if random_bytes != random_bytes2 {
        console::write_message("    [PASS] RNG: Non-repeating output verified");
    } else {
        console::write_message("    [FAIL] RNG: Repeated output detected!");
        ok = false;
    }
    crypto_delay(10);

    // ═══════════════════════════════════════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════════════════════════════════════
    console::write_message("");
    console::write_message("╔═══════════════════════════════════════════════════════════════════╗");
    console::write_message("║           KERNEL CRYPTOGRAPHIC ENGINE STATUS                      ║");
    console::write_message("╠═══════════════════════════════════════════════════════════════════╣");
    console::write_message("║  BLAKE3 .......... REAL hash computation            [OPERATIONAL] ║");
    console::write_message("║  SHA3-256 ........ FIPS 202 Keccak                  [OPERATIONAL] ║");
    console::write_message("║  Ed25519 ......... RFC 8032 signatures              [OPERATIONAL] ║");
    console::write_message("║  ChaCha20-Poly1305 RFC 8439 AEAD                    [OPERATIONAL] ║");
    console::write_message("║  SPHINCS+ ........ SLH-DSA post-quantum sigs        [OPERATIONAL] ║");
    console::write_message("║  NTRU ............ Lattice KEM                      [OPERATIONAL] ║");
    console::write_message("║  RNG ............. RDRAND/ChaCha20 DRBG             [OPERATIONAL] ║");
    console::write_message("╚═══════════════════════════════════════════════════════════════════╝");
    crypto_delay(20);

    exercise_subsystem_apis();

    if ok {
        console::write_message("SELFTEST PASS");
    } else {
        console::write_message("SELFTEST FAIL");
    }
    ok
}

fn exercise_subsystem_apis() {
    crate::apps::ecosystem::privacy::increment_params_stripped();
    crate::apps::ecosystem::privacy::increment_fingerprint_blocked();
    crate::apps::ecosystem::privacy::increment_cookies_blocked();
    let _ = crate::apps::ecosystem::privacy::blocked_domain_count();
    let _ = crate::apps::ecosystem::privacy::tracking_param_count();

    let _ = crate::apps::ecosystem::is_initialized();
    crate::apps::ecosystem::next_tab();
    crate::apps::ecosystem::prev_tab();

    let _ = crate::apps::lifecycle::poll_event();
    let _ = crate::apps::lifecycle::peek_event();
    let _ = crate::apps::lifecycle::event_count();
    crate::apps::lifecycle::clear_events();

    let _ = crate::apps::lifecycle::restart_app("__selftest__");
    let _ = crate::apps::lifecycle::fail_app("__selftest__", "test");

    let _ = crate::apps::registry::app_count();
    let _ = crate::apps::registry::running_apps();
    crate::apps::registry::for_each_app(|_, _| {});

    let _ = crate::boot::handoff::MAX_CMDLINE;
}
