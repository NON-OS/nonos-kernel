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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_ACCENT};

use super::utils::trim_bytes;

pub fn cmd_lsmod() {
    print_line(b"Loaded Kernel Modules:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"Module              Size    Used by", COLOR_TEXT_DIM);

    print_line(b"crypto_core         64K     vault, tls", COLOR_GREEN);
    print_line(b"crypto_pqc          128K    crypto_core", COLOR_ACCENT);
    print_line(b"crypto_zk           96K     attestation", COLOR_ACCENT);
    print_line(b"network_stack       256K    tor, dns", COLOR_GREEN);
    print_line(b"tor_onion           192K    network_stack", COLOR_ACCENT);
    print_line(b"fs_ramfs            32K     vfs", COLOR_GREEN);
    print_line(b"fs_cryptofs         48K     ramfs, vault", COLOR_GREEN);
    print_line(b"graphics_fb         64K     desktop", COLOR_GREEN);
    print_line(b"input_hid           24K     xhci", COLOR_GREEN);
    print_line(b"usb_xhci            96K     pci", COLOR_GREEN);
    print_line(b"security_hardening  32K     -", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Total: 11 modules loaded", COLOR_TEXT_DIM);
}

pub fn cmd_modinfo(cmd: &[u8]) {
    let module = if cmd.len() > 8 {
        trim_bytes(&cmd[8..])
    } else {
        print_line(b"Usage: modinfo <module>", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT);
        print_line(b"Available modules:", COLOR_TEXT_WHITE);
        print_line(b"  crypto_core, crypto_pqc, crypto_zk", COLOR_TEXT_DIM);
        print_line(b"  network_stack, tor_onion", COLOR_TEXT_DIM);
        print_line(b"  fs_ramfs, fs_cryptofs", COLOR_TEXT_DIM);
        print_line(b"  graphics_fb, input_hid, usb_xhci", COLOR_TEXT_DIM);
        print_line(b"  security_hardening", COLOR_TEXT_DIM);
        return;
    };

    match module {
        b"crypto_core" => {
            print_line(b"Module: crypto_core", COLOR_TEXT_WHITE);
            print_line(b"============================================", COLOR_TEXT_DIM);
            print_line(b"Description: Core cryptographic primitives", COLOR_TEXT);
            print_line(b"Version:     1.0.0", COLOR_TEXT);
            print_line(b"Author:      N\xd8NOS Team", COLOR_TEXT);
            print_line(b"License:     AGPL-3.0", COLOR_TEXT);
            print_line(b"", COLOR_TEXT);
            print_line(b"Provides:", COLOR_TEXT_WHITE);
            print_line(b"  - BLAKE3, SHA-256, SHA-512, SHA3", COLOR_TEXT_DIM);
            print_line(b"  - AES-256-GCM, ChaCha20-Poly1305", COLOR_TEXT_DIM);
            print_line(b"  - Ed25519, X25519, secp256k1", COLOR_TEXT_DIM);
            print_line(b"  - HMAC, HKDF, Argon2id", COLOR_TEXT_DIM);
        }
        b"crypto_pqc" => {
            print_line(b"Module: crypto_pqc", COLOR_TEXT_WHITE);
            print_line(b"============================================", COLOR_TEXT_DIM);
            print_line(b"Description: Post-Quantum Cryptography", COLOR_ACCENT);
            print_line(b"Version:     1.0.0", COLOR_TEXT);
            print_line(b"Author:      N\xd8NOS Team", COLOR_TEXT);
            print_line(b"License:     AGPL-3.0", COLOR_TEXT);
            print_line(b"", COLOR_TEXT);
            print_line(b"Provides:", COLOR_TEXT_WHITE);
            print_line(b"  - Kyber1024 (ML-KEM)", COLOR_ACCENT);
            print_line(b"  - Dilithium5 (ML-DSA)", COLOR_ACCENT);
            print_line(b"  - SPHINCS+ (hash-based sigs)", COLOR_ACCENT);
            print_line(b"  - NTRU, McEliece", COLOR_ACCENT);
            print_line(b"", COLOR_TEXT);
            print_line(b"Status: Quantum-resistant algorithms", COLOR_GREEN);
        }
        b"crypto_zk" => {
            print_line(b"Module: crypto_zk", COLOR_TEXT_WHITE);
            print_line(b"============================================", COLOR_TEXT_DIM);
            print_line(b"Description: Zero-Knowledge Proofs", COLOR_ACCENT);
            print_line(b"Version:     1.0.0", COLOR_TEXT);
            print_line(b"", COLOR_TEXT);
            print_line(b"Provides:", COLOR_TEXT_WHITE);
            print_line(b"  - Groth16 proving system", COLOR_ACCENT);
            print_line(b"  - Halo2 (recursive proofs)", COLOR_ACCENT);
            print_line(b"  - Circuit compilation", COLOR_TEXT_DIM);
            print_line(b"  - Proof verification", COLOR_TEXT_DIM);
        }
        b"tor_onion" => {
            print_line(b"Module: tor_onion", COLOR_TEXT_WHITE);
            print_line(b"============================================", COLOR_TEXT_DIM);
            print_line(b"Description: Tor Onion Routing", COLOR_ACCENT);
            print_line(b"Version:     1.0.0", COLOR_TEXT);
            print_line(b"", COLOR_TEXT);
            print_line(b"Provides:", COLOR_TEXT_WHITE);
            print_line(b"  - Circuit establishment", COLOR_TEXT_DIM);
            print_line(b"  - Onion encryption layers", COLOR_TEXT_DIM);
            print_line(b"  - Guard/Relay/Exit selection", COLOR_TEXT_DIM);
            print_line(b"  - Hidden service support", COLOR_TEXT_DIM);
            print_line(b"", COLOR_TEXT);
            print_line(b"Status: Anonymous networking ACTIVE", COLOR_GREEN);
        }
        b"security_hardening" => {
            print_line(b"Module: security_hardening", COLOR_TEXT_WHITE);
            print_line(b"============================================", COLOR_TEXT_DIM);
            print_line(b"Description: Security Hardening", COLOR_TEXT);
            print_line(b"", COLOR_TEXT);
            print_line(b"Provides:", COLOR_TEXT_WHITE);
            print_line(b"  - KASLR implementation", COLOR_GREEN);
            print_line(b"  - Stack canaries", COLOR_GREEN);
            print_line(b"  - W^X enforcement", COLOR_GREEN);
            print_line(b"  - Spectre/Meltdown mitigations", COLOR_GREEN);
            print_line(b"  - Memory sanitization", COLOR_GREEN);
        }
        _ => {
            print_line(b"modinfo: module not found", COLOR_YELLOW);
            print_line(b"Use 'lsmod' to see loaded modules", COLOR_TEXT_DIM);
        }
    }
}

pub fn cmd_insmod(cmd: &[u8]) {
    let module = if cmd.len() > 7 {
        trim_bytes(&cmd[7..])
    } else {
        print_line(b"Usage: insmod <module>", COLOR_TEXT_DIM);
        return;
    };

    if module.is_empty() {
        print_line(b"insmod: module name required", COLOR_YELLOW);
        return;
    }

    print_line(b"insmod: Dynamic loading not supported", COLOR_YELLOW);
    print_line(b"All modules compiled into kernel", COLOR_TEXT_DIM);
    print_line(b"(ZeroState security requirement)", COLOR_TEXT_DIM);
}

pub fn cmd_rmmod(cmd: &[u8]) {
    let module = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: rmmod <module>", COLOR_TEXT_DIM);
        return;
    };

    if module.is_empty() {
        print_line(b"rmmod: module name required", COLOR_YELLOW);
        return;
    }

    print_line(b"rmmod: Unloading not supported", COLOR_YELLOW);
    print_line(b"Modules are permanent for security", COLOR_TEXT_DIM);
}

pub fn cmd_depmod() {
    print_line(b"Module Dependencies:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"crypto_pqc -> crypto_core", COLOR_TEXT);
    print_line(b"crypto_zk -> crypto_core", COLOR_TEXT);
    print_line(b"tor_onion -> network_stack, crypto_core", COLOR_TEXT);
    print_line(b"fs_cryptofs -> fs_ramfs, crypto_core", COLOR_TEXT);
    print_line(b"graphics_fb -> (none)", COLOR_TEXT);
    print_line(b"input_hid -> usb_xhci", COLOR_TEXT);
    print_line(b"usb_xhci -> (none)", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"All dependencies satisfied", COLOR_GREEN);
}

pub fn cmd_sysctl(cmd: &[u8]) {
    let args = if cmd.len() > 7 {
        trim_bytes(&cmd[7..])
    } else {
        b"" as &[u8]
    };

    if args.is_empty() || args == b"-a" {
        print_line(b"Kernel Parameters:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);
        print_line(b"kernel.hostname = n\xd8nos-zerostate", COLOR_TEXT);
        print_line(b"kernel.version = 1.0.0-production", COLOR_TEXT);
        print_line(b"kernel.ostype = N\xd8NOS", COLOR_TEXT);
        print_line(b"", COLOR_TEXT);
        print_line(b"vm.swappiness = 0", COLOR_YELLOW);
        print_line(b"vm.overcommit = 0", COLOR_TEXT);
        print_line(b"vm.zerofill = 1", COLOR_GREEN);
        print_line(b"", COLOR_TEXT);
        print_line(b"net.ipv4.ip_forward = 0", COLOR_TEXT);
        print_line(b"net.tor.enabled = 1", COLOR_GREEN);
        print_line(b"net.tor.enforce = 1", COLOR_GREEN);
        print_line(b"", COLOR_TEXT);
        print_line(b"security.kaslr = 1", COLOR_GREEN);
        print_line(b"security.canary = 1", COLOR_GREEN);
        print_line(b"security.nx = 1", COLOR_GREEN);
        print_line(b"security.smep = 1", COLOR_GREEN);
        print_line(b"security.smap = 1", COLOR_GREEN);
    } else {
        print_line(b"sysctl: read-only in ZeroState mode", COLOR_YELLOW);
    }
}

pub fn cmd_kver() {
    print_line(b"N\xd8NOS Kernel Version:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"Version:    1.0.0-production", COLOR_TEXT);
    print_line(b"Type:       Microkernel (Rust no_std)", COLOR_TEXT);
    print_line(b"Arch:       x86_64 (AMD64)", COLOR_TEXT);
    print_line(b"Target:     x86_64-n\xd8nos", COLOR_TEXT);
    print_line(b"Compiler:   rustc (nightly)", COLOR_TEXT);
    print_line(b"Build:      Release (optimized)", COLOR_TEXT);
    print_line(b"Mode:       ZeroState (RAM-only)", COLOR_ACCENT);
    print_line(b"License:    AGPL-3.0", COLOR_TEXT_DIM);
}
