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

use nonos_capsule_sign::algs::AlgId;
use nonos_capsule_sign::verify::decode::{
    decode_cert, decode_manifest, decode_trust_anchor_policy,
};
use nonos_capsule_sign::verify::{verify_cert, verify_manifest};
use std::fmt::Write as _;

const REQUIRED_ALGS: &[AlgId] = &[AlgId::Ed25519, AlgId::MlDsa65];
// Inside the cert validity window declared in the Makefile
// (2026-01-01 .. 2030-01-01).
const NOW_MS: u64 = 1_778_025_600_000;

// Committed artifacts live under nonos-data/trust/. nonos-sign
// runs from the nonos-sign/ directory under `cargo test`, so all
// paths are anchored at the parent (`..`).
const POLICY_PATH: &str = "../nonos-data/trust/policy/nonos_trust_anchor.policy.bin";

struct Artifacts {
    name: &'static str,
    bin_name: &'static str,
    elf_path: &'static str,
}

const VERIFIED: &[Artifacts] = &[
    Artifacts { name: "proof_io", bin_name: "proof_io", elf_path: "../userland/capsule_proof_io/target/x86_64-nonos-user/release/proof_io" },
    Artifacts { name: "ramfs", bin_name: "ramfs", elf_path: "../userland/capsule_ramfs/target/x86_64-nonos-user/release/ramfs" },
    Artifacts { name: "keyring", bin_name: "keyring", elf_path: "../userland/capsule_keyring/target/x86_64-nonos-user/release/keyring" },
    Artifacts { name: "entropy", bin_name: "entropy", elf_path: "../userland/capsule_entropy/target/x86_64-nonos-user/release/entropy" },
    Artifacts { name: "crypto", bin_name: "crypto", elf_path: "../userland/capsule_crypto/target/x86_64-nonos-user/release/crypto" },
    Artifacts { name: "vfs", bin_name: "vfs", elf_path: "../userland/capsule_vfs/target/x86_64-nonos-user/release/vfs" },
    Artifacts { name: "market", bin_name: "market", elf_path: "../userland/capsule_market/target/x86_64-nonos-user/release/market" },
    Artifacts { name: "driver.virtio_rng", bin_name: "driver_virtio_rng", elf_path: "../userland/capsule_driver_virtio_rng/target/x86_64-nonos-user/release/driver_virtio_rng" },
    Artifacts { name: "driver.virtio_gpu", bin_name: "driver_virtio_gpu", elf_path: "../userland/capsule_driver_virtio_gpu/target/x86_64-nonos-user/release/driver_virtio_gpu" },
    Artifacts { name: "driver.ps2_kbd0", bin_name: "driver_ps2_input", elf_path: "../userland/capsule_driver_ps2_input/target/x86_64-nonos-user/release/driver_ps2_input" },
    Artifacts { name: "driver.virtio_blk0", bin_name: "driver_virtio_blk", elf_path: "../userland/capsule_driver_virtio_blk/target/x86_64-nonos-user/release/driver_virtio_blk" },
    Artifacts { name: "driver.virtio_net0", bin_name: "driver_virtio_net", elf_path: "../userland/capsule_driver_virtio_net/target/x86_64-nonos-user/release/driver_virtio_net" },
    Artifacts { name: "driver.xhci0", bin_name: "driver_xhci", elf_path: "../userland/capsule_driver_xhci/target/x86_64-nonos-user/release/driver_xhci" },
    Artifacts { name: "driver.e1000_0", bin_name: "driver_e1000", elf_path: "../userland/capsule_driver_e1000/target/x86_64-nonos-user/release/driver_e1000" },
    Artifacts { name: "net.l2", bin_name: "net_l2", elf_path: "../userland/capsule_net_l2/target/x86_64-nonos-user/release/net_l2" },
    Artifacts { name: "net.ip", bin_name: "net_ip", elf_path: "../userland/capsule_net_ip/target/x86_64-nonos-user/release/net_ip" },
    Artifacts { name: "net.udp", bin_name: "net_udp", elf_path: "../userland/capsule_net_udp/target/x86_64-nonos-user/release/net_udp" },
    Artifacts { name: "net.dhcp", bin_name: "net_dhcp", elf_path: "../userland/capsule_net_dhcp/target/x86_64-nonos-user/release/net_dhcp" },
    Artifacts { name: "input_router", bin_name: "input_router", elf_path: "../userland/capsule_input_router/target/x86_64-nonos-user/release/input_router" },
    Artifacts { name: "compositor", bin_name: "compositor", elf_path: "../userland/compositor/target/x86_64-nonos-user/release/compositor" },
    Artifacts { name: "wm", bin_name: "wm", elf_path: "../userland/capsule_wm/target/x86_64-nonos-user/release/wm" },
    Artifacts { name: "desktop_shell", bin_name: "desktop_shell", elf_path: "../userland/capsule_desktop_shell/target/x86_64-nonos-user/release/desktop_shell" },
    Artifacts { name: "image_codec", bin_name: "image_codec", elf_path: "../userland/capsule_image_codec/target/x86_64-nonos-user/release/image_codec" },
    Artifacts { name: "clipboard", bin_name: "clipboard", elf_path: "../userland/capsule_clipboard/target/x86_64-nonos-user/release/clipboard" },
    Artifacts { name: "login", bin_name: "login", elf_path: "../userland/capsule_login/target/x86_64-nonos-user/release/login" },
    Artifacts { name: "wallpaper", bin_name: "wallpaper", elf_path: "../userland/capsule_wallpaper/target/x86_64-nonos-user/release/wallpaper" },
    Artifacts { name: "toolkit", bin_name: "toolkit", elf_path: "../userland/toolkit/target/x86_64-nonos-user/release/toolkit" },
    Artifacts { name: "app.about", bin_name: "about", elf_path: "../userland/capsule_about/target/x86_64-nonos-user/release/about" },
    Artifacts { name: "app.calculator", bin_name: "calculator", elf_path: "../userland/capsule_calculator/target/x86_64-nonos-user/release/calculator" },
    Artifacts { name: "app.terminal", bin_name: "terminal", elf_path: "../userland/capsule_terminal/target/x86_64-nonos-user/release/terminal" },
    Artifacts { name: "app.file_manager", bin_name: "file_manager", elf_path: "../userland/capsule_file_manager/target/x86_64-nonos-user/release/file_manager" },
    Artifacts { name: "app.text_editor", bin_name: "text_editor", elf_path: "../userland/capsule_text_editor/target/x86_64-nonos-user/release/text_editor" },
    Artifacts { name: "app.settings", bin_name: "settings", elf_path: "../userland/capsule_settings/target/x86_64-nonos-user/release/settings" },
    Artifacts { name: "app.process_manager", bin_name: "process_manager", elf_path: "../userland/capsule_process_manager/target/x86_64-nonos-user/release/process_manager" },
];

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("missing artifact {path}: {e}"))
}

fn cert_path(bin_name: &str) -> String {
    format!("../nonos-data/trust/capsules/{bin_name}.nonos_id_cert.bin")
}

fn manifest_path(bin_name: &str) -> String {
    format!("../nonos-data/trust/capsules/{bin_name}.manifest.bin")
}

fn stale_marker(bin_name: &str) -> String {
    format!("../nonos-data/trust/capsules/{bin_name}.STALE")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{b:02x}").expect("write to String cannot fail");
    }
    out
}

#[test]
fn on_disk_artifacts_verify_against_baked_policy() {
    let policy_bytes = read(POLICY_PATH);
    let policy =
        decode_trust_anchor_policy(&policy_bytes).expect("baked trust-anchor policy must decode");

    for a in VERIFIED {
        let cert_p = cert_path(a.bin_name);
        let manifest_p = manifest_path(a.bin_name);
        let stale_p = stale_marker(a.bin_name);

        if std::path::Path::new(&stale_p).exists() {
            panic!(
                "{}: STALE marker is not allowed in the production artifact gate: {}",
                a.name, stale_p
            );
        }

        let cert_bytes = read(&cert_p);
        let manifest_bytes = read(&manifest_p);

        let cert = decode_cert(&cert_bytes)
            .unwrap_or_else(|e| panic!("{}: cert decode failed: {:?}", a.name, e));
        verify_cert(&cert, &cert_bytes, &policy, REQUIRED_ALGS, Some(NOW_MS))
            .unwrap_or_else(|e| panic!("{}: cert verify failed: {:?}", a.name, e));

        let manifest = decode_manifest(&manifest_bytes)
            .unwrap_or_else(|e| panic!("{}: manifest decode failed: {:?}", a.name, e));
        verify_manifest(&manifest, &manifest_bytes, &cert, &cert_bytes, &policy, REQUIRED_ALGS)
            .unwrap_or_else(|e| panic!("{}: manifest verify failed: {:?}", a.name, e));

        let elf_bytes = read(a.elf_path);
        let computed = *blake3::hash(&elf_bytes).as_bytes();
        if computed != manifest.payload_hash {
            panic!(
                "{}: manifest payload_hash {} does not match ELF {} hash {}",
                a.name,
                hex_lower(&manifest.payload_hash),
                a.elf_path,
                hex_lower(&computed),
            );
        }
    }
}
