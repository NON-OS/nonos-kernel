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

pub(crate) fn get_service_entry(name: &str) -> Option<fn()> {
    match name {
        "vfs" => Some(svc_vfs),
        "network" => Some(svc_net),
        "display" => Some(svc_display),
        "drivers" => Some(svc_drivers),
        "crypto" => Some(svc_crypto),
        "zk" => Some(svc_zk),
        "input" => Some(svc_input),
        "audio" => Some(svc_audio),
        "gpu" => Some(svc_gpu),
        "apps" => Some(svc_apps),
        "agents" => Some(svc_agents),
        "shell" => Some(svc_shell),
        "desktop" => Some(svc_desktop),
        "kworker" => Some(svc_kworker),
        "softirq" => Some(svc_softirq),
        "entropy" => Some(svc_entropy),
        "keyring" => Some(svc_keyring),
        "aes" => Some(svc_aes),
        "chacha" => Some(svc_chacha),
        "sha3" => Some(svc_sha3),
        "blake3" => Some(svc_blake3),
        "ed25519" => Some(svc_ed25519),
        "secp256k1" => Some(svc_secp256k1),
        "zkprover" => Some(svc_zkprover),
        "groth16" => Some(svc_groth16),
        "plonk" => Some(svc_plonk),
        "kyber" => Some(svc_kyber),
        "dilithium" => Some(svc_dilithium),
        "netmgr" => Some(svc_netmgr),
        "tls" => Some(svc_tls),
        "wallet" => Some(svc_wallet),
        "storage" => Some(svc_storage),
        "udev" => Some(svc_udev),
        _ => None,
    }
}

fn svc_vfs() {
    crate::userspace::run_vfs_service();
}
fn svc_net() {
    crate::userspace::run_net_service();
}
fn svc_display() {
    crate::userspace::run_display_service();
}
fn svc_drivers() {
    crate::userspace::run_driver_manager();
}
fn svc_crypto() {
    crate::userspace::run_crypto_service();
}
fn svc_zk() {
    crate::userspace::run_zk_service();
}
fn svc_input() {
    crate::userspace::run_input_service();
}
fn svc_audio() {
    crate::userspace::run_audio_service();
}
fn svc_gpu() {
    crate::userspace::run_gpu_service();
}
fn svc_apps() {
    crate::userspace::run_apps_service();
}
fn svc_agents() {
    crate::userspace::run_agents_service();
}
fn svc_shell() {
    crate::userspace::run_shell_service();
}
fn svc_kworker() {
    crate::userspace::run_kworker_service();
}
fn svc_softirq() {
    crate::userspace::run_softirq_service();
}
fn svc_entropy() {
    crate::userspace::run_entropy_service();
}
fn svc_keyring() {
    crate::userspace::run_keyring_service();
}
fn svc_aes() {
    crate::userspace::run_aes_service();
}
fn svc_chacha() {
    crate::userspace::run_chacha_service();
}
fn svc_sha3() {
    crate::userspace::run_sha3_service();
}
fn svc_blake3() {
    crate::userspace::run_blake3_service();
}
fn svc_ed25519() {
    crate::userspace::run_ed25519_service();
}
fn svc_secp256k1() {
    crate::userspace::run_secp256k1_service();
}
fn svc_zkprover() {
    crate::userspace::run_zkprover_service();
}
fn svc_groth16() {
    crate::userspace::run_groth16_service();
}
fn svc_plonk() {
    crate::userspace::run_plonk_service();
}
fn svc_kyber() {
    crate::userspace::run_kyber_service();
}
fn svc_dilithium() {
    crate::userspace::run_dilithium_service();
}
fn svc_netmgr() {
    crate::userspace::run_netmgr_service();
}
fn svc_tls() {
    crate::userspace::run_tls_service();
}
fn svc_wallet() {
    crate::userspace::run_wallet_service();
}
fn svc_storage() {
    crate::userspace::run_storage_service();
}
fn svc_udev() {
    crate::userspace::run_udev_service();
}

fn svc_desktop() {
    crate::sys::serial::println(b"[DESKTOP] Service started");
    crate::graphics::framebuffer::fill_rect(0, 0, 100, 100, 0xFF00FF00);
    if crate::boot::main::graphics_init::init_graphics_for_microkernel() {
        crate::sys::serial::println(b"[DESKTOP] Running desktop loop");
        crate::boot::main::desktop_run::run_desktop();
    }
    crate::sys::serial::println(b"[DESKTOP] Failed to init graphics");
    loop {
        crate::sched::yield_now();
    }
}
