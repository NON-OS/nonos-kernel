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

// Service-name → entry-fn dispatcher. The microkernel build does not
// reach this dispatcher: the real userland capsules (proof_io, ramfs,
// keyring) are spawned through their own kernel-side mirrors. Every
// arm below resolves to a kernel-resident `*_service` wrapper in
// `crate::userspace::*`, which is gated behind `nonos-legacy-tree`.
// Keeping the dispatcher under the same flag prevents it from dragging
// the legacy graph into the active build.

#[cfg(feature = "nonos-legacy-tree")]
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

// In the microkernel build there are no kernel-resident services to
// dispatch. The capsule spawn paths set up their own initial context
// directly via `setup_initial_context`.
#[cfg(not(feature = "nonos-legacy-tree"))]
pub(crate) fn get_service_entry(_name: &str) -> Option<fn()> {
    None
}

#[cfg(feature = "nonos-legacy-tree")]
fn svc_vfs() {
    crate::userspace::run_vfs_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_net() {
    crate::userspace::run_net_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_display() {
    crate::userspace::run_display_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_drivers() {
    crate::userspace::run_driver_manager();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_crypto() {
    crate::userspace::run_crypto_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_zk() {
    crate::userspace::run_zk_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_input() {
    crate::userspace::run_input_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_audio() {
    crate::userspace::run_audio_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_gpu() {
    crate::userspace::run_gpu_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_apps() {
    crate::userspace::run_apps_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_agents() {
    crate::userspace::run_agents_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_shell() {
    crate::userspace::run_shell_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_kworker() {
    crate::userspace::run_kworker_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_softirq() {
    crate::userspace::run_softirq_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_entropy() {
    crate::userspace::run_entropy_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_aes() {
    crate::userspace::run_aes_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_chacha() {
    crate::userspace::run_chacha_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_sha3() {
    crate::userspace::run_sha3_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_blake3() {
    crate::userspace::run_blake3_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_ed25519() {
    crate::userspace::run_ed25519_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_secp256k1() {
    crate::userspace::run_secp256k1_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_zkprover() {
    crate::userspace::run_zkprover_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_groth16() {
    crate::userspace::run_groth16_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_plonk() {
    crate::userspace::run_plonk_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_kyber() {
    crate::userspace::run_kyber_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_dilithium() {
    crate::userspace::run_dilithium_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_netmgr() {
    crate::userspace::run_netmgr_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_tls() {
    crate::userspace::run_tls_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_wallet() {
    crate::userspace::run_wallet_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_storage() {
    crate::userspace::run_storage_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_udev() {
    crate::userspace::run_udev_service();
}

#[cfg(feature = "nonos-legacy-tree")]
fn svc_desktop() {
    crate::sys::serial::println(b"[DESKTOP] Service started");
    crate::graphics::framebuffer::fill_rect(0, 0, 100, 100, 0xFF00FF00);
    #[cfg(target_arch = "x86_64")]
    {
        if crate::boot::main::graphics_init::init_graphics_for_microkernel() {
            crate::sys::serial::println(b"[DESKTOP] Running desktop loop");
            crate::boot::main::desktop_run::run_desktop();
        }
    }
    crate::sys::serial::println(b"[DESKTOP] Failed to init graphics");
    loop {
        crate::sched::yield_now();
    }
}
