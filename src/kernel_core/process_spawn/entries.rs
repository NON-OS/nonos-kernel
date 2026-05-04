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
// arm below resolves to a kernel-resident `*_engine` wrapper in
// `crate::services::*`, which is gated behind `nonos-legacy-tree`.
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
    crate::services::vfs_engine::run_vfs_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_net() {
    crate::services::net_engine::run_net_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_display() {
    crate::services::display_engine::run_display_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_drivers() {
    crate::services::driver_engine::run_driver_manager();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_crypto() {
    crate::services::crypto_engine::run_crypto_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_zk() {
    crate::services::zk_engine::run_zk_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_input() {
    crate::services::input_engine::run_input_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_audio() {
    crate::services::audio_engine::run_audio_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_gpu() {
    crate::services::gpu_engine::run_gpu_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_apps() {
    crate::services::apps_engine::run_apps_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_agents() {
    crate::services::agents_engine::run_agents_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_shell() {
    crate::services::shell_engine::run_shell_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_kworker() {
    crate::services::kworker_engine::run_kworker_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_softirq() {
    crate::services::softirq_engine::run_softirq_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_entropy() {
    crate::services::entropy_engine::run_entropy_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_aes() {
    crate::services::aes_engine::run_aes_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_chacha() {
    crate::services::chacha_engine::run_chacha_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_sha3() {
    crate::services::sha3_engine::run_sha3_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_blake3() {
    crate::services::blake3_engine::run_blake3_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_ed25519() {
    crate::services::ed25519_engine::run_ed25519_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_secp256k1() {
    crate::services::secp256k1_engine::run_secp256k1_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_zkprover() {
    crate::services::zkprover_engine::run_zkprover_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_groth16() {
    crate::services::groth16_engine::run_groth16_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_plonk() {
    crate::services::plonk_engine::run_plonk_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_kyber() {
    crate::services::kyber_engine::run_kyber_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_dilithium() {
    crate::services::dilithium_engine::run_dilithium_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_netmgr() {
    crate::services::netmgr_engine::run_netmgr_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_tls() {
    crate::services::tls_engine::run_tls_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_wallet() {
    crate::services::wallet_engine::run_wallet_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_storage() {
    crate::services::storage_engine::run_storage_service();
}
#[cfg(feature = "nonos-legacy-tree")]
fn svc_udev() {
    crate::services::udev_engine::run_udev_service();
}

#[cfg(feature = "nonos-legacy-tree")]
fn svc_desktop() {
    crate::sys::serial::println(b"[DESKTOP] kernel-resident wrapper inert; awaiting capsule_desktop");
    loop {
        crate::sched::yield_now();
    }
}
