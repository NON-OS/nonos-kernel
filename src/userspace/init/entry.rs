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

use super::supervisor::init_loop;
use crate::sys::boot_log;

pub fn run_init() -> ! {
    boot_log::ok("INIT", "Starting");
    crate::sys::serial::println(b"[INIT-TRACE] before spawn_ramfs_capsule");
    spawn_ramfs_capsule();
    crate::sys::serial::println(b"[INIT-TRACE] after spawn_ramfs_capsule");
    #[cfg(feature = "nonos-ramfs-smoketest")]
    {
        for _ in 0..200 {
            crate::sched::yield_now();
        }
        crate::fs::ramfs_capsule::smoketest::run();
    }

    spawn_keyring_capsule();
    spawn_entropy_capsule();
    spawn_crypto_capsule();
    spawn_vfs_capsule();
    #[cfg(feature = "nonos-capsule-market")]
    spawn_market_capsule();
    #[cfg(feature = "nonos-capsule-driver-virtio-rng")]
    spawn_driver_virtio_rng_capsule();
    #[cfg(feature = "nonos-capsule-driver-virtio-blk")]
    spawn_driver_virtio_blk_capsule();
    #[cfg(feature = "nonos-capsule-driver-virtio-net")]
    spawn_driver_virtio_net_capsule();
    #[cfg(feature = "nonos-capsule-driver-ps2-input")]
    spawn_driver_ps2_input_capsule();
    #[cfg(feature = "nonos-capsule-driver-xhci")]
    spawn_driver_xhci_capsule();
    #[cfg(feature = "nonos-keyring-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_KEYRING,
        crate::security::keyring_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-entropy-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_ENTROPY,
        crate::security::entropy_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-crypto-hash-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_CRYPTO,
        crate::security::crypto_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-vfs-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_VFS,
        crate::fs::vfs_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-virtio-rng-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::virtio_rng_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-market-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_APPS,
        crate::security::market_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-virtio-blk-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::virtio_blk_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-virtio-net-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::virtio_net_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-ps2-input-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::ps2_kbd_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-xhci-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::xhci_capsule::smoketest::run,
    );

    boot_log::ok("INIT", "Capsules spawned");
    lower_init_priority();
    for _ in 0..100 {
        crate::sched::yield_now();
    }
    // Replaces the init image with a one-shot proof binary and
    // transfers to CPL=3; control does not return here on
    // success. The wallpaper smoke profile swaps out the binary
    // for the graphics-syscall round trip; production builds
    // launch proof_io.
    #[cfg(feature = "nonos-wallpaper-smoketest")]
    crate::userspace::capsule_wallpaper::launch();
    #[cfg(not(feature = "nonos-wallpaper-smoketest"))]
    crate::userspace::capsule_proof_io::launch();
    init_loop()
}

fn lower_init_priority() {
    use crate::process::core::{Priority, CURRENT_PID, PROCESS_TABLE};
    use core::sync::atomic::Ordering;
    let pid = CURRENT_PID.load(Ordering::Relaxed);
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.priority.lock() = Priority::Low;
    }
}

fn spawn_ramfs_capsule() {
    use crate::fs::ramfs_capsule;
    super::capsule_boot::boot(
        "RAMFS",
        "ramfs",
        ramfs_capsule::spawn_ramfs_capsule,
        ramfs_capsule::shared_state,
    );
}

fn spawn_keyring_capsule() {
    use crate::security::keyring_capsule;
    super::capsule_boot::boot(
        "KEYRING",
        "keyring",
        keyring_capsule::spawn_keyring_capsule,
        keyring_capsule::shared_state,
    );
}

fn spawn_entropy_capsule() {
    use crate::security::entropy_capsule;
    super::capsule_boot::boot(
        "ENTROPY",
        "entropy",
        entropy_capsule::spawn_entropy_capsule,
        entropy_capsule::shared_state,
    );
}

fn spawn_crypto_capsule() {
    use crate::security::crypto_capsule;
    super::capsule_boot::boot(
        "CRYPTO",
        "crypto",
        crypto_capsule::spawn_crypto_capsule,
        crypto_capsule::shared_state,
    );
}

fn spawn_vfs_capsule() {
    use crate::fs::vfs_capsule;
    super::capsule_boot::boot(
        "VFS",
        "vfs",
        vfs_capsule::spawn_vfs_capsule,
        vfs_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-virtio-rng")]
fn spawn_driver_virtio_rng_capsule() {
    use crate::hardware::virtio_rng_capsule;
    super::capsule_boot::boot(
        "DRIVER-VIRTIO-RNG",
        "driver_virtio_rng",
        virtio_rng_capsule::spawn_driver_virtio_rng_capsule,
        virtio_rng_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-market")]
fn spawn_market_capsule() {
    use crate::security::market_capsule;
    super::capsule_boot::boot(
        "MARKET",
        "market",
        market_capsule::spawn_market_capsule,
        market_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-virtio-blk")]
fn spawn_driver_virtio_blk_capsule() {
    use crate::hardware::virtio_blk_capsule;
    super::capsule_boot::boot(
        "DRIVER-VIRTIO-BLK",
        "driver_virtio_blk",
        virtio_blk_capsule::spawn_driver_virtio_blk_capsule,
        virtio_blk_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-virtio-net")]
fn spawn_driver_virtio_net_capsule() {
    use crate::hardware::virtio_net_capsule;
    super::capsule_boot::boot(
        "DRIVER-VIRTIO-NET",
        "driver_virtio_net",
        virtio_net_capsule::spawn_driver_virtio_net_capsule,
        virtio_net_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-ps2-input")]
fn spawn_driver_ps2_input_capsule() {
    use crate::hardware::ps2_kbd_capsule;
    super::capsule_boot::boot(
        "DRIVER-PS2-INPUT",
        "driver_ps2_input",
        ps2_kbd_capsule::spawn_driver_ps2_input_capsule,
        ps2_kbd_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-xhci")]
fn spawn_driver_xhci_capsule() {
    use crate::hardware::xhci_capsule;
    super::capsule_boot::boot(
        "DRIVER-XHCI",
        "driver_xhci",
        xhci_capsule::spawn_driver_xhci_capsule,
        xhci_capsule::shared_state,
    );
}
