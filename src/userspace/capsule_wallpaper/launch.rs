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

use super::embed::{WALLPAPER_ELF, WALLPAPER_PATH};
use super::spawn::spawn_wallpaper_capsule;
use crate::capabilities::Capability;
use crate::kernel_core::process_spawn::capsule_spawn::SpawnError;

const WALLPAPER_CAPS: &[Capability] = &[
    Capability::CoreExec,
    Capability::Memory,
    Capability::Debug,
    Capability::GraphicsDisplayQuery,
    Capability::GraphicsSurfaceCreate,
    Capability::GraphicsSurfaceMap,
    Capability::GraphicsPresent,
];

fn spawn_err_name(err: SpawnError) -> &'static str {
    match err {
        SpawnError::FeatureDisabled => "FeatureDisabled",
        SpawnError::ElfLoad => "ElfLoad",
        SpawnError::ProcessCreation => "ProcessCreation",
        SpawnError::AddressSpace => "AddressSpace",
        SpawnError::EndpointCollision => "EndpointCollision",
        SpawnError::NonosIdCertRejected(_) => "NonosIdCertRejected",
        SpawnError::ManifestRejected(_) => "ManifestRejected",
    }
}

fn install_wallpaper_caps() -> Result<(), &'static str> {
    let pid = crate::process::current_process()
        .ok_or("wallpaper: no current process")?
        .pid;
    let mut mask: u64 = 0;
    for cap in WALLPAPER_CAPS {
        mask |= cap.bit();
    }
    crate::process::caps::grant(pid, mask).ok_or("wallpaper: cap grant failed")?;
    Ok(())
}

/// Run the wallpaper capsule once. The current process's address
/// space is replaced by the wallpaper binary and control transfers
/// to its `_start` in CPL=3. The binary drives the graphics
/// syscall round trip (display_dimensions, surface_create,
/// surface_map, surface_present_full, surface_destroy) and exits.
///
/// Off when the `nonos-capsule-wallpaper` feature is disabled.
pub fn launch() {
    crate::sys::serial::println(b"[WALLPAPER-RC] wallpaper launch entered");
    if WALLPAPER_ELF.is_empty() {
        crate::sys::serial::println(b"[WALLPAPER-RC] wallpaper launch skipped: empty elf");
        return;
    }
    if let Err(e) = install_wallpaper_caps() {
        crate::sys::serial::println(b"[NONOS] wallpaper: cap install failed");
        let _ = e;
        return;
    }
    crate::sys::serial::println(b"[NONOS] wallpaper: launching from /capsules/wallpaper");
    if let Err(e) = crate::process::exec_process(WALLPAPER_PATH, &[], &[]) {
        crate::sys::serial::println(b"[NONOS] wallpaper: exec failed");
        crate::sys::serial::println(e.as_bytes());
        if e == "VFS not initialized" {
            crate::sys::serial::println(b"[NONOS] wallpaper: falling back to embedded spawn");
            if let Err(err) = spawn_wallpaper_capsule() {
                crate::sys::serial::println(b"[NONOS] wallpaper: spawn fallback failed");
                crate::sys::serial::println(spawn_err_name(err).as_bytes());
            }
        }
    }
    crate::sys::serial::println(b"[NONOS] wallpaper: launch returned");
}
