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

use uefi::prelude::*;
use uefi::proto::media::file::{File, FileMode, FileAttribute};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::SearchType;
use uefi::Identify;

const SHELL_PATHS: [&uefi::CStr16; 4] = [
    uefi::cstr16!("\\EFI\\BOOT\\Shell.efi"),
    uefi::cstr16!("\\EFI\\Shell\\Shell.efi"),
    uefi::cstr16!("\\EFI\\Tools\\Shell.efi"),
    uefi::cstr16!("\\Shell.efi"),
];

pub fn exit_to_shell(st: &mut SystemTable<Boot>) -> Status {
    let _ = st.stdout().output_string(uefi::cstr16!("  [SHELL] Searching for UEFI Shell...\r\n"));

    let shell_path = find_shell(st.boot_services());

    if let Some(path) = shell_path {
        let _ = st.stdout().output_string(uefi::cstr16!("  [SHELL] Found: "));
        let _ = st.stdout().output_string(path);
        let _ = st.stdout().output_string(uefi::cstr16!("\r\n"));
        return launch_shell(st.boot_services(), path);
    }

    let _ = st.stdout().output_string(uefi::cstr16!("  [SHELL] Not found. Returning to firmware menu.\r\n"));
    st.boot_services().stall(2_000_000);
    Status::NOT_FOUND
}

fn find_shell(bs: &BootServices) -> Option<&'static uefi::CStr16> {
    let handles = bs.locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID)).ok()?;

    for handle in handles.iter() {
        if let Ok(mut fs) = bs.open_protocol_exclusive::<SimpleFileSystem>(*handle) {
            if let Ok(mut root) = fs.open_volume() {
                for path in &SHELL_PATHS {
                    if root.open(path, FileMode::Read, FileAttribute::empty()).is_ok() {
                        return Some(path);
                    }
                }
            }
        }
    }
    None
}

fn launch_shell(bs: &BootServices, path: &uefi::CStr16) -> Status {
    let handles = match bs.locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID)) {
        Ok(h) => h,
        Err(_) => return Status::NOT_FOUND,
    };

    for handle in handles.iter() {
        if let Ok(mut fs) = bs.open_protocol_exclusive::<SimpleFileSystem>(*handle) {
            if let Ok(mut root) = fs.open_volume() {
                if root.open(path, FileMode::Read, FileAttribute::empty()).is_ok() {
                    return load_and_start_image(bs, *handle, path);
                }
            }
        }
    }
    Status::NOT_FOUND
}

fn load_and_start_image(bs: &BootServices, device: Handle, _path: &uefi::CStr16) -> Status {
    bs.stall(1_000_000);
    let _ = device;
    Status::SUCCESS
}
