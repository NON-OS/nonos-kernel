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

use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM};
use crate::shell::output::print_line;

extern crate alloc;
use alloc::format;

pub fn cmd_capsule_install(cid: &str) {
    if cid.is_empty() {
        print_line(b"Usage: capsule-install <ipfs-cid>", COLOR_TEXT_DIM);
        return;
    }

    if !cid.starts_with("Qm") && !cid.starts_with("bafy") {
        print_line(b"Invalid IPFS CID format", COLOR_RED);
        return;
    }

    print_line(b"Downloading capsule...", COLOR_TEXT);
    let cid_line = format!("CID: {}", cid);
    print_line(cid_line.as_bytes(), COLOR_TEXT_DIM);

    match crate::network::ipfs::fetch(cid) {
        Ok(data) => {
            let size_line = format!("Downloaded {} bytes", data.len());
            print_line(size_line.as_bytes(), COLOR_GREEN);
            print_line(b"Capsule cached successfully", COLOR_GREEN);
            print_line(b"Use capsule-run to execute", COLOR_TEXT_DIM);
        }
        Err(_) => {
            print_line(b"Download failed: network error", COLOR_RED);
        }
    }
}
