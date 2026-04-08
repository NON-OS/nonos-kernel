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
use alloc::string::String;
use spin::RwLock;

pub const GATEWAYS: [&str; 4] = [
    "https://ipfs.io/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://dweb.link/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
];

static ACTIVE_GW: RwLock<usize> = RwLock::new(0);

pub fn get_url(cid: &str) -> String {
    let idx = *ACTIVE_GW.read();
    alloc::format!("{}{}", GATEWAYS[idx], cid)
}

pub fn rotate_gateway() {
    let mut idx = ACTIVE_GW.write();
    *idx = (*idx + 1) % GATEWAYS.len();
}

pub fn set_gateway(idx: usize) {
    if idx < GATEWAYS.len() { *ACTIVE_GW.write() = idx; }
}

pub fn current_gateway() -> &'static str {
    GATEWAYS[*ACTIVE_GW.read()]
}
