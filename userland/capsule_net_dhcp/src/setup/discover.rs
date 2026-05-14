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

use nonos_libc::mk_service_lookup;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverError {
    NotFound,
}

fn lookup(name: &str) -> Result<u32, DiscoverError> {
    let mut port: u32 = 0;
    let mut pid: u32 = 0;
    let rc = mk_service_lookup(name.as_ptr(), name.len(), &mut port, &mut pid);
    if rc != 0 || port == 0 {
        return Err(DiscoverError::NotFound);
    }
    Ok(port)
}

pub fn net_l2() -> Result<u32, DiscoverError> {
    lookup("net.l2")
}

pub fn net_ip() -> Result<u32, DiscoverError> {
    lookup("net.ip")
}
