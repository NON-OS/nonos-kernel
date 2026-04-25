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

use alloc::vec::Vec;

pub const SCM_RIGHTS: u32 = 1;
pub const SCM_CREDENTIALS: u32 = 2;
pub const SOL_SOCKET: u32 = 1;

#[derive(Debug, Clone)]
pub enum AncillaryData {
    Rights(ScmRights),
    Credentials(ScmCredentials),
    SourcePath(alloc::string::String),
}

impl AncillaryData {
    pub fn from_path(path: &str) -> Self {
        AncillaryData::SourcePath(alloc::string::String::from(path))
    }

    pub fn get_source_path(&self) -> Option<alloc::string::String> {
        match self {
            AncillaryData::SourcePath(p) => Some(p.clone()),
            _ => None,
        }
    }

    pub fn get_fds(&self) -> Option<&[i32]> {
        match self {
            AncillaryData::Rights(r) => Some(&r.fds),
            _ => None,
        }
    }

    pub fn get_credentials(&self) -> Option<ScmCredentials> {
        match self {
            AncillaryData::Credentials(c) => Some(*c),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScmRights {
    pub fds: Vec<i32>,
}

#[derive(Debug, Clone, Copy)]
pub struct ScmCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[repr(C)]
struct CmsgHdr {
    cmsg_len: usize,
    cmsg_level: u32,
    cmsg_type: u32,
}

pub fn parse_ancillary(data: &[u8]) -> Result<Vec<AncillaryData>, i32> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset + 12 <= data.len() {
        let hdr = unsafe { &*(data.as_ptr().add(offset) as *const CmsgHdr) };
        if hdr.cmsg_len < 12 || offset + hdr.cmsg_len > data.len() {
            break;
        }
        let payload = &data[offset + 12..offset + hdr.cmsg_len];
        if hdr.cmsg_level == SOL_SOCKET {
            match hdr.cmsg_type {
                SCM_RIGHTS => {
                    let fds: Vec<i32> = payload
                        .chunks_exact(4)
                        .map(|c| i32::from_ne_bytes([c[0], c[1], c[2], c[3]]))
                        .collect();
                    result.push(AncillaryData::Rights(ScmRights { fds }));
                }
                SCM_CREDENTIALS => {
                    if payload.len() >= 12 {
                        let creds = ScmCredentials {
                            pid: i32::from_ne_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]),
                            uid: u32::from_ne_bytes([
                                payload[4], payload[5], payload[6], payload[7],
                            ]),
                            gid: u32::from_ne_bytes([
                                payload[8],
                                payload[9],
                                payload[10],
                                payload[11],
                            ]),
                        };
                        result.push(AncillaryData::Credentials(creds));
                    }
                }
                _ => {}
            }
        }
        offset += (hdr.cmsg_len + 7) & !7;
    }
    Ok(result)
}

pub fn build_ancillary(items: &[AncillaryData]) -> Vec<u8> {
    let mut result = Vec::new();
    for item in items {
        match item {
            AncillaryData::Rights(r) => {
                let payload_len = r.fds.len() * 4;
                let total_len = 12 + payload_len;
                result.extend(&total_len.to_ne_bytes());
                result.extend(&SOL_SOCKET.to_ne_bytes());
                result.extend(&SCM_RIGHTS.to_ne_bytes());
                for fd in &r.fds {
                    result.extend(&fd.to_ne_bytes());
                }
                while result.len() % 8 != 0 {
                    result.push(0);
                }
            }
            AncillaryData::Credentials(c) => {
                let total_len: usize = 12 + 12;
                result.extend(&total_len.to_ne_bytes());
                result.extend(&SOL_SOCKET.to_ne_bytes());
                result.extend(&SCM_CREDENTIALS.to_ne_bytes());
                result.extend(&c.pid.to_ne_bytes());
                result.extend(&c.uid.to_ne_bytes());
                result.extend(&c.gid.to_ne_bytes());
                while result.len() % 8 != 0 {
                    result.push(0);
                }
            }
            AncillaryData::SourcePath(_path) => {}
        }
    }
    result
}
