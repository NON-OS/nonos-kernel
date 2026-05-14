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

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct Submission {
    pub cdw0: u32,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl Submission {
    pub const fn identify_controller(cid: u16, prp1: u64) -> Self {
        Self {
            cdw0: 0x06 | ((cid as u32) << 16),
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1,
            prp2: 0,
            cdw10: 1,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    pub const fn identify_namespace(cid: u16, nsid: u32, prp1: u64) -> Self {
        Self {
            cdw0: 0x06 | ((cid as u32) << 16),
            nsid,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    pub const fn get_log_page(cid: u16, nsid: u32, lid: u8, bytes: u32, prp1: u64) -> Self {
        let dwords = bytes / 4;
        let numd = dwords - 1;
        Self {
            cdw0: 0x02 | ((cid as u32) << 16),
            nsid,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1,
            prp2: 0,
            cdw10: (lid as u32) | ((numd & 0xffff) << 16),
            cdw11: (numd >> 16) & 0xffff,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }
}

const _: () = assert!(core::mem::size_of::<Submission>() == 64);
