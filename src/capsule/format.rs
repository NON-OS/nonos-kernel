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

pub const NOXC_MAGIC: u32 = 0x43584F4E;
pub const FORMAT_VERSION: u16 = 0x0001;
pub const HEADER_SIZE: usize = 64;
pub const SIG_SIZE: usize = 64;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CapsuleHeader {
    pub magic: u32,
    pub version: u16,
    pub flags: u16,
    pub manifest_off: u64,
    pub manifest_len: u64,
    pub binary_off: u64,
    pub binary_len: u64,
    pub assets_off: u64,
    pub assets_len: u64,
    pub sig_off: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError { TooSmall, BadMagic, BadVersion, BadOffset }

impl CapsuleHeader {
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < HEADER_SIZE { return Err(FormatError::TooSmall); }
        let h = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Self) };
        if h.magic != NOXC_MAGIC { return Err(FormatError::BadMagic); }
        if h.version != FORMAT_VERSION { return Err(FormatError::BadVersion); }
        if h.manifest_off < HEADER_SIZE as u64 { return Err(FormatError::BadOffset); }
        Ok(h)
    }

    pub fn manifest<'a>(&self, d: &'a [u8]) -> Option<&'a [u8]> {
        let s = self.manifest_off as usize;
        let e = s + self.manifest_len as usize;
        if e <= d.len() { Some(&d[s..e]) } else { None }
    }

    pub fn binary<'a>(&self, d: &'a [u8]) -> Option<&'a [u8]> {
        let s = self.binary_off as usize;
        let e = s + self.binary_len as usize;
        if e <= d.len() { Some(&d[s..e]) } else { None }
    }

    pub fn signature<'a>(&self, d: &'a [u8]) -> Option<&'a [u8]> {
        let s = self.sig_off as usize;
        if s + SIG_SIZE <= d.len() { Some(&d[s..s + SIG_SIZE]) } else { None }
    }

    pub fn signed_data<'a>(&self, d: &'a [u8]) -> Option<&'a [u8]> {
        let e = self.sig_off as usize;
        if e <= d.len() { Some(&d[..e]) } else { None }
    }
}
