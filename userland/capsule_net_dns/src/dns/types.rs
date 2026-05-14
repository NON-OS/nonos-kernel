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

pub const NAME_MAX: usize = 255;
pub const LABEL_MAX: usize = 63;
pub const POINTER_MASK: u8 = 0xC0;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;

pub const CLASS_IN: u16 = 1;

#[derive(Clone, Copy, Debug)]
pub struct Question<'a> {
    pub qname: &'a [u8],
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct ResourceRecord<'a> {
    pub name: &'a [u8],
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
}
