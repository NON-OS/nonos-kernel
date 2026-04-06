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

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsercopyError {
    NullPointer,
    InvalidAddress,
    AddressOverflow,
    PageNotMapped,
    PageNotUser,
    PageNotWritable,
    PageFault,
    NoProcessContext,
    SizeTooLarge,
    UnalignedPointer,
}

impl fmt::Display for UsercopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullPointer => write!(f, "null pointer"),
            Self::InvalidAddress => write!(f, "invalid user address"),
            Self::AddressOverflow => write!(f, "address overflow"),
            Self::PageNotMapped => write!(f, "page not mapped"),
            Self::PageNotUser => write!(f, "page not accessible from userspace"),
            Self::PageNotWritable => write!(f, "page not writable"),
            Self::PageFault => write!(f, "page fault during access"),
            Self::NoProcessContext => write!(f, "no process context"),
            Self::SizeTooLarge => write!(f, "copy size too large"),
            Self::UnalignedPointer => write!(f, "user pointer is not aligned for the target type"),
        }
    }
}
