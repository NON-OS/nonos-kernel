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

use super::action::Sigaction;
use super::flags::SigactionFlags;
use crate::process::signal::set::SignalSet;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelSigaction {
    pub sa_handler: u64,
    pub sa_flags: u64,
    pub sa_restorer: u64,
    pub sa_mask: u64,
}

impl From<KernelSigaction> for Sigaction {
    fn from(ksa: KernelSigaction) -> Self {
        Self {
            handler: ksa.sa_handler as usize,
            flags: SigactionFlags::from_bits_truncate(ksa.sa_flags as u32),
            mask: SignalSet::from_bits(ksa.sa_mask),
            restorer: ksa.sa_restorer as usize,
        }
    }
}

impl From<&Sigaction> for KernelSigaction {
    fn from(action: &Sigaction) -> Self {
        Self {
            sa_handler: action.handler as u64,
            sa_flags: action.flags.bits() as u64,
            sa_restorer: action.restorer as u64,
            sa_mask: action.mask.as_bits(),
        }
    }
}
