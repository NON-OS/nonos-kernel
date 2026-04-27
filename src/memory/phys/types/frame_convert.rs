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

use super::frame::Frame;
use x86_64::PhysAddr;

impl From<u64> for Frame {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<Frame> for u64 {
    fn from(frame: Frame) -> u64 {
        frame.0
    }
}

impl From<PhysAddr> for Frame {
    fn from(addr: PhysAddr) -> Self {
        Self(addr.as_u64())
    }
}

impl From<Frame> for PhysAddr {
    fn from(frame: Frame) -> PhysAddr {
        PhysAddr::new(frame.0)
    }
}
