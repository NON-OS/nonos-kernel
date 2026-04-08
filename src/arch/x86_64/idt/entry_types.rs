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

pub trait FnPtr {
    fn addr(self) -> u64;
}

impl<T> FnPtr for T
where
    T: Copy,
{
    #[inline]
    fn addr(self) -> u64 {
        let ptr = &self as *const T as *const ();
        unsafe { core::ptr::read(ptr as *const u64) }
    }
}

pub type ExceptionHandler = extern "C" fn(&mut super::entry_frame::InterruptFrame);
pub type ExceptionHandlerWithError = extern "C" fn(&mut super::entry_frame::InterruptFrame, u64);
