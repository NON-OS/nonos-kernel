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

mod core;
mod registers;
mod trb;
mod usb;

pub use self::core::*;
pub use registers::*;
pub use trb::*;
pub use usb::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portsc_change_bits() {
        assert_eq!(PORTSC_CHANGE_BITS & PORTSC_CSC, PORTSC_CSC);
        assert_eq!(PORTSC_CHANGE_BITS & PORTSC_PED, 0);
    }

    #[test]
    fn test_trb_alignment() {
        assert_eq!(TRB_ALIGNMENT, 16);
        assert!(DMA_MIN_ALIGNMENT >= TRB_ALIGNMENT as usize);
    }
}
