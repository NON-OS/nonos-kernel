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

pub use super::constants_cr::*;
pub use super::constants_msr::*;
pub use super::constants_segments::*;
pub use super::constants_stack::*;
pub use super::constants_xcr::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_stack_alignment() {
        assert_eq!(BOOT_STACK_TOP % 16, 0);
    }

    #[test]
    fn test_cr_flags() {
        assert_eq!(CR0_PG, 0x80000000);
        assert_eq!(CR4_PAE, 0x20);
    }

    #[test]
    fn test_xcr0_flags() {
        assert_eq!(XCR0_X87 | XCR0_SSE | XCR0_AVX, 0x07);
    }
}
