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

#[cfg(test)]
mod tests {
    use super::super::value::PortValue;
    use super::super::port::Port;
    use super::super::range::PortRange;

    #[test]
    fn test_port_value_sizes() {
        assert_eq!(u8::size(), 1);
        assert_eq!(u16::size(), 2);
        assert_eq!(u32::size(), 4);
    }

    #[test]
    fn test_port_creation() {
        let port8: Port<u8> = Port::new(0x3F8);
        let port16: Port<u16> = Port::new(0x1F0);
        let port32: Port<u32> = Port::new(0xCFC);

        assert_eq!(port8.port(), 0x3F8);
        assert_eq!(port16.port(), 0x1F0);
        assert_eq!(port32.port(), 0xCFC);
    }

    #[test]
    fn test_port_range() {
        let range = PortRange::new(0x100, 8);
        assert_eq!(range.start(), 0x100);
        assert_eq!(range.count(), 8);
        assert_eq!(range.end(), 0x108);

        assert!(range.contains(0x100));
        assert!(range.contains(0x107));
        assert!(!range.contains(0x108));
    }

    #[test]
    fn test_port_range_overlap() {
        let range1 = PortRange::new(0x100, 8);
        let range2 = PortRange::new(0x104, 8);
        let range3 = PortRange::new(0x108, 8);

        assert!(range1.overlaps(&range2));
        assert!(!range1.overlaps(&range3));
    }
}
