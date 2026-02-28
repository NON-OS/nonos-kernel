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
    use super::super::tsc::rdtsc;
    use super::super::cpuid::cpuid;
    use super::super::control_regs::{read_cr0, read_cr3, read_cr4};

    #[test]
    fn test_rdtsc_monotonic() {
        let t1 = rdtsc();
        let t2 = rdtsc();
        assert!(t2 >= t1);
    }

    #[test]
    fn test_cpuid() {
        let (eax, _, _, _) = cpuid(0);
        assert!(eax >= 1);
    }

    #[test]
    fn test_read_cr0() {
        let cr0 = read_cr0();
        assert!(cr0 & 1 != 0);
    }

    #[test]
    fn test_read_cr3() {
        let cr3 = read_cr3();
        assert!(cr3 != 0);
    }

    #[test]
    fn test_read_cr4() {
        let cr4 = read_cr4();
        assert!(cr4 & (1 << 5) != 0);
    }
}
