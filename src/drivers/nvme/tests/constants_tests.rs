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
    use crate::drivers::nvme::constants;

    #[test]
    fn test_constants() {
        assert_eq!(constants::PAGE_SIZE, 4096);
        assert_eq!(constants::ADMIN_QUEUE_DEPTH, 32);
        assert_eq!(constants::IO_QUEUE_DEPTH, 256);
        assert_eq!(constants::SUBMISSION_ENTRY_SIZE, 64);
        assert_eq!(constants::COMPLETION_ENTRY_SIZE, 16);
    }

    #[test]
    fn test_doorbell_calculation() {
        let dstrd = 0;
        let qid = 1;

        let sq_offset = constants::doorbell_sq_offset(dstrd, qid);
        let cq_offset = constants::doorbell_cq_offset(dstrd, qid);

        assert_eq!(sq_offset, 0x1000 + 8);
        assert_eq!(cq_offset, 0x1000 + 12);
    }

    #[test]
    fn test_cap_helpers() {
        let cap: u64 = 0x00200028_0002_01FF;

        assert_eq!(constants::cap_mqes(cap), 0x01FF);
        assert_eq!(constants::cap_dstrd(cap), 0);
    }

    #[test]
    fn test_aqa_encoding() {
        let aqa = constants::aqa(32, 32);
        assert_eq!(aqa & 0xFFF, 31);
        assert_eq!((aqa >> 16) & 0xFFF, 31);
    }

    #[test]
    fn test_version_parsing() {
        assert_eq!(constants::version_major(0x00010400), 1);
        assert_eq!(constants::version_minor(0x00010400), 4);
        assert_eq!(constants::version_tertiary(0x00010400), 0);
    }
}
