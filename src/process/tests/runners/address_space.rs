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

use crate::process::tests::address_space_types_tests as t;
use crate::test::framework::{TestCase, TestSuite};

pub fn register(s: &mut TestSuite) {
    s.add(TestCase::new("page_size_constant", t::test_page_size_constant));
    s.add(TestCase::new("large_page_size_constant", t::test_large_page_size_constant));
    s.add(TestCase::new("huge_page_size_constant", t::test_huge_page_size_constant));
    s.add(TestCase::new("user_space_end_constant", t::test_user_space_end_constant));
    s.add(TestCase::new("kernel_space_start_constant", t::test_kernel_space_start_constant));
    s.add(TestCase::new("max_pcid_constant", t::test_max_pcid_constant));
    s.add(TestCase::new("vma_new", t::test_vma_new));
    s.add(TestCase::new("vma_size", t::test_vma_size));
    s.add(TestCase::new("vma_contains", t::test_vma_contains));
    s.add(TestCase::new("vma_overlaps", t::test_vma_overlaps));
    s.add(TestCase::new("vma_overlaps_subset", t::test_vma_overlaps_subset));
    s.add(TestCase::new("vma_clone", t::test_vma_clone));
    s.add(TestCase::new("protection_flags_read_only", t::test_protection_flags_read_only));
    s.add(TestCase::new("protection_flags_write", t::test_protection_flags_write));
    s.add(TestCase::new("protection_flags_exec", t::test_protection_flags_exec));
    s.add(TestCase::new("protection_flags_combined", t::test_protection_flags_combined));
    s.add(TestCase::new("protection_flags_all", t::test_protection_flags_all));
    s.add(TestCase::new("pte_flags_addr_mask", t::test_pte_flags_addr_mask));
    s.add(TestCase::new("address_space_boundaries", t::test_address_space_boundaries));
    s.add(TestCase::new("page_sizes_ordering", t::test_page_sizes_ordering));
    s.add(TestCase::new("page_sizes_power_of_two", t::test_page_sizes_power_of_two));
    s.add(TestCase::new("page_size_alignment", t::test_page_size_alignment));
    s.add(TestCase::new("vma_size_zero", t::test_vma_size_zero));
    s.add(TestCase::new("vma_adjacent_not_overlapping", t::test_vma_adjacent_not_overlapping));
    s.add(TestCase::new("vma_cow_flag", t::test_vma_cow_flag));
    s.add(TestCase::new("vma_anonymous_flag", t::test_vma_anonymous_flag));
    s.add(TestCase::new("vma_refcount_increment", t::test_vma_refcount_increment));
    s.add(TestCase::new("protection_flags_default", t::test_protection_flags_default));
    s.add(TestCase::new("protection_flags_equality", t::test_protection_flags_equality));
    s.add(TestCase::new("protection_flags_to_pte_flags", t::test_protection_flags_to_pte_flags));
    s.add(TestCase::new("protection_flags_no_exec_flag", t::test_protection_flags_no_exec_flag));
}
