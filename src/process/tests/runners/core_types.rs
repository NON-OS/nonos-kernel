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

use crate::process::tests::core_types_tests as t;
use crate::test::framework::{TestCase, TestSuite};

pub fn register(s: &mut TestSuite) {
    s.add(TestCase::new("process_state_variants", t::process_state_variants));
    s.add(TestCase::new("process_state_zombie_with_code", t::process_state_zombie_with_code));
    s.add(TestCase::new(
        "process_state_terminated_with_code",
        t::process_state_terminated_with_code,
    ));
    s.add(TestCase::new("process_state_clone", t::process_state_clone));
    s.add(TestCase::new("priority_variants", t::priority_variants));
    s.add(TestCase::new("priority_not_equal", t::priority_not_equal));
    s.add(TestCase::new("priority_clone", t::priority_clone));
    s.add(TestCase::new("vma_basic", t::vma_basic));
    s.add(TestCase::new("vma_clone", t::vma_clone));
    s.add(TestCase::new("isolation_flags_default", t::isolation_flags_default));
    s.add(TestCase::new("isolation_flags_clone", t::isolation_flags_clone));
    s.add(TestCase::new("suspended_context_fields", t::suspended_context_fields));
    s.add(TestCase::new("suspended_context_clone", t::suspended_context_clone));
    s.add(TestCase::new("align_up_power_of_two", t::align_up_power_of_two));
    s.add(TestCase::new("align_up_various_alignments", t::align_up_various_alignments));
    s.add(TestCase::new("align_up_alignment_1", t::align_up_alignment_1));
    s.add(TestCase::new("overlaps_no_overlap", t::overlaps_no_overlap));
    s.add(TestCase::new("overlaps_with_first", t::overlaps_with_first));
    s.add(TestCase::new("overlaps_adjacent", t::overlaps_adjacent));
    s.add(TestCase::new("overlaps_empty_vmas", t::overlaps_empty_vmas));
    s.add(TestCase::new("overlaps_zero_length", t::overlaps_zero_length));
    s.add(TestCase::new("pid_type_alias", t::pid_type_alias));
    s.add(TestCase::new("tid_type_alias", t::tid_type_alias));
}
