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

use crate::process::tests::thread_group_tests as t;
use crate::test::framework::{TestCase, TestSuite};

pub fn register(s: &mut TestSuite) {
    s.add(TestCase::new("thread_group_new", t::thread_group_new));
    s.add(TestCase::new("thread_group_add_thread", t::thread_group_add_thread));
    s.add(TestCase::new("thread_group_remove_thread", t::thread_group_remove_thread));
    s.add(TestCase::new("thread_group_remove_nonexistent", t::thread_group_remove_nonexistent));
    s.add(TestCase::new("thread_group_is_leader", t::thread_group_is_leader));
    s.add(TestCase::new("thread_group_thread_count_atomic", t::thread_group_thread_count_atomic));
    s.add(TestCase::new("thread_group_remove_leader", t::thread_group_remove_leader));
    s.add(TestCase::new("thread_group_tgid_unchanged", t::thread_group_tgid_unchanged));
    s.add(TestCase::new("thread_group_threads_list", t::thread_group_threads_list));
    s.add(TestCase::new(
        "thread_group_remove_all_except_leader",
        t::thread_group_remove_all_except_leader,
    ));
    s.add(TestCase::new("thread_group_multiple_add_remove", t::thread_group_multiple_add_remove));
}
