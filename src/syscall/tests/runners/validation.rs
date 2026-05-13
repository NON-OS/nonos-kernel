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

use crate::syscall::tests::validation as t;
use crate::test::framework::{TestCase, TestSuite};

pub fn register(s: &mut TestSuite) {
    s.add(TestCase::new("validation::module_exists", t::test_module_exists));
    s.add(TestCase::new("validation::basic_constants", t::test_basic_constants));
    s.add(TestCase::new("validation::basic_operations", t::test_basic_operations));
}
