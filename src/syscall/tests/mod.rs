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

mod caps;
mod errnos;
mod numbers;
mod runners;
mod types;
mod validation;

use crate::test::framework::TestSuite;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("syscall");
    runners::types::register(&mut suite);
    runners::numbers::register(&mut suite);
    runners::errnos::register(&mut suite);
    runners::caps::register(&mut suite);
    runners::validation::register(&mut suite);
    suite.run()
}
