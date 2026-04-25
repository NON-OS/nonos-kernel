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

use crate::nox::doctor::DoctorRunner;
use crate::nox::output::Output;
use crate::nox::NoxResult;

pub fn cmd_doctor() -> NoxResult<bool> {
    let msg = Output::arrow_blue("Checking system for potential problems");
    crate::drivers::console::write_message(&msg);
    let mut runner = DoctorRunner::new();
    runner.run_all();
    let (passed, warnings, errors) = runner.summary();
    for result in runner.results() {
        let line = if result.passed {
            Output::check(&result.message)
        } else {
            Output::cross(&result.message)
        };
        crate::drivers::console::write_message(&line);
    }
    let summary = alloc::format!("{} passed, {} warnings, {} errors", passed, warnings, errors);
    crate::drivers::console::write_message(&Output::arrow(&summary));
    Ok(!runner.has_errors())
}
