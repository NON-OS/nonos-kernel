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

use super::outcome::Outcome;
use crate::command::builtin;
use crate::command::output::Output;
use crate::command::parse::Argv;
use crate::term::history::History;
use crate::term::scrollback::Scrollback;

pub fn run(history: &mut History, sb: &mut Scrollback, argv: &Argv<'_>) -> Outcome {
    if argv.argc == 0 {
        return Outcome::Repaint;
    }
    let args = &argv.argv[..argv.argc];
    if builtin::exit_check::want_exit(args) {
        return Outcome::Exit;
    }
    match args[0] {
        b"help" | b"?" => builtin::help::run(&mut Output::new(sb), args),
        b"version" | b"ver" => builtin::version::run(&mut Output::new(sb), args),
        b"echo" => builtin::echo::run(&mut Output::new(sb), args),
        b"clear" | b"cls" => builtin::clear::run(sb, args),
        b"history" => builtin::history_cmd::run(&mut Output::new(sb), history, args),
        b"service" | b"lookup" => builtin::service::run(&mut Output::new(sb), args),
        b"capsules" | b"ps" | b"services" => builtin::capsules::run(&mut Output::new(sb), args),
        b"ping" => builtin::ping::run(&mut Output::new(sb), args),
        b"display" => builtin::display::run(&mut Output::new(sb), args),
        b"market" | b"apps" => builtin::market::run(&mut Output::new(sb), args),
        b"motd" | b"banner" => builtin::motd::run(sb, args),
        b"whoami" | b"id" => builtin::whoami::run(&mut Output::new(sb), args),
        b"about" => builtin::about::run(&mut Output::new(sb), args),
        other => builtin::unknown::run(&mut Output::new(sb), other),
    }
    Outcome::Repaint
}
