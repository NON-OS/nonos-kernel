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

use std::path::Path;

use crate::args::Flags;
use crate::error::CliError;
use crate::keys::OperatorKey;

pub(super) fn load_operator_key(flags: &Flags) -> Result<OperatorKey, CliError> {
    match (flags.optional("key-file"), flags.optional("key-env")) {
        (Some(_), Some(_)) => Err(CliError::KeyError(
            "specify exactly one of --key-file or --key-env".to_string(),
        )),
        (Some(path), None) => OperatorKey::from_file(Path::new(path)),
        (None, Some(var)) => OperatorKey::from_env(var),
        (None, None) => Err(CliError::KeyError(
            "missing --key-file <path> or --key-env <var>".to_string(),
        )),
    }
}
