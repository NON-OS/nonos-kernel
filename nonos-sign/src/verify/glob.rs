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

// Mirrors src/security/nonos_id_cert/schema/glob_match.rs. Either the
// glob matches the namespace literally, or the glob ends with `*` and
// the namespace begins with the prefix before the star.
pub fn glob_match(glob: &str, namespace: &str) -> bool {
    if glob == namespace {
        return true;
    }
    if let Some(prefix) = glob.strip_suffix('*') {
        return namespace.starts_with(prefix);
    }
    false
}
