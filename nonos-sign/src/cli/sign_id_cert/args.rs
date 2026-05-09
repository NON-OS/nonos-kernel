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

use std::path::PathBuf;

use nonos_capsule_sign::algs::AlgId;

pub(super) struct Args {
    pub serial: u64,
    pub nonos_id: [u8; 32],
    pub ns_globs: Vec<String>,
    pub caps_ceiling: u64,
    pub epoch: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub pub_keys: Vec<(AlgId, PathBuf)>,
    pub ta_seeds: Vec<(AlgId, PathBuf)>,
    pub metadata: String,
    pub out: PathBuf,
}
