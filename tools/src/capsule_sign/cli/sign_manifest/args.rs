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
    pub cert: PathBuf,
    pub namespace: String,
    pub version: (u32, u32, u32),
    pub target: String,
    pub elf: PathBuf,
    pub required_caps: u64,
    pub optional_caps: u64,
    pub endpoints: Vec<(u8, u32, String)>,
    pub pub_seeds: Vec<(AlgId, PathBuf)>,
    pub out: PathBuf,
}
