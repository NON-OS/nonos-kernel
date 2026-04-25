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

mod get;
mod init;
mod seed;

pub use get::{get_entropy64, get_entropy64_secure, get_tsc_entropy};
pub use init::{
    has_adequate_entropy, init_entropy, mark_bootloader_entropy_provided, verify_entropy_sources,
};
pub use seed::{collect_seed_entropy, collect_seed_entropy_secure, mix_entropy_into_seed};
