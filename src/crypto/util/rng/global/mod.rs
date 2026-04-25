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

mod generate;
mod init;
mod seed;
mod state;

pub use generate::{
    fill_random_bytes, fill_random_bytes_secure, get_random_bytes, get_random_bytes_secure,
    random_range, random_range_secure, random_u32, random_u32_secure, random_u64,
    random_u64_secure,
};
pub use init::{init_rng, init_rng_simple, is_initialized};
pub use seed::{seed_direct, seed_from_bootloader, seed_rng};
pub use state::GLOBAL_COUNTER;
