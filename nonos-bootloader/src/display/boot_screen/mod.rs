// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod crypto;
mod init;
mod progress;
mod stages;

pub use crypto::{animate_hash_reveal, reset_hash_reveal, show_crypto_verification, BootCryptoState};
pub use init::init_boot_screen;
pub use progress::{draw_boot_progress, reset_animation, show_error_screen, show_handoff_message, tick_animation};
pub use stages::{get_current_stage, reset_stage, update_stage};
