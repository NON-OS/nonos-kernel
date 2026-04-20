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
mod math_utils;
mod draw_gradient_background;
mod draw_particle_effects;
mod draw_animated_logo;
mod draw_progress_bar;
mod draw_stage_indicators;
mod draw_boot_messages;
mod draw_spinning_indicator;
mod draw_status_items;
mod draw_system_info;
mod get_stage_name;
mod update_animation_timer;
mod render_complete_bootloader;

pub use crypto::{animate_hash_reveal, reset_hash_reveal, show_crypto_verification, BootCryptoState};
pub use init::init_boot_screen;
pub use progress::{draw_boot_progress, reset_animation, show_error_screen, show_handoff_message, tick_animation};
pub use stages::{get_current_stage, reset_stage, update_stage};
pub use draw_gradient_background::draw_gradient_background;
pub use draw_particle_effects::draw_particle_effects;
pub use draw_animated_logo::draw_animated_logo;
pub use draw_progress_bar::{draw_progress_bar, set_progress_percent};
pub use draw_stage_indicators::{draw_stage_indicators, set_current_stage, advance_stage};
pub use draw_boot_messages::{draw_boot_messages, add_boot_message};
pub use draw_spinning_indicator::draw_spinning_indicator;
pub use draw_status_items::draw_status_items;
pub use draw_system_info::draw_system_info;
pub use get_stage_name::get_stage_name;
pub use update_animation_timer::{update_animation_timer, get_animation_frame};
pub use render_complete_bootloader::{render_complete_bootloader, set_boot_stage};
