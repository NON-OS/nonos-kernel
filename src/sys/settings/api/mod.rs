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

mod display;
mod input;
mod privacy;
mod system;
pub mod kernel;

pub use display::{brightness, set_brightness, screen_timeout, set_screen_timeout};
pub use input::{mouse_sensitivity, set_mouse_sensitivity, keyboard_layout, set_keyboard_layout};
pub use input::{sound_enabled, set_sound_enabled};
pub use privacy::{anonymous_mode, set_anonymous_mode, nym_enabled, set_nym_enabled};
pub use privacy::{auto_wipe, set_auto_wipe};
pub use system::{theme, set_theme, timezone, set_timezone};
pub use system::{language, set_language, developer_mode, set_developer_mode};
pub use system::{hardware_crypto, set_hardware_crypto, zk_attestation, set_zk_attestation};
pub use system::{system_keys_generated, set_system_keys_generated};
pub use display::{notifications_enabled, set_notifications_enabled, animations_enabled, set_animations_enabled};
pub use input::{cursor_size, set_cursor_size, high_contrast, set_high_contrast, font_size, set_font_size};
pub use privacy::{auto_lock_timeout, set_auto_lock_timeout, wifi_autoconnect, set_wifi_autoconnect};
pub use kernel::{
    kernel_aslr, set_kernel_aslr, kernel_stack_guard, set_kernel_stack_guard,
    kernel_nx_bit, set_kernel_nx_bit, kernel_smep, set_kernel_smep, kernel_smap, set_kernel_smap,
    kernel_debug, set_kernel_debug, kernel_serial, set_kernel_serial,
    kernel_watchdog, set_kernel_watchdog, kernel_preempt, set_kernel_preempt,
    kernel_hugepages, set_kernel_hugepages, kernel_iommu, set_kernel_iommu,
    kernel_seccomp, set_kernel_seccomp,
};
