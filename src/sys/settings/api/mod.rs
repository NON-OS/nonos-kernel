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
pub mod kernel;
mod privacy;
mod system;

pub use display::{
    animations_enabled, notifications_enabled, set_animations_enabled, set_notifications_enabled,
};
pub use display::{brightness, screen_timeout, set_brightness, set_screen_timeout};
pub use input::{
    cursor_size, font_size, high_contrast, set_cursor_size, set_font_size, set_high_contrast,
};
pub use input::{keyboard_layout, mouse_sensitivity, set_keyboard_layout, set_mouse_sensitivity};
pub use input::{set_sound_enabled, sound_enabled};
pub use kernel::{
    kernel_aslr, kernel_debug, kernel_hugepages, kernel_iommu, kernel_nx_bit, kernel_preempt,
    kernel_seccomp, kernel_serial, kernel_smap, kernel_smep, kernel_stack_guard, kernel_watchdog,
    set_kernel_aslr, set_kernel_debug, set_kernel_hugepages, set_kernel_iommu, set_kernel_nx_bit,
    set_kernel_preempt, set_kernel_seccomp, set_kernel_serial, set_kernel_smap, set_kernel_smep,
    set_kernel_stack_guard, set_kernel_watchdog,
};
pub use privacy::{anonymous_mode, nym_enabled, set_anonymous_mode, set_nym_enabled};
pub use privacy::{
    auto_lock_timeout, set_auto_lock_timeout, set_wifi_autoconnect, wifi_autoconnect,
};
pub use privacy::{auto_wipe, set_auto_wipe};
pub use system::{developer_mode, language, set_developer_mode, set_language};
pub use system::{hardware_crypto, set_hardware_crypto, set_zk_attestation, zk_attestation};
pub use system::{set_system_keys_generated, system_keys_generated};
pub use system::{set_theme, set_timezone, theme, timezone};
