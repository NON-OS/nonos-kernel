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

use crate::sys::settings::*;
use crate::test::framework::TestResult;

pub(crate) fn test_settings_default_brightness() -> TestResult {
    let s = Settings::default();
    if s.brightness != 80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_mouse_sensitivity() -> TestResult {
    let s = Settings::default();
    if s.mouse_sensitivity != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_sound_enabled() -> TestResult {
    let s = Settings::default();
    if !s.sound_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_anonymous_mode() -> TestResult {
    let s = Settings::default();
    if !s.anonymous_mode {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_nym_enabled() -> TestResult {
    let s = Settings::default();
    if s.nym_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_theme() -> TestResult {
    let s = Settings::default();
    if s.theme != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_keyboard_layout() -> TestResult {
    let s = Settings::default();
    if s.keyboard_layout != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_auto_wipe() -> TestResult {
    let s = Settings::default();
    if !s.auto_wipe {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_timezone() -> TestResult {
    let s = Settings::default();
    if s.timezone != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_screen_timeout() -> TestResult {
    let s = Settings::default();
    if s.screen_timeout != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_language() -> TestResult {
    let s = Settings::default();
    if s.language != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_developer_mode() -> TestResult {
    let s = Settings::default();
    if s.developer_mode {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_hardware_crypto() -> TestResult {
    let s = Settings::default();
    if !s.hardware_crypto {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_zk_attestation() -> TestResult {
    let s = Settings::default();
    if !s.zk_attestation {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_system_keys_generated() -> TestResult {
    let s = Settings::default();
    if s.system_keys_generated {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_notifications_enabled() -> TestResult {
    let s = Settings::default();
    if !s.notifications_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_high_contrast() -> TestResult {
    let s = Settings::default();
    if s.high_contrast {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_font_size() -> TestResult {
    let s = Settings::default();
    if s.font_size != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_auto_lock_timeout() -> TestResult {
    let s = Settings::default();
    if s.auto_lock_timeout != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_wifi_autoconnect() -> TestResult {
    let s = Settings::default();
    if !s.wifi_autoconnect {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_animations_enabled() -> TestResult {
    let s = Settings::default();
    if !s.animations_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_cursor_size() -> TestResult {
    let s = Settings::default();
    if s.cursor_size != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_aslr() -> TestResult {
    let s = Settings::default();
    if !s.kernel_aslr {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_stack_guard() -> TestResult {
    let s = Settings::default();
    if !s.kernel_stack_guard {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_nx_bit() -> TestResult {
    let s = Settings::default();
    if !s.kernel_nx_bit {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_smep() -> TestResult {
    let s = Settings::default();
    if !s.kernel_smep {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_smap() -> TestResult {
    let s = Settings::default();
    if !s.kernel_smap {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_debug() -> TestResult {
    let s = Settings::default();
    if s.kernel_debug {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_serial() -> TestResult {
    let s = Settings::default();
    if !s.kernel_serial {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_watchdog() -> TestResult {
    let s = Settings::default();
    if s.kernel_watchdog {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_preempt() -> TestResult {
    let s = Settings::default();
    if !s.kernel_preempt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_hugepages() -> TestResult {
    let s = Settings::default();
    if s.kernel_hugepages {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_iommu() -> TestResult {
    let s = Settings::default();
    if !s.kernel_iommu {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_default_kernel_seccomp() -> TestResult {
    let s = Settings::default();
    if !s.kernel_seccomp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_is_copy() -> TestResult {
    let s1 = Settings::default();
    let s2 = s1;
    if s1.brightness != s2.brightness {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_is_clone() -> TestResult {
    let s1 = Settings::default();
    let s2 = s1.clone();
    if s1.brightness != s2.brightness {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_const_default() -> TestResult {
    const S: Settings = Settings::default();
    if S.brightness != 80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_brightness_getter() -> TestResult {
    init();
    let _ = brightness();
    TestResult::Pass
}

pub(crate) fn test_set_brightness_normal() -> TestResult {
    init();
    set_brightness(50);
    if brightness() != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_brightness_max() -> TestResult {
    init();
    set_brightness(100);
    if brightness() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_brightness_clamp() -> TestResult {
    init();
    set_brightness(255);
    if brightness() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_brightness_zero() -> TestResult {
    init();
    set_brightness(0);
    if brightness() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_sensitivity_getter() -> TestResult {
    init();
    let _ = mouse_sensitivity();
    TestResult::Pass
}

pub(crate) fn test_set_mouse_sensitivity_normal() -> TestResult {
    init();
    set_mouse_sensitivity(5);
    if mouse_sensitivity() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_mouse_sensitivity_clamp_low() -> TestResult {
    init();
    set_mouse_sensitivity(0);
    if mouse_sensitivity() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_mouse_sensitivity_clamp_high() -> TestResult {
    init();
    set_mouse_sensitivity(100);
    if mouse_sensitivity() != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_anonymous_mode_getter() -> TestResult {
    init();
    let _ = anonymous_mode();
    TestResult::Pass
}

pub(crate) fn test_set_anonymous_mode_true() -> TestResult {
    init();
    set_anonymous_mode(true);
    if !anonymous_mode() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_anonymous_mode_false() -> TestResult {
    init();
    set_anonymous_mode(false);
    if anonymous_mode() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_enabled_getter() -> TestResult {
    init();
    let _ = nym_enabled();
    TestResult::Pass
}

pub(crate) fn test_set_nym_enabled_true() -> TestResult {
    init();
    set_nym_enabled(true);
    if !nym_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_nym_enabled_false() -> TestResult {
    init();
    set_nym_enabled(false);
    if nym_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_getter() -> TestResult {
    init();
    let _ = theme();
    TestResult::Pass
}

pub(crate) fn test_set_theme() -> TestResult {
    init();
    set_theme(2);
    if theme() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_auto_wipe_getter() -> TestResult {
    init();
    let _ = auto_wipe();
    TestResult::Pass
}

pub(crate) fn test_set_auto_wipe_true() -> TestResult {
    init();
    set_auto_wipe(true);
    if !auto_wipe() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_auto_wipe_false() -> TestResult {
    init();
    set_auto_wipe(false);
    if auto_wipe() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timezone_getter() -> TestResult {
    init();
    let _ = timezone();
    TestResult::Pass
}

pub(crate) fn test_set_timezone_positive() -> TestResult {
    init();
    set_timezone(5);
    if timezone() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_timezone_negative() -> TestResult {
    init();
    set_timezone(-8);
    if timezone() != -8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_timezone_clamp_low() -> TestResult {
    init();
    set_timezone(-20);
    if timezone() != -12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_timezone_clamp_high() -> TestResult {
    init();
    set_timezone(20);
    if timezone() != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_returns_settings() -> TestResult {
    init();
    let s = get();
    if !(s.brightness <= 100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_mut_returns_mutable_ref() -> TestResult {
    init();
    let s = get_mut();
    s.brightness = 50;
    if brightness() != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mark_modified() -> TestResult {
    init();
    mark_modified();
    if !needs_save() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_needs_save_returns_bool() -> TestResult {
    init();
    let _: bool = needs_save();
    TestResult::Pass
}

pub(crate) fn test_serialize_returns_size() -> TestResult {
    let s = Settings::default();
    let mut buf = [0u8; 1024];
    let size = serialize(&s, &mut buf);
    if !(size > 0) {
        return TestResult::Fail;
    }
    if !(size <= 1024) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deserialize_roundtrip() -> TestResult {
    let mut s1 = Settings::default();
    s1.brightness = 42;
    s1.mouse_sensitivity = 7;
    s1.anonymous_mode = false;
    s1.timezone = -5;

    let mut buf = [0u8; 1024];
    let _size = serialize(&s1, &mut buf);

    let mut s2 = Settings::default();
    deserialize(&buf, &mut s2);

    if s2.brightness != 42 {
        return TestResult::Fail;
    }
    if s2.mouse_sensitivity != 7 {
        return TestResult::Fail;
    }
    if s2.anonymous_mode {
        return TestResult::Fail;
    }
    if s2.timezone != -5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_settings_filename_constant() -> TestResult {
    if SETTINGS_FILENAME.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hostname_init() -> TestResult {
    init_hostname();
    TestResult::Pass
}

pub(crate) fn test_get_hostname() -> TestResult {
    init_hostname();
    let hostname = get_hostname();
    if hostname.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_hostname_valid() -> TestResult {
    init_hostname();
    let result = set_hostname("test-host");
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if get_hostname() != "test-host" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_hostname_empty_fails() -> TestResult {
    init_hostname();
    let result = set_hostname("");
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_hostname_too_long_fails() -> TestResult {
    init_hostname();
    let long_name = "a".repeat(100);
    let result = set_hostname(&long_name);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_hostname_invalid_chars_fails() -> TestResult {
    init_hostname();
    let result = set_hostname("host@name");
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_domainname() -> TestResult {
    init_hostname();
    let _ = get_domainname();
    TestResult::Pass
}

pub(crate) fn test_set_domainname_valid() -> TestResult {
    init_hostname();
    let result = set_domainname("example.com");
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if get_domainname() != "example.com" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_domainname_empty() -> TestResult {
    init_hostname();
    let result = set_domainname("");
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if get_domainname() != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_domainname_too_long_fails() -> TestResult {
    init_hostname();
    let long_domain = "a".repeat(100);
    let result = set_domainname(&long_domain);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reset_to_defaults() -> TestResult {
    init();
    set_brightness(10);
    set_mouse_sensitivity(1);
    reset_to_defaults();
    if brightness() != 80 {
        return TestResult::Fail;
    }
    if mouse_sensitivity() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_timeout_getter() -> TestResult {
    init();
    let _ = screen_timeout();
    TestResult::Pass
}

pub(crate) fn test_set_screen_timeout() -> TestResult {
    init();
    set_screen_timeout(30);
    if screen_timeout() != 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_screen_timeout_clamp() -> TestResult {
    init();
    set_screen_timeout(100);
    if screen_timeout() != 60 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keyboard_layout_getter() -> TestResult {
    init();
    let _ = keyboard_layout();
    TestResult::Pass
}

pub(crate) fn test_set_keyboard_layout() -> TestResult {
    init();
    set_keyboard_layout(2);
    if keyboard_layout() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_keyboard_layout_clamp() -> TestResult {
    init();
    set_keyboard_layout(100);
    if keyboard_layout() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sound_enabled_getter() -> TestResult {
    init();
    let _ = sound_enabled();
    TestResult::Pass
}

pub(crate) fn test_set_sound_enabled() -> TestResult {
    init();
    set_sound_enabled(false);
    if sound_enabled() {
        return TestResult::Fail;
    }
    set_sound_enabled(true);
    if !sound_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_getter() -> TestResult {
    init();
    let _ = language();
    TestResult::Pass
}

pub(crate) fn test_set_language() -> TestResult {
    init();
    set_language(2);
    if language() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_developer_mode_getter() -> TestResult {
    init();
    let _ = developer_mode();
    TestResult::Pass
}

pub(crate) fn test_set_developer_mode() -> TestResult {
    init();
    set_developer_mode(true);
    if !developer_mode() {
        return TestResult::Fail;
    }
    set_developer_mode(false);
    if developer_mode() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hardware_crypto_getter() -> TestResult {
    init();
    let _ = hardware_crypto();
    TestResult::Pass
}

pub(crate) fn test_set_hardware_crypto() -> TestResult {
    init();
    set_hardware_crypto(false);
    if hardware_crypto() {
        return TestResult::Fail;
    }
    set_hardware_crypto(true);
    if !hardware_crypto() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_attestation_getter() -> TestResult {
    init();
    let _ = zk_attestation();
    TestResult::Pass
}

pub(crate) fn test_set_zk_attestation() -> TestResult {
    init();
    set_zk_attestation(false);
    if zk_attestation() {
        return TestResult::Fail;
    }
    set_zk_attestation(true);
    if !zk_attestation() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_system_keys_generated_getter() -> TestResult {
    init();
    let _ = system_keys_generated();
    TestResult::Pass
}

pub(crate) fn test_set_system_keys_generated() -> TestResult {
    init();
    set_system_keys_generated(true);
    if !system_keys_generated() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_notifications_enabled_getter() -> TestResult {
    init();
    let _ = notifications_enabled();
    TestResult::Pass
}

pub(crate) fn test_set_notifications_enabled() -> TestResult {
    init();
    set_notifications_enabled(false);
    if notifications_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_animations_enabled_getter() -> TestResult {
    init();
    let _ = animations_enabled();
    TestResult::Pass
}

pub(crate) fn test_set_animations_enabled() -> TestResult {
    init();
    set_animations_enabled(false);
    if animations_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cursor_size_getter() -> TestResult {
    init();
    let _ = cursor_size();
    TestResult::Pass
}

pub(crate) fn test_set_cursor_size() -> TestResult {
    init();
    set_cursor_size(2);
    if cursor_size() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_cursor_size_clamp() -> TestResult {
    init();
    set_cursor_size(100);
    if cursor_size() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_high_contrast_getter() -> TestResult {
    init();
    let _ = high_contrast();
    TestResult::Pass
}

pub(crate) fn test_set_high_contrast() -> TestResult {
    init();
    set_high_contrast(true);
    if !high_contrast() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_font_size_getter() -> TestResult {
    init();
    let _ = font_size();
    TestResult::Pass
}

pub(crate) fn test_set_font_size() -> TestResult {
    init();
    set_font_size(2);
    if font_size() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_font_size_clamp() -> TestResult {
    init();
    set_font_size(100);
    if font_size() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_auto_lock_timeout_getter() -> TestResult {
    init();
    let _ = auto_lock_timeout();
    TestResult::Pass
}

pub(crate) fn test_set_auto_lock_timeout() -> TestResult {
    init();
    set_auto_lock_timeout(15);
    if auto_lock_timeout() != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_auto_lock_timeout_clamp() -> TestResult {
    init();
    set_auto_lock_timeout(100);
    if auto_lock_timeout() != 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_wifi_autoconnect_getter() -> TestResult {
    init();
    let _ = wifi_autoconnect();
    TestResult::Pass
}

pub(crate) fn test_set_wifi_autoconnect() -> TestResult {
    init();
    set_wifi_autoconnect(false);
    if wifi_autoconnect() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
