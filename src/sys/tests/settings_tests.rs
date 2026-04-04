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

#[test]
fn test_settings_default_brightness() {
    let s = Settings::default();
    assert_eq!(s.brightness, 80);
}

#[test]
fn test_settings_default_mouse_sensitivity() {
    let s = Settings::default();
    assert_eq!(s.mouse_sensitivity, 5);
}

#[test]
fn test_settings_default_sound_enabled() {
    let s = Settings::default();
    assert!(s.sound_enabled);
}

#[test]
fn test_settings_default_anonymous_mode() {
    let s = Settings::default();
    assert!(s.anonymous_mode);
}

#[test]
fn test_settings_default_nym_enabled() {
    let s = Settings::default();
    assert!(!s.nym_enabled);
}

#[test]
fn test_settings_default_theme() {
    let s = Settings::default();
    assert_eq!(s.theme, 0);
}

#[test]
fn test_settings_default_keyboard_layout() {
    let s = Settings::default();
    assert_eq!(s.keyboard_layout, 0);
}

#[test]
fn test_settings_default_auto_wipe() {
    let s = Settings::default();
    assert!(s.auto_wipe);
}

#[test]
fn test_settings_default_timezone() {
    let s = Settings::default();
    assert_eq!(s.timezone, 0);
}

#[test]
fn test_settings_default_screen_timeout() {
    let s = Settings::default();
    assert_eq!(s.screen_timeout, 0);
}

#[test]
fn test_settings_default_language() {
    let s = Settings::default();
    assert_eq!(s.language, 0);
}

#[test]
fn test_settings_default_developer_mode() {
    let s = Settings::default();
    assert!(!s.developer_mode);
}

#[test]
fn test_settings_default_hardware_crypto() {
    let s = Settings::default();
    assert!(s.hardware_crypto);
}

#[test]
fn test_settings_default_zk_attestation() {
    let s = Settings::default();
    assert!(s.zk_attestation);
}

#[test]
fn test_settings_default_system_keys_generated() {
    let s = Settings::default();
    assert!(!s.system_keys_generated);
}

#[test]
fn test_settings_default_notifications_enabled() {
    let s = Settings::default();
    assert!(s.notifications_enabled);
}

#[test]
fn test_settings_default_high_contrast() {
    let s = Settings::default();
    assert!(!s.high_contrast);
}

#[test]
fn test_settings_default_font_size() {
    let s = Settings::default();
    assert_eq!(s.font_size, 1);
}

#[test]
fn test_settings_default_auto_lock_timeout() {
    let s = Settings::default();
    assert_eq!(s.auto_lock_timeout, 5);
}

#[test]
fn test_settings_default_wifi_autoconnect() {
    let s = Settings::default();
    assert!(s.wifi_autoconnect);
}

#[test]
fn test_settings_default_animations_enabled() {
    let s = Settings::default();
    assert!(s.animations_enabled);
}

#[test]
fn test_settings_default_cursor_size() {
    let s = Settings::default();
    assert_eq!(s.cursor_size, 1);
}

#[test]
fn test_settings_default_kernel_aslr() {
    let s = Settings::default();
    assert!(s.kernel_aslr);
}

#[test]
fn test_settings_default_kernel_stack_guard() {
    let s = Settings::default();
    assert!(s.kernel_stack_guard);
}

#[test]
fn test_settings_default_kernel_nx_bit() {
    let s = Settings::default();
    assert!(s.kernel_nx_bit);
}

#[test]
fn test_settings_default_kernel_smep() {
    let s = Settings::default();
    assert!(s.kernel_smep);
}

#[test]
fn test_settings_default_kernel_smap() {
    let s = Settings::default();
    assert!(s.kernel_smap);
}

#[test]
fn test_settings_default_kernel_debug() {
    let s = Settings::default();
    assert!(!s.kernel_debug);
}

#[test]
fn test_settings_default_kernel_serial() {
    let s = Settings::default();
    assert!(s.kernel_serial);
}

#[test]
fn test_settings_default_kernel_watchdog() {
    let s = Settings::default();
    assert!(!s.kernel_watchdog);
}

#[test]
fn test_settings_default_kernel_preempt() {
    let s = Settings::default();
    assert!(s.kernel_preempt);
}

#[test]
fn test_settings_default_kernel_hugepages() {
    let s = Settings::default();
    assert!(!s.kernel_hugepages);
}

#[test]
fn test_settings_default_kernel_iommu() {
    let s = Settings::default();
    assert!(s.kernel_iommu);
}

#[test]
fn test_settings_default_kernel_seccomp() {
    let s = Settings::default();
    assert!(s.kernel_seccomp);
}

#[test]
fn test_settings_is_copy() {
    let s1 = Settings::default();
    let s2 = s1;
    assert_eq!(s1.brightness, s2.brightness);
}

#[test]
fn test_settings_is_clone() {
    let s1 = Settings::default();
    let s2 = s1.clone();
    assert_eq!(s1.brightness, s2.brightness);
}

#[test]
fn test_settings_const_default() {
    const S: Settings = Settings::default();
    assert_eq!(S.brightness, 80);
}

#[test]
fn test_brightness_getter() {
    init();
    let _ = brightness();
}

#[test]
fn test_set_brightness_normal() {
    init();
    set_brightness(50);
    assert_eq!(brightness(), 50);
}

#[test]
fn test_set_brightness_max() {
    init();
    set_brightness(100);
    assert_eq!(brightness(), 100);
}

#[test]
fn test_set_brightness_clamp() {
    init();
    set_brightness(255);
    assert_eq!(brightness(), 100);
}

#[test]
fn test_set_brightness_zero() {
    init();
    set_brightness(0);
    assert_eq!(brightness(), 0);
}

#[test]
fn test_mouse_sensitivity_getter() {
    init();
    let _ = mouse_sensitivity();
}

#[test]
fn test_set_mouse_sensitivity_normal() {
    init();
    set_mouse_sensitivity(5);
    assert_eq!(mouse_sensitivity(), 5);
}

#[test]
fn test_set_mouse_sensitivity_clamp_low() {
    init();
    set_mouse_sensitivity(0);
    assert_eq!(mouse_sensitivity(), 1);
}

#[test]
fn test_set_mouse_sensitivity_clamp_high() {
    init();
    set_mouse_sensitivity(100);
    assert_eq!(mouse_sensitivity(), 10);
}

#[test]
fn test_anonymous_mode_getter() {
    init();
    let _ = anonymous_mode();
}

#[test]
fn test_set_anonymous_mode_true() {
    init();
    set_anonymous_mode(true);
    assert!(anonymous_mode());
}

#[test]
fn test_set_anonymous_mode_false() {
    init();
    set_anonymous_mode(false);
    assert!(!anonymous_mode());
}

#[test]
fn test_nym_enabled_getter() {
    init();
    let _ = nym_enabled();
}

#[test]
fn test_set_nym_enabled_true() {
    init();
    set_nym_enabled(true);
    assert!(nym_enabled());
}

#[test]
fn test_set_nym_enabled_false() {
    init();
    set_nym_enabled(false);
    assert!(!nym_enabled());
}

#[test]
fn test_theme_getter() {
    init();
    let _ = theme();
}

#[test]
fn test_set_theme() {
    init();
    set_theme(2);
    assert_eq!(theme(), 2);
}

#[test]
fn test_auto_wipe_getter() {
    init();
    let _ = auto_wipe();
}

#[test]
fn test_set_auto_wipe_true() {
    init();
    set_auto_wipe(true);
    assert!(auto_wipe());
}

#[test]
fn test_set_auto_wipe_false() {
    init();
    set_auto_wipe(false);
    assert!(!auto_wipe());
}

#[test]
fn test_timezone_getter() {
    init();
    let _ = timezone();
}

#[test]
fn test_set_timezone_positive() {
    init();
    set_timezone(5);
    assert_eq!(timezone(), 5);
}

#[test]
fn test_set_timezone_negative() {
    init();
    set_timezone(-8);
    assert_eq!(timezone(), -8);
}

#[test]
fn test_set_timezone_clamp_low() {
    init();
    set_timezone(-20);
    assert_eq!(timezone(), -12);
}

#[test]
fn test_set_timezone_clamp_high() {
    init();
    set_timezone(20);
    assert_eq!(timezone(), 14);
}

#[test]
fn test_get_returns_settings() {
    init();
    let s = get();
    assert!(s.brightness <= 100);
}

#[test]
fn test_get_mut_returns_mutable_ref() {
    init();
    let s = get_mut();
    s.brightness = 50;
    assert_eq!(brightness(), 50);
}

#[test]
fn test_mark_modified() {
    init();
    mark_modified();
    assert!(needs_save());
}

#[test]
fn test_needs_save_returns_bool() {
    init();
    let _: bool = needs_save();
}

#[test]
fn test_serialize_returns_size() {
    let s = Settings::default();
    let mut buf = [0u8; 1024];
    let size = serialize(&s, &mut buf);
    assert!(size > 0);
    assert!(size <= 1024);
}

#[test]
fn test_deserialize_roundtrip() {
    let mut s1 = Settings::default();
    s1.brightness = 42;
    s1.mouse_sensitivity = 7;
    s1.anonymous_mode = false;
    s1.timezone = -5;

    let mut buf = [0u8; 1024];
    let _size = serialize(&s1, &mut buf);

    let mut s2 = Settings::default();
    deserialize(&buf, &mut s2);

    assert_eq!(s2.brightness, 42);
    assert_eq!(s2.mouse_sensitivity, 7);
    assert!(!s2.anonymous_mode);
    assert_eq!(s2.timezone, -5);
}

#[test]
fn test_settings_filename_constant() {
    assert!(!SETTINGS_FILENAME.is_empty());
}

#[test]
fn test_hostname_init() {
    init_hostname();
}

#[test]
fn test_get_hostname() {
    init_hostname();
    let hostname = get_hostname();
    assert!(!hostname.is_empty());
}

#[test]
fn test_set_hostname_valid() {
    init_hostname();
    let result = set_hostname("test-host");
    assert!(result.is_ok());
    assert_eq!(get_hostname(), "test-host");
}

#[test]
fn test_set_hostname_empty_fails() {
    init_hostname();
    let result = set_hostname("");
    assert!(result.is_err());
}

#[test]
fn test_set_hostname_too_long_fails() {
    init_hostname();
    let long_name = "a".repeat(100);
    let result = set_hostname(&long_name);
    assert!(result.is_err());
}

#[test]
fn test_set_hostname_invalid_chars_fails() {
    init_hostname();
    let result = set_hostname("host@name");
    assert!(result.is_err());
}

#[test]
fn test_get_domainname() {
    init_hostname();
    let _ = get_domainname();
}

#[test]
fn test_set_domainname_valid() {
    init_hostname();
    let result = set_domainname("example.com");
    assert!(result.is_ok());
    assert_eq!(get_domainname(), "example.com");
}

#[test]
fn test_set_domainname_empty() {
    init_hostname();
    let result = set_domainname("");
    assert!(result.is_ok());
    assert_eq!(get_domainname(), "");
}

#[test]
fn test_set_domainname_too_long_fails() {
    init_hostname();
    let long_domain = "a".repeat(100);
    let result = set_domainname(&long_domain);
    assert!(result.is_err());
}

#[test]
fn test_reset_to_defaults() {
    init();
    set_brightness(10);
    set_mouse_sensitivity(1);
    reset_to_defaults();
    assert_eq!(brightness(), 80);
    assert_eq!(mouse_sensitivity(), 5);
}

#[test]
fn test_screen_timeout_getter() {
    init();
    let _ = screen_timeout();
}

#[test]
fn test_set_screen_timeout() {
    init();
    set_screen_timeout(30);
    assert_eq!(screen_timeout(), 30);
}

#[test]
fn test_set_screen_timeout_clamp() {
    init();
    set_screen_timeout(100);
    assert_eq!(screen_timeout(), 60);
}

#[test]
fn test_keyboard_layout_getter() {
    init();
    let _ = keyboard_layout();
}

#[test]
fn test_set_keyboard_layout() {
    init();
    set_keyboard_layout(2);
    assert_eq!(keyboard_layout(), 2);
}

#[test]
fn test_set_keyboard_layout_clamp() {
    init();
    set_keyboard_layout(100);
    assert_eq!(keyboard_layout(), 5);
}

#[test]
fn test_sound_enabled_getter() {
    init();
    let _ = sound_enabled();
}

#[test]
fn test_set_sound_enabled() {
    init();
    set_sound_enabled(false);
    assert!(!sound_enabled());
    set_sound_enabled(true);
    assert!(sound_enabled());
}

#[test]
fn test_language_getter() {
    init();
    let _ = language();
}

#[test]
fn test_set_language() {
    init();
    set_language(2);
    assert_eq!(language(), 2);
}

#[test]
fn test_developer_mode_getter() {
    init();
    let _ = developer_mode();
}

#[test]
fn test_set_developer_mode() {
    init();
    set_developer_mode(true);
    assert!(developer_mode());
    set_developer_mode(false);
    assert!(!developer_mode());
}

#[test]
fn test_hardware_crypto_getter() {
    init();
    let _ = hardware_crypto();
}

#[test]
fn test_set_hardware_crypto() {
    init();
    set_hardware_crypto(false);
    assert!(!hardware_crypto());
    set_hardware_crypto(true);
    assert!(hardware_crypto());
}

#[test]
fn test_zk_attestation_getter() {
    init();
    let _ = zk_attestation();
}

#[test]
fn test_set_zk_attestation() {
    init();
    set_zk_attestation(false);
    assert!(!zk_attestation());
    set_zk_attestation(true);
    assert!(zk_attestation());
}

#[test]
fn test_system_keys_generated_getter() {
    init();
    let _ = system_keys_generated();
}

#[test]
fn test_set_system_keys_generated() {
    init();
    set_system_keys_generated(true);
    assert!(system_keys_generated());
}

#[test]
fn test_notifications_enabled_getter() {
    init();
    let _ = notifications_enabled();
}

#[test]
fn test_set_notifications_enabled() {
    init();
    set_notifications_enabled(false);
    assert!(!notifications_enabled());
}

#[test]
fn test_animations_enabled_getter() {
    init();
    let _ = animations_enabled();
}

#[test]
fn test_set_animations_enabled() {
    init();
    set_animations_enabled(false);
    assert!(!animations_enabled());
}

#[test]
fn test_cursor_size_getter() {
    init();
    let _ = cursor_size();
}

#[test]
fn test_set_cursor_size() {
    init();
    set_cursor_size(2);
    assert_eq!(cursor_size(), 2);
}

#[test]
fn test_set_cursor_size_clamp() {
    init();
    set_cursor_size(100);
    assert_eq!(cursor_size(), 2);
}

#[test]
fn test_high_contrast_getter() {
    init();
    let _ = high_contrast();
}

#[test]
fn test_set_high_contrast() {
    init();
    set_high_contrast(true);
    assert!(high_contrast());
}

#[test]
fn test_font_size_getter() {
    init();
    let _ = font_size();
}

#[test]
fn test_set_font_size() {
    init();
    set_font_size(2);
    assert_eq!(font_size(), 2);
}

#[test]
fn test_set_font_size_clamp() {
    init();
    set_font_size(100);
    assert_eq!(font_size(), 2);
}

#[test]
fn test_auto_lock_timeout_getter() {
    init();
    let _ = auto_lock_timeout();
}

#[test]
fn test_set_auto_lock_timeout() {
    init();
    set_auto_lock_timeout(15);
    assert_eq!(auto_lock_timeout(), 15);
}

#[test]
fn test_set_auto_lock_timeout_clamp() {
    init();
    set_auto_lock_timeout(100);
    assert_eq!(auto_lock_timeout(), 30);
}

#[test]
fn test_wifi_autoconnect_getter() {
    init();
    let _ = wifi_autoconnect();
}

#[test]
fn test_set_wifi_autoconnect() {
    init();
    set_wifi_autoconnect(false);
    assert!(!wifi_autoconnect());
}
