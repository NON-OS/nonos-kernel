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

use crate::log::*;
use crate::arch::x86_64::vga::Color;

#[test]
fn test_severity_debug_variant() {
    let sev = Severity::Debug;
    assert_eq!(sev, Severity::Debug);
}

#[test]
fn test_severity_info_variant() {
    let sev = Severity::Info;
    assert_eq!(sev, Severity::Info);
}

#[test]
fn test_severity_warn_variant() {
    let sev = Severity::Warn;
    assert_eq!(sev, Severity::Warn);
}

#[test]
fn test_severity_err_variant() {
    let sev = Severity::Err;
    assert_eq!(sev, Severity::Err);
}

#[test]
fn test_severity_fatal_variant() {
    let sev = Severity::Fatal;
    assert_eq!(sev, Severity::Fatal);
}

#[test]
fn test_severity_debug_color() {
    assert_eq!(Severity::Debug.color(), Color::Cyan);
}

#[test]
fn test_severity_info_color() {
    assert_eq!(Severity::Info.color(), Color::LightGreen);
}

#[test]
fn test_severity_warn_color() {
    assert_eq!(Severity::Warn.color(), Color::Yellow);
}

#[test]
fn test_severity_err_color() {
    assert_eq!(Severity::Err.color(), Color::LightRed);
}

#[test]
fn test_severity_fatal_color() {
    assert_eq!(Severity::Fatal.color(), Color::LightRed);
}

#[test]
fn test_severity_debug_as_str() {
    assert_eq!(Severity::Debug.as_str(), "DBG");
}

#[test]
fn test_severity_info_as_str() {
    assert_eq!(Severity::Info.as_str(), "INFO");
}

#[test]
fn test_severity_warn_as_str() {
    assert_eq!(Severity::Warn.as_str(), "WARN");
}

#[test]
fn test_severity_err_as_str() {
    assert_eq!(Severity::Err.as_str(), "ERR");
}

#[test]
fn test_severity_fatal_as_str() {
    assert_eq!(Severity::Fatal.as_str(), "FATAL");
}

#[test]
fn test_severity_clone() {
    let s1 = Severity::Info;
    let s2 = s1.clone();
    assert_eq!(s1, s2);
}

#[test]
fn test_severity_copy() {
    let s1 = Severity::Warn;
    let s2 = s1;
    assert_eq!(s1, s2);
}

#[test]
fn test_severity_equality() {
    assert_eq!(Severity::Debug, Severity::Debug);
    assert_eq!(Severity::Info, Severity::Info);
    assert_eq!(Severity::Warn, Severity::Warn);
    assert_eq!(Severity::Err, Severity::Err);
    assert_eq!(Severity::Fatal, Severity::Fatal);
}

#[test]
fn test_severity_inequality() {
    assert_ne!(Severity::Debug, Severity::Info);
    assert_ne!(Severity::Info, Severity::Warn);
    assert_ne!(Severity::Warn, Severity::Err);
    assert_ne!(Severity::Err, Severity::Fatal);
    assert_ne!(Severity::Fatal, Severity::Debug);
}

#[test]
fn test_severity_debug_format() {
    let debug_str = alloc::format!("{:?}", Severity::Debug);
    assert!(debug_str.contains("Debug"));
}

#[test]
fn test_severity_info_debug_format() {
    let debug_str = alloc::format!("{:?}", Severity::Info);
    assert!(debug_str.contains("Info"));
}

#[test]
fn test_severity_warn_debug_format() {
    let debug_str = alloc::format!("{:?}", Severity::Warn);
    assert!(debug_str.contains("Warn"));
}

#[test]
fn test_severity_err_debug_format() {
    let debug_str = alloc::format!("{:?}", Severity::Err);
    assert!(debug_str.contains("Err"));
}

#[test]
fn test_severity_fatal_debug_format() {
    let debug_str = alloc::format!("{:?}", Severity::Fatal);
    assert!(debug_str.contains("Fatal"));
}

#[test]
fn test_all_severity_variants_unique() {
    let severities = [
        Severity::Debug,
        Severity::Info,
        Severity::Warn,
        Severity::Err,
        Severity::Fatal,
    ];
    for i in 0..severities.len() {
        for j in (i + 1)..severities.len() {
            assert_ne!(severities[i], severities[j]);
        }
    }
}

#[test]
fn test_all_severity_str_representations_unique() {
    let strs = [
        Severity::Debug.as_str(),
        Severity::Info.as_str(),
        Severity::Warn.as_str(),
        Severity::Err.as_str(),
        Severity::Fatal.as_str(),
    ];
    for i in 0..strs.len() {
        for j in (i + 1)..strs.len() {
            assert_ne!(strs[i], strs[j]);
        }
    }
}

#[test]
fn test_severity_color_returns_valid_color() {
    let severities = [
        Severity::Debug,
        Severity::Info,
        Severity::Warn,
        Severity::Err,
        Severity::Fatal,
    ];
    for sev in severities {
        let _ = sev.color();
    }
}

#[test]
fn test_severity_as_str_not_empty() {
    let severities = [
        Severity::Debug,
        Severity::Info,
        Severity::Warn,
        Severity::Err,
        Severity::Fatal,
    ];
    for sev in severities {
        assert!(!sev.as_str().is_empty());
    }
}

#[test]
fn test_severity_err_and_fatal_same_color() {
    assert_eq!(Severity::Err.color(), Severity::Fatal.color());
}

#[test]
fn test_severity_debug_info_warn_different_colors() {
    assert_ne!(Severity::Debug.color(), Severity::Info.color());
    assert_ne!(Severity::Info.color(), Severity::Warn.color());
    assert_ne!(Severity::Debug.color(), Severity::Warn.color());
}
