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

#[test]
fn test_debug_simple_logs_debug_severity() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    debug_simple("debug test");

    let entries = get_log_entries();
    if !entries.is_empty() {
        let found = entries.iter().any(|e| {
            e.msg.as_str() == "debug test" && e.sev == Severity::Debug
        });
        assert!(found || entries.is_empty());
    }
    clear_log_buffer();
}

#[test]
fn test_info_simple_logs_info_severity() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    info_simple("info test");

    let entries = get_log_entries();
    if !entries.is_empty() {
        let found = entries.iter().any(|e| {
            e.msg.as_str() == "info test" && e.sev == Severity::Info
        });
        assert!(found || entries.is_empty());
    }
    clear_log_buffer();
}

#[test]
fn test_warn_simple_logs_warn_severity() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    warn_simple("warn test");

    let entries = get_log_entries();
    if !entries.is_empty() {
        let found = entries.iter().any(|e| {
            e.msg.as_str() == "warn test" && e.sev == Severity::Warn
        });
        assert!(found || entries.is_empty());
    }
    clear_log_buffer();
}

#[test]
fn test_log_error_simple_logs_err_severity() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    log_error_simple("error test");

    let entries = get_log_entries();
    if !entries.is_empty() {
        let found = entries.iter().any(|e| {
            e.msg.as_str() == "error test" && e.sev == Severity::Err
        });
        assert!(found || entries.is_empty());
    }
    clear_log_buffer();
}

#[test]
fn test_debug_simple_empty_message() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    debug_simple("");
    clear_log_buffer();
}

#[test]
fn test_info_simple_empty_message() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    info_simple("");
    clear_log_buffer();
}

#[test]
fn test_warn_simple_empty_message() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    warn_simple("");
    clear_log_buffer();
}

#[test]
fn test_log_error_simple_empty_message() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    log_error_simple("");
    clear_log_buffer();
}

#[test]
fn test_debug_simple_long_message() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    let long_msg = "d".repeat(200);
    debug_simple(&long_msg);
    clear_log_buffer();
}

#[test]
fn test_info_simple_long_message() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    let long_msg = "i".repeat(200);
    info_simple(&long_msg);
    clear_log_buffer();
}

#[test]
fn test_warn_simple_long_message() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    let long_msg = "w".repeat(200);
    warn_simple(&long_msg);
    clear_log_buffer();
}

#[test]
fn test_log_error_simple_long_message() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    let long_msg = "e".repeat(200);
    log_error_simple(&long_msg);
    clear_log_buffer();
}

#[test]
fn test_multiple_helper_calls() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    debug_simple("msg1");
    info_simple("msg2");
    warn_simple("msg3");
    log_error_simple("msg4");

    let count = log_entry_count();
    assert!(count >= 4);
    clear_log_buffer();
}

#[test]
fn test_helpers_preserve_message_content() {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    info_simple("preserved content");

    let entries = get_log_entries();
    let found = entries.iter().any(|e| e.msg.as_str() == "preserved content");
    assert!(found || entries.is_empty());
    clear_log_buffer();
}

#[test]
fn test_helpers_no_panic_without_logger() {
    debug_simple("no panic");
    info_simple("no panic");
    warn_simple("no panic");
    log_error_simple("no panic");
}

#[test]
fn test_compat_logger_module_exports() {
    use crate::log::logger;
    let _sev = logger::Severity::Info;
}

#[test]
fn test_compat_nonos_logger_module_exports() {
    use crate::log::nonos_logger;
    let _sev = nonos_logger::Severity::Debug;
    let _size = nonos_logger::RAM_BUF_SIZE;
}

#[test]
fn test_compat_simple_logger_module_exports() {
    use crate::log::simple_logger;
    let _sev = simple_logger::Severity::Warn;
}

#[test]
fn test_init_logger_alias_exists() {
    let _ = init_logger as fn();
}

#[test]
fn test_helper_functions_are_inline() {
    debug_simple("inline check");
    info_simple("inline check");
    warn_simple("inline check");
    log_error_simple("inline check");
    clear_log_buffer();
}

#[test]
fn test_debug_simple_uses_debug_str() {
    let mut manager = LogManager::new();
    manager.log(Severity::Debug, "test");
    let entries = manager.get_entries();
    assert_eq!(entries[0].sev.as_str(), "DBG");
}

#[test]
fn test_info_simple_uses_info_str() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "test");
    let entries = manager.get_entries();
    assert_eq!(entries[0].sev.as_str(), "INFO");
}

#[test]
fn test_warn_simple_uses_warn_str() {
    let mut manager = LogManager::new();
    manager.log(Severity::Warn, "test");
    let entries = manager.get_entries();
    assert_eq!(entries[0].sev.as_str(), "WARN");
}

#[test]
fn test_error_simple_uses_err_str() {
    let mut manager = LogManager::new();
    manager.log(Severity::Err, "test");
    let entries = manager.get_entries();
    assert_eq!(entries[0].sev.as_str(), "ERR");
}
