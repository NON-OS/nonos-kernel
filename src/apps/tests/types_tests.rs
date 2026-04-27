// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::apps::types::{AppError, AppId, AppResult, AppType};
use crate::test::framework::TestResult;

pub(crate) fn test_app_id_new_increments() -> TestResult {
    let id1 = AppId::new();
    let id2 = AppId::new();
    if id2.as_u64() <= id1.as_u64() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_id_system_is_zero() -> TestResult {
    if AppId::SYSTEM.as_u64() != 0 {
        return TestResult::Fail;
    }
    if !AppId::SYSTEM.is_system() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_id_from_raw() -> TestResult {
    let id = AppId::from_raw(42);
    if id.as_u64() != 42 {
        return TestResult::Fail;
    }
    if id.is_system() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_id_display() -> TestResult {
    let id = AppId::from_raw(123);
    let s = alloc::format!("{}", id);
    if s != "app:123" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_id_default() -> TestResult {
    let id: AppId = Default::default();
    if id.is_system() {
        return TestResult::Fail;
    }
    if id.as_u64() == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_id_equality() -> TestResult {
    let id1 = AppId::from_raw(100);
    let id2 = AppId::from_raw(100);
    let id3 = AppId::from_raw(101);
    if id1 != id2 {
        return TestResult::Fail;
    }
    if id1 == id3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_id_ordering() -> TestResult {
    let id1 = AppId::from_raw(10);
    let id2 = AppId::from_raw(20);
    if !(id1 < id2) {
        return TestResult::Fail;
    }
    if !(id2 > id1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_id_hash() -> TestResult {
    use alloc::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(AppId::from_raw(1));
    set.insert(AppId::from_raw(2));
    set.insert(AppId::from_raw(1));
    if set.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_type_as_str() -> TestResult {
    if AppType::System.as_str() != "System" {
        return TestResult::Fail;
    }
    if AppType::Utility.as_str() != "Utility" {
        return TestResult::Fail;
    }
    if AppType::Browser.as_str() != "Browser" {
        return TestResult::Fail;
    }
    if AppType::Wallet.as_str() != "Wallet" {
        return TestResult::Fail;
    }
    if AppType::Finance.as_str() != "Finance" {
        return TestResult::Fail;
    }
    if AppType::Privacy.as_str() != "Privacy" {
        return TestResult::Fail;
    }
    if AppType::Network.as_str() != "Network" {
        return TestResult::Fail;
    }
    if AppType::Editor.as_str() != "Editor" {
        return TestResult::Fail;
    }
    if AppType::Terminal.as_str() != "Terminal" {
        return TestResult::Fail;
    }
    if AppType::Settings.as_str() != "Settings" {
        return TestResult::Fail;
    }
    if AppType::Ecosystem.as_str() != "Ecosystem" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_type_icon() -> TestResult {
    if AppType::System.icon() != "gear" {
        return TestResult::Fail;
    }
    if AppType::Browser.icon() != "globe" {
        return TestResult::Fail;
    }
    if AppType::Wallet.icon() != "wallet" {
        return TestResult::Fail;
    }
    if AppType::Privacy.icon() != "shield" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_type_requires_network() -> TestResult {
    if !AppType::Browser.requires_network() {
        return TestResult::Fail;
    }
    if !AppType::Wallet.requires_network() {
        return TestResult::Fail;
    }
    if !AppType::Finance.requires_network() {
        return TestResult::Fail;
    }
    if !AppType::Network.requires_network() {
        return TestResult::Fail;
    }
    if !AppType::Ecosystem.requires_network() {
        return TestResult::Fail;
    }
    if AppType::System.requires_network() {
        return TestResult::Fail;
    }
    if AppType::Utility.requires_network() {
        return TestResult::Fail;
    }
    if AppType::Editor.requires_network() {
        return TestResult::Fail;
    }
    if AppType::Terminal.requires_network() {
        return TestResult::Fail;
    }
    if AppType::Settings.requires_network() {
        return TestResult::Fail;
    }
    if AppType::Privacy.requires_network() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_type_requires_crypto() -> TestResult {
    if !AppType::Wallet.requires_crypto() {
        return TestResult::Fail;
    }
    if !AppType::Finance.requires_crypto() {
        return TestResult::Fail;
    }
    if !AppType::Privacy.requires_crypto() {
        return TestResult::Fail;
    }
    if !AppType::Ecosystem.requires_crypto() {
        return TestResult::Fail;
    }
    if AppType::Browser.requires_crypto() {
        return TestResult::Fail;
    }
    if AppType::System.requires_crypto() {
        return TestResult::Fail;
    }
    if AppType::Network.requires_crypto() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_type_default() -> TestResult {
    let default: AppType = Default::default();
    if default != AppType::Utility {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_type_equality() -> TestResult {
    if AppType::Browser != AppType::Browser {
        return TestResult::Fail;
    }
    if AppType::Browser == AppType::Wallet {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_type_clone() -> TestResult {
    let t1 = AppType::Privacy;
    let t2 = t1.clone();
    if t1 != t2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_error_as_str() -> TestResult {
    if AppError::NotFound.as_str() != "Application not found" {
        return TestResult::Fail;
    }
    if AppError::AlreadyRegistered.as_str() != "Application already registered" {
        return TestResult::Fail;
    }
    if AppError::NotRunning.as_str() != "Application not running" {
        return TestResult::Fail;
    }
    if AppError::AlreadyRunning.as_str() != "Application already running" {
        return TestResult::Fail;
    }
    if AppError::PermissionDenied.as_str() != "Permission denied" {
        return TestResult::Fail;
    }
    if AppError::InvalidState.as_str() != "Invalid application state" {
        return TestResult::Fail;
    }
    if AppError::NetworkRequired.as_str() != "Network connectivity required" {
        return TestResult::Fail;
    }
    if AppError::CryptoRequired.as_str() != "Cryptographic subsystem required" {
        return TestResult::Fail;
    }
    if AppError::ResourceExhausted.as_str() != "Resources exhausted" {
        return TestResult::Fail;
    }
    if AppError::InitFailed.as_str() != "Initialization failed" {
        return TestResult::Fail;
    }
    if AppError::Timeout.as_str() != "Operation timed out" {
        return TestResult::Fail;
    }
    if AppError::Cancelled.as_str() != "Operation cancelled" {
        return TestResult::Fail;
    }
    if AppError::Internal.as_str() != "Internal error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_error_display() -> TestResult {
    let err = AppError::NotFound;
    let s = alloc::format!("{}", err);
    if s != "Application not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_error_equality() -> TestResult {
    if AppError::NotFound != AppError::NotFound {
        return TestResult::Fail;
    }
    if AppError::NotFound == AppError::NotRunning {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_error_clone() -> TestResult {
    let e1 = AppError::PermissionDenied;
    let e2 = e1.clone();
    if e1 != e2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_result_ok() -> TestResult {
    let result: AppResult<u32> = Ok(42);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_result_err() -> TestResult {
    let result: AppResult<u32> = Err(AppError::NotFound);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != AppError::NotFound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_type_repr() -> TestResult {
    if (AppType::System as u8) != 0 {
        return TestResult::Fail;
    }
    if (AppType::Utility as u8) != 1 {
        return TestResult::Fail;
    }
    if (AppType::Browser as u8) != 2 {
        return TestResult::Fail;
    }
    if (AppType::Wallet as u8) != 3 {
        return TestResult::Fail;
    }
    if (AppType::Finance as u8) != 4 {
        return TestResult::Fail;
    }
    if (AppType::Privacy as u8) != 5 {
        return TestResult::Fail;
    }
    if (AppType::Network as u8) != 6 {
        return TestResult::Fail;
    }
    if (AppType::Editor as u8) != 7 {
        return TestResult::Fail;
    }
    if (AppType::Terminal as u8) != 8 {
        return TestResult::Fail;
    }
    if (AppType::Settings as u8) != 9 {
        return TestResult::Fail;
    }
    if (AppType::Ecosystem as u8) != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_app_types_have_icons() -> TestResult {
    let types = [
        AppType::System,
        AppType::Utility,
        AppType::Browser,
        AppType::Wallet,
        AppType::Finance,
        AppType::Privacy,
        AppType::Network,
        AppType::Editor,
        AppType::Terminal,
        AppType::Settings,
        AppType::Ecosystem,
    ];
    for t in types {
        if t.icon().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_app_types_have_str() -> TestResult {
    let types = [
        AppType::System,
        AppType::Utility,
        AppType::Browser,
        AppType::Wallet,
        AppType::Finance,
        AppType::Privacy,
        AppType::Network,
        AppType::Editor,
        AppType::Terminal,
        AppType::Settings,
        AppType::Ecosystem,
    ];
    for t in types {
        if t.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
