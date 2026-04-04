extern crate alloc;

use crate::apps::types::{AppError, AppId, AppType};

#[test]
fn test_app_id_new_increments() {
    let id1 = AppId::new();
    let id2 = AppId::new();
    assert!(id2.as_u64() > id1.as_u64());
}

#[test]
fn test_app_id_system_is_zero() {
    assert_eq!(AppId::SYSTEM.as_u64(), 0);
    assert!(AppId::SYSTEM.is_system());
}

#[test]
fn test_app_id_from_raw() {
    let id = AppId::from_raw(42);
    assert_eq!(id.as_u64(), 42);
    assert!(!id.is_system());
}

#[test]
fn test_app_id_display() {
    let id = AppId::from_raw(123);
    let s = alloc::format!("{}", id);
    assert_eq!(s, "app:123");
}

#[test]
fn test_app_id_default() {
    let id: AppId = Default::default();
    assert!(!id.is_system());
    assert!(id.as_u64() > 0);
}

#[test]
fn test_app_id_equality() {
    let id1 = AppId::from_raw(100);
    let id2 = AppId::from_raw(100);
    let id3 = AppId::from_raw(101);
    assert_eq!(id1, id2);
    assert_ne!(id1, id3);
}

#[test]
fn test_app_id_ordering() {
    let id1 = AppId::from_raw(10);
    let id2 = AppId::from_raw(20);
    assert!(id1 < id2);
    assert!(id2 > id1);
}

#[test]
fn test_app_id_hash() {
    use alloc::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(AppId::from_raw(1));
    set.insert(AppId::from_raw(2));
    set.insert(AppId::from_raw(1));
    assert_eq!(set.len(), 2);
}

#[test]
fn test_app_type_as_str() {
    assert_eq!(AppType::System.as_str(), "System");
    assert_eq!(AppType::Utility.as_str(), "Utility");
    assert_eq!(AppType::Browser.as_str(), "Browser");
    assert_eq!(AppType::Wallet.as_str(), "Wallet");
    assert_eq!(AppType::Finance.as_str(), "Finance");
    assert_eq!(AppType::Privacy.as_str(), "Privacy");
    assert_eq!(AppType::Network.as_str(), "Network");
    assert_eq!(AppType::Editor.as_str(), "Editor");
    assert_eq!(AppType::Terminal.as_str(), "Terminal");
    assert_eq!(AppType::Settings.as_str(), "Settings");
    assert_eq!(AppType::Ecosystem.as_str(), "Ecosystem");
}

#[test]
fn test_app_type_icon() {
    assert_eq!(AppType::System.icon(), "gear");
    assert_eq!(AppType::Browser.icon(), "globe");
    assert_eq!(AppType::Wallet.icon(), "wallet");
    assert_eq!(AppType::Privacy.icon(), "shield");
}

#[test]
fn test_app_type_requires_network() {
    assert!(AppType::Browser.requires_network());
    assert!(AppType::Wallet.requires_network());
    assert!(AppType::Finance.requires_network());
    assert!(AppType::Network.requires_network());
    assert!(AppType::Ecosystem.requires_network());
    assert!(!AppType::System.requires_network());
    assert!(!AppType::Utility.requires_network());
    assert!(!AppType::Editor.requires_network());
    assert!(!AppType::Terminal.requires_network());
    assert!(!AppType::Settings.requires_network());
    assert!(!AppType::Privacy.requires_network());
}

#[test]
fn test_app_type_requires_crypto() {
    assert!(AppType::Wallet.requires_crypto());
    assert!(AppType::Finance.requires_crypto());
    assert!(AppType::Privacy.requires_crypto());
    assert!(AppType::Ecosystem.requires_crypto());
    assert!(!AppType::Browser.requires_crypto());
    assert!(!AppType::System.requires_crypto());
    assert!(!AppType::Network.requires_crypto());
}

#[test]
fn test_app_type_default() {
    let default: AppType = Default::default();
    assert_eq!(default, AppType::Utility);
}

#[test]
fn test_app_type_equality() {
    assert_eq!(AppType::Browser, AppType::Browser);
    assert_ne!(AppType::Browser, AppType::Wallet);
}

#[test]
fn test_app_type_clone() {
    let t1 = AppType::Privacy;
    let t2 = t1.clone();
    assert_eq!(t1, t2);
}

#[test]
fn test_app_error_as_str() {
    assert_eq!(AppError::NotFound.as_str(), "Application not found");
    assert_eq!(AppError::AlreadyRegistered.as_str(), "Application already registered");
    assert_eq!(AppError::NotRunning.as_str(), "Application not running");
    assert_eq!(AppError::AlreadyRunning.as_str(), "Application already running");
    assert_eq!(AppError::PermissionDenied.as_str(), "Permission denied");
    assert_eq!(AppError::InvalidState.as_str(), "Invalid application state");
    assert_eq!(AppError::NetworkRequired.as_str(), "Network connectivity required");
    assert_eq!(AppError::CryptoRequired.as_str(), "Cryptographic subsystem required");
    assert_eq!(AppError::ResourceExhausted.as_str(), "Resources exhausted");
    assert_eq!(AppError::InitFailed.as_str(), "Initialization failed");
    assert_eq!(AppError::Timeout.as_str(), "Operation timed out");
    assert_eq!(AppError::Cancelled.as_str(), "Operation cancelled");
    assert_eq!(AppError::Internal.as_str(), "Internal error");
}

#[test]
fn test_app_error_display() {
    let err = AppError::NotFound;
    let s = alloc::format!("{}", err);
    assert_eq!(s, "Application not found");
}

#[test]
fn test_app_error_equality() {
    assert_eq!(AppError::NotFound, AppError::NotFound);
    assert_ne!(AppError::NotFound, AppError::NotRunning);
}

#[test]
fn test_app_error_clone() {
    let e1 = AppError::PermissionDenied;
    let e2 = e1.clone();
    assert_eq!(e1, e2);
}

#[test]
fn test_app_result_ok() {
    let result: crate::apps::types::AppResult<u32> = Ok(42);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_app_result_err() {
    let result: crate::apps::types::AppResult<u32> = Err(AppError::NotFound);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), AppError::NotFound);
}

#[test]
fn test_app_type_repr() {
    assert_eq!(AppType::System as u8, 0);
    assert_eq!(AppType::Utility as u8, 1);
    assert_eq!(AppType::Browser as u8, 2);
    assert_eq!(AppType::Wallet as u8, 3);
    assert_eq!(AppType::Finance as u8, 4);
    assert_eq!(AppType::Privacy as u8, 5);
    assert_eq!(AppType::Network as u8, 6);
    assert_eq!(AppType::Editor as u8, 7);
    assert_eq!(AppType::Terminal as u8, 8);
    assert_eq!(AppType::Settings as u8, 9);
    assert_eq!(AppType::Ecosystem as u8, 10);
}

#[test]
fn test_all_app_types_have_icons() {
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
        assert!(!t.icon().is_empty());
    }
}

#[test]
fn test_all_app_types_have_str() {
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
        assert!(!t.as_str().is_empty());
    }
}
