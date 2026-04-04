use crate::userspace::init::spawn_service;
use crate::userspace::init::spawn::SpawnError;

#[test]
fn test_spawn_error_debug() {
    let err = SpawnError::Failed;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("Failed"));
}

#[test]
fn test_spawn_error_clone() {
    let err = SpawnError::Failed;
    let cloned = err.clone();
    assert!(matches!(cloned, SpawnError::Failed));
}

#[test]
fn test_spawn_error_copy() {
    let err = SpawnError::Failed;
    let copied: SpawnError = err;
    assert!(matches!(copied, SpawnError::Failed));
    assert!(matches!(err, SpawnError::Failed));
}

#[test]
fn test_spawn_error_from_static_str() {
    let err: SpawnError = "some error".into();
    assert!(matches!(err, SpawnError::Failed));
}

#[test]
fn test_spawn_error_from_empty_str() {
    let err: SpawnError = "".into();
    assert!(matches!(err, SpawnError::Failed));
}

#[test]
fn test_spawn_service_exported() {
    let _: fn(&str) -> Result<crate::process::core::Pid, SpawnError> = spawn_service;
}

#[test]
fn test_spawn_error_is_failed_variant() {
    let err = SpawnError::Failed;
    match err {
        SpawnError::Failed => assert!(true),
    }
}
