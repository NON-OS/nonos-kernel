use crate::test::framework::TestResult;
use crate::userspace::init::spawn::SpawnError;
use crate::userspace::init::spawn_service;

pub(crate) fn test_spawn_error_debug() -> TestResult {
    let err = SpawnError::Failed;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("Failed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spawn_error_clone() -> TestResult {
    let err = SpawnError::Failed;
    let cloned = err.clone();
    if !matches!(cloned, SpawnError::Failed) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spawn_error_copy() -> TestResult {
    let err = SpawnError::Failed;
    let copied: SpawnError = err;
    if !matches!(copied, SpawnError::Failed) {
        return TestResult::Fail;
    }
    if !matches!(err, SpawnError::Failed) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spawn_error_from_static_str() -> TestResult {
    let err: SpawnError = "some error".into();
    if !matches!(err, SpawnError::Failed) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spawn_error_from_empty_str() -> TestResult {
    let err: SpawnError = "".into();
    if !matches!(err, SpawnError::Failed) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spawn_service_exported() -> TestResult {
    let _: fn(&str) -> Result<crate::process::core::Pid, SpawnError> = spawn_service;
    TestResult::Pass
}

pub(crate) fn test_spawn_error_is_failed_variant() -> TestResult {
    let err = SpawnError::Failed;
    match err {
        SpawnError::Failed => TestResult::Pass,
    }
}
