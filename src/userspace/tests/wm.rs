use crate::test::framework::TestResult;

const WM_MAIN: &str = include_str!("../../../userland/wm/src/main.rs");

pub(crate) fn test_wm_focus_policy_regression_markers() -> TestResult {
    if !WM_MAIN.contains("WM_OP_FOCUS_SET") {
        return TestResult::Fail;
    }
    if !WM_MAIN.contains("focus policy owner") {
        return TestResult::Fail;
    }
    if !WM_MAIN.contains("WM_OP_Z_ORDER_SET") {
        return TestResult::Fail;
    }
    if !WM_MAIN.contains("z-order policy owner") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_wm_lifecycle_resize_regression_markers() -> TestResult {
    if !WM_MAIN.contains("WM_OP_LIFECYCLE_EVENT") {
        return TestResult::Fail;
    }
    if !WM_MAIN.contains("lifecycle policy owner") {
        return TestResult::Fail;
    }
    if !WM_MAIN.contains("WM_OP_RESIZE_REQUEST") {
        return TestResult::Fail;
    }
    if !WM_MAIN.contains("resize policy owner") {
        return TestResult::Fail;
    }
    if !WM_MAIN.contains("mk_ipc_recv(WM_ENDPOINT") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
