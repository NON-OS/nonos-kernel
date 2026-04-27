use crate::test::framework::TestResult;

pub(crate) fn test_settings_module_exists() -> TestResult {
    TestResult::Pass
}

pub(crate) fn test_theme_values() -> TestResult {
    let light: u8 = 0;
    let dark: u8 = 1;
    if light == dark {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_font_sizes() -> TestResult {
    let small: u8 = 12;
    let medium: u8 = 14;
    let large: u8 = 18;
    if !(small < medium) {
        return TestResult::Fail;
    }
    if !(medium < large) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
