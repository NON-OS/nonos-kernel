// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::terminal::completion::{Completer, MAX_COMPLETIONS, MAX_COMPLETION_LEN};
use crate::test::framework::TestResult;

pub(crate) fn test_completer_new() -> TestResult {
    let completer = Completer::new();
    if completer.match_count() != 0 {
        return TestResult::Fail;
    }
    if completer.is_showing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_completions_empty() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"");
    if completer.match_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_completions_single_match() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"exi");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_completions_multiple_matches() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"l");
    if completer.match_count() <= 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_completions_no_match() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"zzzznotacommand");
    if completer.match_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_complete_single() -> TestResult {
    let mut completer = Completer::new();
    let result = completer.complete(b"exi");
    if result.is_none() {
        return TestResult::Fail;
    }
    let completion = result.unwrap();
    if completion != b"exit" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_complete_cycles() -> TestResult {
    let mut completer = Completer::new();
    let first = completer.complete(b"l");
    if first.is_none() {
        return TestResult::Fail;
    }

    let second = completer.complete(b"l");
    if second.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_complete_no_match() -> TestResult {
    let mut completer = Completer::new();
    let result = completer.complete(b"xyznotexist");
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_reset() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"ls");
    if completer.match_count() <= 0 {
        return TestResult::Fail;
    }
    completer.reset();
    if completer.match_count() != 0 {
        return TestResult::Fail;
    }
    if completer.is_showing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_is_showing_after_complete() -> TestResult {
    let mut completer = Completer::new();
    completer.complete(b"hel");
    if !completer.is_showing() && completer.match_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_prefix_cd() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"cd");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_prefix_cat() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"cat");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_prefix_vault() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"vault");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_prefix_net() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"net");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_completions_constant() -> TestResult {
    if MAX_COMPLETIONS != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_completion_len_constant() -> TestResult {
    if MAX_COMPLETION_LEN != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_complete_with_space_prefix() -> TestResult {
    let mut completer = Completer::new();
    let result = completer.complete(b"echo hel");
    if result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_completions_case_sensitive() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"LS");
    if completer.match_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_about() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"abo");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_clear() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"cle");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_crypto() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"cry");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_ping() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"pin");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_find_grep() -> TestResult {
    let mut completer = Completer::new();
    completer.find_completions(b"gre");
    if completer.match_count() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_reset_clears_showing() -> TestResult {
    let mut completer = Completer::new();
    completer.complete(b"ls");
    completer.reset();
    if completer.is_showing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completer_complete_returns_full_command() -> TestResult {
    let mut completer = Completer::new();
    let result = completer.complete(b"hel");
    if let Some(completion) = result {
        if completion.len() < 4 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
