// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::terminal::history::{CommandHistory, HISTORY_SIZE, MAX_CMD_LEN};
use crate::test::framework::TestResult;

pub(crate) fn test_command_history_new() -> TestResult {
    let history = CommandHistory::new();
    if history.count() != 0 {
        return TestResult::Fail;
    }
    if history.is_browsing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_add_single() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"ls -la");
    if history.count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_add_empty() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"");
    if history.count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_add_multiple() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"ls");
    history.add(b"pwd");
    history.add(b"cd /home");
    if history.count() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_no_duplicates() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"ls");
    history.add(b"ls");
    if history.count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_duplicates_after_other() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"ls");
    history.add(b"pwd");
    history.add(b"ls");
    if history.count() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_get_single() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"test command");
    let (cmd, len) = history.get(0).unwrap();
    if &cmd[..len] != b"test command" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_get_multiple() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.add(b"second");
    history.add(b"third");

    let (cmd0, len0) = history.get(0).unwrap();
    if &cmd0[..len0] != b"first" {
        return TestResult::Fail;
    }

    let (cmd1, len1) = history.get(1).unwrap();
    if &cmd1[..len1] != b"second" {
        return TestResult::Fail;
    }

    let (cmd2, len2) = history.get(2).unwrap();
    if &cmd2[..len2] != b"third" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_get_out_of_bounds() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"only one");
    if history.get(1).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_get_empty() -> TestResult {
    let history = CommandHistory::new();
    if history.get(0).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_start_browse() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"cmd1");
    history.add(b"cmd2");
    history.start_browse(b"current");
    if !history.is_browsing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_browse_prev() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.add(b"second");
    history.start_browse(b"");

    let (cmd, len) = history.prev().unwrap();
    if &cmd[..len] != b"second" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_browse_prev_multiple() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.add(b"second");
    history.add(b"third");
    history.start_browse(b"");

    let (cmd1, len1) = history.prev().unwrap();
    if &cmd1[..len1] != b"third" {
        return TestResult::Fail;
    }

    let (cmd2, len2) = history.prev().unwrap();
    if &cmd2[..len2] != b"second" {
        return TestResult::Fail;
    }

    let (cmd3, len3) = history.prev().unwrap();
    if &cmd3[..len3] != b"first" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_browse_prev_at_start() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"only");
    history.start_browse(b"");
    history.prev();
    if history.prev().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_browse_next() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.add(b"second");
    history.start_browse(b"saved");
    history.prev();
    history.prev();

    let (cmd, len) = history.next().unwrap();
    if &cmd[..len] != b"second" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_browse_next_to_saved() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.start_browse(b"saved");
    history.prev();

    let (cmd, len) = history.next().unwrap();
    if &cmd[..len] != b"saved" {
        return TestResult::Fail;
    }
    if history.is_browsing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_browse_next_not_browsing() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"cmd");
    if history.next().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_cancel_browse() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"cmd");
    history.start_browse(b"");
    if !history.is_browsing() {
        return TestResult::Fail;
    }
    history.cancel_browse();
    if history.is_browsing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_clear() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"cmd1");
    history.add(b"cmd2");
    history.clear();
    if history.count() != 0 {
        return TestResult::Fail;
    }
    if history.get(0).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_overflow() -> TestResult {
    let mut history = CommandHistory::new();
    for i in 0..HISTORY_SIZE + 10 {
        let mut cmd = [0u8; 16];
        let s = alloc::format!("cmd{}", i);
        cmd[..s.len()].copy_from_slice(s.as_bytes());
        history.add(&cmd[..s.len()]);
    }
    if history.count() != HISTORY_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_truncates_long() -> TestResult {
    let mut history = CommandHistory::new();
    let long_cmd = [b'x'; MAX_CMD_LEN + 100];
    history.add(&long_cmd);
    if history.count() != 1 {
        return TestResult::Fail;
    }
    let (_, len) = history.get(0).unwrap();
    if len != MAX_CMD_LEN {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_history_size_constant() -> TestResult {
    if HISTORY_SIZE != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_cmd_len_constant() -> TestResult {
    if MAX_CMD_LEN != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_secure_erase() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"secret command");
    history.secure_erase();
    if history.count() != 0 {
        return TestResult::Fail;
    }
    if history.is_browsing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_browse_empty() -> TestResult {
    let mut history = CommandHistory::new();
    history.start_browse(b"test");
    if history.prev().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_add_preserves_order() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"alpha");
    history.add(b"beta");
    history.add(b"gamma");

    let (cmd0, len0) = history.get(0).unwrap();
    let (cmd1, len1) = history.get(1).unwrap();
    let (cmd2, len2) = history.get(2).unwrap();

    if &cmd0[..len0] != b"alpha" {
        return TestResult::Fail;
    }
    if &cmd1[..len1] != b"beta" {
        return TestResult::Fail;
    }
    if &cmd2[..len2] != b"gamma" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_history_browsing_resets_on_add() -> TestResult {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.start_browse(b"");
    history.prev();
    if !history.is_browsing() {
        return TestResult::Fail;
    }
    history.add(b"second");
    if history.is_browsing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
