use crate::shell::terminal::history::{CommandHistory, HISTORY_SIZE, MAX_CMD_LEN};

#[test]
fn test_command_history_new() {
    let history = CommandHistory::new();
    assert_eq!(history.count(), 0);
    assert!(!history.is_browsing());
}

#[test]
fn test_command_history_add_single() {
    let mut history = CommandHistory::new();
    history.add(b"ls -la");
    assert_eq!(history.count(), 1);
}

#[test]
fn test_command_history_add_empty() {
    let mut history = CommandHistory::new();
    history.add(b"");
    assert_eq!(history.count(), 0);
}

#[test]
fn test_command_history_add_multiple() {
    let mut history = CommandHistory::new();
    history.add(b"ls");
    history.add(b"pwd");
    history.add(b"cd /home");
    assert_eq!(history.count(), 3);
}

#[test]
fn test_command_history_no_duplicates() {
    let mut history = CommandHistory::new();
    history.add(b"ls");
    history.add(b"ls");
    assert_eq!(history.count(), 1);
}

#[test]
fn test_command_history_duplicates_after_other() {
    let mut history = CommandHistory::new();
    history.add(b"ls");
    history.add(b"pwd");
    history.add(b"ls");
    assert_eq!(history.count(), 3);
}

#[test]
fn test_command_history_get_single() {
    let mut history = CommandHistory::new();
    history.add(b"test command");
    let (cmd, len) = history.get(0).unwrap();
    assert_eq!(&cmd[..len], b"test command");
}

#[test]
fn test_command_history_get_multiple() {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.add(b"second");
    history.add(b"third");

    let (cmd0, len0) = history.get(0).unwrap();
    assert_eq!(&cmd0[..len0], b"first");

    let (cmd1, len1) = history.get(1).unwrap();
    assert_eq!(&cmd1[..len1], b"second");

    let (cmd2, len2) = history.get(2).unwrap();
    assert_eq!(&cmd2[..len2], b"third");
}

#[test]
fn test_command_history_get_out_of_bounds() {
    let mut history = CommandHistory::new();
    history.add(b"only one");
    assert!(history.get(1).is_none());
}

#[test]
fn test_command_history_get_empty() {
    let history = CommandHistory::new();
    assert!(history.get(0).is_none());
}

#[test]
fn test_command_history_start_browse() {
    let mut history = CommandHistory::new();
    history.add(b"cmd1");
    history.add(b"cmd2");
    history.start_browse(b"current");
    assert!(history.is_browsing());
}

#[test]
fn test_command_history_browse_prev() {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.add(b"second");
    history.start_browse(b"");

    let (cmd, len) = history.prev().unwrap();
    assert_eq!(&cmd[..len], b"second");
}

#[test]
fn test_command_history_browse_prev_multiple() {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.add(b"second");
    history.add(b"third");
    history.start_browse(b"");

    let (cmd1, len1) = history.prev().unwrap();
    assert_eq!(&cmd1[..len1], b"third");

    let (cmd2, len2) = history.prev().unwrap();
    assert_eq!(&cmd2[..len2], b"second");

    let (cmd3, len3) = history.prev().unwrap();
    assert_eq!(&cmd3[..len3], b"first");
}

#[test]
fn test_command_history_browse_prev_at_start() {
    let mut history = CommandHistory::new();
    history.add(b"only");
    history.start_browse(b"");
    history.prev();
    assert!(history.prev().is_none());
}

#[test]
fn test_command_history_browse_next() {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.add(b"second");
    history.start_browse(b"saved");
    history.prev();
    history.prev();

    let (cmd, len) = history.next().unwrap();
    assert_eq!(&cmd[..len], b"second");
}

#[test]
fn test_command_history_browse_next_to_saved() {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.start_browse(b"saved");
    history.prev();

    let (cmd, len) = history.next().unwrap();
    assert_eq!(&cmd[..len], b"saved");
    assert!(!history.is_browsing());
}

#[test]
fn test_command_history_browse_next_not_browsing() {
    let mut history = CommandHistory::new();
    history.add(b"cmd");
    assert!(history.next().is_none());
}

#[test]
fn test_command_history_cancel_browse() {
    let mut history = CommandHistory::new();
    history.add(b"cmd");
    history.start_browse(b"");
    assert!(history.is_browsing());
    history.cancel_browse();
    assert!(!history.is_browsing());
}

#[test]
fn test_command_history_clear() {
    let mut history = CommandHistory::new();
    history.add(b"cmd1");
    history.add(b"cmd2");
    history.clear();
    assert_eq!(history.count(), 0);
    assert!(history.get(0).is_none());
}

#[test]
fn test_command_history_overflow() {
    let mut history = CommandHistory::new();
    for i in 0..HISTORY_SIZE + 10 {
        let mut cmd = [0u8; 16];
        let s = alloc::format!("cmd{}", i);
        cmd[..s.len()].copy_from_slice(s.as_bytes());
        history.add(&cmd[..s.len()]);
    }
    assert_eq!(history.count(), HISTORY_SIZE);
}

#[test]
fn test_command_history_truncates_long() {
    let mut history = CommandHistory::new();
    let long_cmd = [b'x'; MAX_CMD_LEN + 100];
    history.add(&long_cmd);
    assert_eq!(history.count(), 1);
    let (_, len) = history.get(0).unwrap();
    assert_eq!(len, MAX_CMD_LEN);
}

#[test]
fn test_history_size_constant() {
    assert_eq!(HISTORY_SIZE, 64);
}

#[test]
fn test_max_cmd_len_constant() {
    assert_eq!(MAX_CMD_LEN, 256);
}

#[test]
fn test_command_history_secure_erase() {
    let mut history = CommandHistory::new();
    history.add(b"secret command");
    history.secure_erase();
    assert_eq!(history.count(), 0);
    assert!(!history.is_browsing());
}

#[test]
fn test_command_history_browse_empty() {
    let mut history = CommandHistory::new();
    history.start_browse(b"test");
    assert!(history.prev().is_none());
}

#[test]
fn test_command_history_add_preserves_order() {
    let mut history = CommandHistory::new();
    history.add(b"alpha");
    history.add(b"beta");
    history.add(b"gamma");

    let (cmd0, len0) = history.get(0).unwrap();
    let (cmd1, len1) = history.get(1).unwrap();
    let (cmd2, len2) = history.get(2).unwrap();

    assert_eq!(&cmd0[..len0], b"alpha");
    assert_eq!(&cmd1[..len1], b"beta");
    assert_eq!(&cmd2[..len2], b"gamma");
}

#[test]
fn test_command_history_browsing_resets_on_add() {
    let mut history = CommandHistory::new();
    history.add(b"first");
    history.start_browse(b"");
    history.prev();
    assert!(history.is_browsing());
    history.add(b"second");
    assert!(!history.is_browsing());
}
