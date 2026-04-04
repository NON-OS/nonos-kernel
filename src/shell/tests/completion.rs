use crate::shell::terminal::completion::{Completer, MAX_COMPLETIONS, MAX_COMPLETION_LEN};

#[test]
fn test_completer_new() {
    let completer = Completer::new();
    assert_eq!(completer.match_count(), 0);
    assert!(!completer.is_showing());
}

#[test]
fn test_completer_find_completions_empty() {
    let mut completer = Completer::new();
    completer.find_completions(b"");
    assert_eq!(completer.match_count(), 0);
}

#[test]
fn test_completer_find_completions_single_match() {
    let mut completer = Completer::new();
    completer.find_completions(b"exi");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_completer_find_completions_multiple_matches() {
    let mut completer = Completer::new();
    completer.find_completions(b"l");
    assert!(completer.match_count() > 1);
}

#[test]
fn test_completer_find_completions_no_match() {
    let mut completer = Completer::new();
    completer.find_completions(b"zzzznotacommand");
    assert_eq!(completer.match_count(), 0);
}

#[test]
fn test_completer_complete_single() {
    let mut completer = Completer::new();
    let result = completer.complete(b"exi");
    assert!(result.is_some());
    let completion = result.unwrap();
    assert_eq!(completion, b"exit");
}

#[test]
fn test_completer_complete_cycles() {
    let mut completer = Completer::new();
    let first = completer.complete(b"l");
    assert!(first.is_some());

    let second = completer.complete(b"l");
    assert!(second.is_some());
}

#[test]
fn test_completer_complete_no_match() {
    let mut completer = Completer::new();
    let result = completer.complete(b"xyznotexist");
    assert!(result.is_none());
}

#[test]
fn test_completer_reset() {
    let mut completer = Completer::new();
    completer.find_completions(b"ls");
    assert!(completer.match_count() > 0);
    completer.reset();
    assert_eq!(completer.match_count(), 0);
    assert!(!completer.is_showing());
}

#[test]
fn test_completer_is_showing_after_complete() {
    let mut completer = Completer::new();
    completer.complete(b"hel");
    assert!(completer.is_showing() || completer.match_count() == 1);
}

#[test]
fn test_completer_prefix_cd() {
    let mut completer = Completer::new();
    completer.find_completions(b"cd");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_completer_prefix_cat() {
    let mut completer = Completer::new();
    completer.find_completions(b"cat");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_completer_prefix_vault() {
    let mut completer = Completer::new();
    completer.find_completions(b"vault");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_completer_prefix_net() {
    let mut completer = Completer::new();
    completer.find_completions(b"net");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_max_completions_constant() {
    assert_eq!(MAX_COMPLETIONS, 16);
}

#[test]
fn test_max_completion_len_constant() {
    assert_eq!(MAX_COMPLETION_LEN, 32);
}

#[test]
fn test_completer_complete_with_space_prefix() {
    let mut completer = Completer::new();
    let result = completer.complete(b"echo hel");
    assert!(result.is_some());
}

#[test]
fn test_completer_find_completions_case_sensitive() {
    let mut completer = Completer::new();
    completer.find_completions(b"LS");
    assert_eq!(completer.match_count(), 0);
}

#[test]
fn test_completer_find_about() {
    let mut completer = Completer::new();
    completer.find_completions(b"abo");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_completer_find_clear() {
    let mut completer = Completer::new();
    completer.find_completions(b"cle");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_completer_find_crypto() {
    let mut completer = Completer::new();
    completer.find_completions(b"cry");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_completer_find_ping() {
    let mut completer = Completer::new();
    completer.find_completions(b"pin");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_completer_find_grep() {
    let mut completer = Completer::new();
    completer.find_completions(b"gre");
    assert!(completer.match_count() >= 1);
}

#[test]
fn test_completer_reset_clears_showing() {
    let mut completer = Completer::new();
    completer.complete(b"ls");
    completer.reset();
    assert!(!completer.is_showing());
}

#[test]
fn test_completer_complete_returns_full_command() {
    let mut completer = Completer::new();
    let result = completer.complete(b"hel");
    if let Some(completion) = result {
        assert!(completion.len() >= 4);
    }
}
