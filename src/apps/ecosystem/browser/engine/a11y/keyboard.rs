#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A11yAction {
    Click,
    Toggle,
    Dismiss,
    MoveNext,
    MovePrev,
    None,
}

pub fn handle_keyboard_a11y(key: &str, tag: &str) -> A11yAction {
    match key {
        "Enter" => match tag {
            "a" | "button" | "summary" => A11yAction::Click,
            "input" => A11yAction::Click,
            _ => A11yAction::None,
        },
        " " | "Space" => match tag {
            "button" => A11yAction::Click,
            "input" => A11yAction::Toggle,
            "select" => A11yAction::Toggle,
            _ => A11yAction::None,
        },
        "Escape" => A11yAction::Dismiss,
        "ArrowDown" | "ArrowRight" => A11yAction::MoveNext,
        "ArrowUp" | "ArrowLeft" => A11yAction::MovePrev,
        _ => A11yAction::None,
    }
}
