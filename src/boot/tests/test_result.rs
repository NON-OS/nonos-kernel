// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestResult {
    Pass,
    Fail,
}

impl TestResult {
    pub fn passed(self) -> bool {
        matches!(self, Self::Pass)
    }
}
