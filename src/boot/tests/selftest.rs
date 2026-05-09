// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use super::handoff_security;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelftestReport {
    pub handoff_security: bool,
}

impl SelftestReport {
    pub fn all_passed(&self) -> bool {
        self.handoff_security
    }
}

pub fn run_all() -> SelftestReport {
    SelftestReport { handoff_security: handoff_security::all_pass() }
}
