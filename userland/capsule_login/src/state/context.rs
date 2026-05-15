use crate::protocol::{E_AUTH, E_BUSY};

pub struct Context {
    pub keyring_port: u32,
    pub desktop_shell_port: u32,
    pub compositor_port: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub backing_va: u64,
    serial: u32,
    state: SessionState,
}

enum SessionState {
    Locked,
    Unlocked { owner_pid: u32, key_id: u32, serial: u32 },
}

impl Context {
    pub fn new(
        keyring_port: u32,
        desktop_shell_port: u32,
        compositor_port: u32,
        width: u32,
        height: u32,
        stride: u32,
        backing_va: u64,
    ) -> Self {
        Self {
            keyring_port,
            desktop_shell_port,
            compositor_port,
            width,
            height,
            stride,
            backing_va,
            serial: 0,
            state: SessionState::Locked,
        }
    }

    pub fn start_session(&mut self, owner_pid: u32, key_id: u32) -> Result<u32, i32> {
        if matches!(self.state, SessionState::Unlocked { .. }) {
            return Err(E_BUSY);
        }
        self.serial = self.serial.wrapping_add(1);
        let serial = self.serial;
        self.state = SessionState::Unlocked { owner_pid, key_id, serial };
        Ok(serial)
    }

    pub fn end_session(&mut self, caller_pid: u32) -> Result<(), i32> {
        match self.state {
            SessionState::Locked => Ok(()),
            SessionState::Unlocked { owner_pid, .. } if owner_pid != caller_pid => Err(E_AUTH),
            SessionState::Unlocked { .. } => {
                self.state = SessionState::Locked;
                Ok(())
            }
        }
    }

    pub fn state_words(&self) -> (u32, u32, u32) {
        match self.state {
            SessionState::Locked => (0, 0, 0),
            SessionState::Unlocked { owner_pid, serial, .. } => (1, owner_pid, serial),
        }
    }

    pub fn current_key_id(&self) -> Option<u32> {
        match self.state {
            SessionState::Locked => None,
            SessionState::Unlocked { key_id, .. } => Some(key_id),
        }
    }
}
