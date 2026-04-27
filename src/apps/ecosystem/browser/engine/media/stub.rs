extern crate alloc;
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaState {
    Idle,
    Loading,
    Playing,
    Paused,
    Ended,
    Error,
}

pub struct MediaElement {
    pub src: String,
    pub state: MediaState,
    pub current_time: f64,
    pub duration: f64,
    pub muted: bool,
    pub volume: f64,
    pub loop_playback: bool,
}

impl MediaElement {
    pub fn new() -> Self {
        Self {
            src: String::new(),
            state: MediaState::Idle,
            current_time: 0.0,
            duration: 0.0,
            muted: false,
            volume: 1.0,
            loop_playback: false,
        }
    }

    pub fn play(&mut self) -> Result<(), &'static str> {
        Err("media playback not supported")
    }

    pub fn pause(&mut self) {
        self.state = MediaState::Paused;
    }

    pub fn load(&mut self, src: &str) {
        self.src = String::from(src);
        self.state = MediaState::Error;
    }

    pub fn can_play_type(&self, _mime: &str) -> &'static str {
        ""
    }
}
