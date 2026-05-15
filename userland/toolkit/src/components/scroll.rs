#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrollState {
    pub offset: u32,
    pub content: u32,
    pub viewport: u32,
}

impl ScrollState {
    pub fn clamp(mut self) -> Self {
        let max = self.content.saturating_sub(self.viewport);
        if self.offset > max {
            self.offset = max;
        }
        self
    }
}
