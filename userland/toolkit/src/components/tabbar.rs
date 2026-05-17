#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TabBarState {
    pub selected: usize,
    pub tabs: usize,
}

impl TabBarState {
    pub fn select(mut self, idx: usize) -> Self {
        if self.tabs == 0 {
            self.selected = 0;
            return self;
        }
        self.selected = idx.min(self.tabs - 1);
        self
    }
}
