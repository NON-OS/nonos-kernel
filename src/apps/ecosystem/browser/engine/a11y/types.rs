extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AriaRole {
    Alert, AlertDialog, Application, Article, Banner, Button, Cell, Checkbox,
    Complementary, ContentInfo, Dialog, Document, Feed, Figure, Form, Grid,
    GridCell, Group, Heading, Img, Link, List, ListBox, ListItem, Main,
    Navigation, None, Option, Presentation, ProgressBar, Radio, RadioGroup,
    Region, Row, RowGroup, Search, Separator, Slider, SpinButton, Status,
    Switch, Tab, TabList, TabPanel, Table, TextBox, Timer, ToolBar, Tooltip, Tree,
}

#[derive(Debug, Clone)]
pub struct AccessibleState {
    pub checked: Option<bool>,
    pub disabled: bool,
    pub expanded: Option<bool>,
    pub hidden: bool,
    pub selected: bool,
    pub required: bool,
    pub live: Option<String>,
}

impl AccessibleState {
    pub fn default_state() -> Self {
        Self { checked: None, disabled: false, expanded: None, hidden: false, selected: false, required: false, live: None }
    }
}

#[derive(Debug, Clone)]
pub struct AccessibleNode {
    pub role: AriaRole,
    pub name: String,
    pub description: String,
    pub state: AccessibleState,
    pub children: Vec<AccessibleNode>,
    pub level: Option<u32>,
}

impl AccessibleNode {
    pub fn new(role: AriaRole, name: &str) -> Self {
        Self { role, name: String::from(name), description: String::new(), state: AccessibleState::default_state(), children: Vec::new(), level: None }
    }
}
