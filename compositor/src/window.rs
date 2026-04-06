// SPDX-License-Identifier: MIT

//! Window state and UI mode management.
//!
//! Each window in Delphi carries an independent UI mode
//! (Direct, Assisted, Autonomous, Focus) displayed as a 12px
//! colored circle in the title bar. This module defines the
//! per-window state and mode types.

use serde::{Deserialize, Serialize};

/// The four UI modes from the Delphi spec.
///
/// Each window has its own mode. Modes operate independently
/// and simultaneously across windows.
///
/// # Examples
///
/// ```
/// use compositor::window::UiMode;
///
/// let mode = UiMode::Direct;
/// assert_eq!(mode.color(), [0.0, 0.8, 0.0, 1.0]);
/// assert_eq!(mode.label(), "Direct");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum UiMode {
    /// Full traditional desktop. AI invisible.
    #[default]
    Direct,
    /// User drives, AI navigates. Inline suggestions.
    Assisted,
    /// AI drives for delegated tasks. Ephemeral task UI.
    Autonomous,
    /// AI fully dormant. Maximum privacy.
    Focus,
}

impl UiMode {
    /// RGBA color for the mode badge (12px circle in title bar).
    ///
    /// - Green (#00cc00) = Direct
    /// - Purple (#9333ea) = Assisted
    /// - Orange (#f97316) = Autonomous
    /// - Gray (#6b7280) = Focus
    ///
    /// # Examples
    ///
    /// ```
    /// use compositor::window::UiMode;
    ///
    /// let color = UiMode::Assisted.color();
    /// assert!(color[0] > 0.5); // Purple has red component.
    /// ```
    #[must_use]
    pub fn color(self) -> [f32; 4] {
        match self {
            Self::Direct => [0.0, 0.8, 0.0, 1.0],
            Self::Assisted => [0.576, 0.2, 0.918, 1.0],
            Self::Autonomous => [0.976, 0.451, 0.086, 1.0],
            Self::Focus => [0.420, 0.447, 0.502, 1.0],
        }
    }

    /// Human-readable label for the mode.
    ///
    /// # Examples
    ///
    /// ```
    /// use compositor::window::UiMode;
    ///
    /// assert_eq!(UiMode::Focus.label(), "Focus");
    /// ```
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => "Direct",
            Self::Assisted => "Assisted",
            Self::Autonomous => "Autonomous",
            Self::Focus => "Focus",
        }
    }

    /// Cycle to the next mode.
    ///
    /// Order: Direct → Assisted → Autonomous → Focus → Direct.
    ///
    /// # Examples
    ///
    /// ```
    /// use compositor::window::UiMode;
    ///
    /// assert_eq!(UiMode::Direct.next(), UiMode::Assisted);
    /// assert_eq!(UiMode::Focus.next(), UiMode::Direct);
    /// ```
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Direct => Self::Assisted,
            Self::Assisted => Self::Autonomous,
            Self::Autonomous => Self::Focus,
            Self::Focus => Self::Direct,
        }
    }
}

/// Per-window state stored in the compositor.
///
/// Tracks position, size, UI mode, and title for each mapped surface.
///
/// # Examples
///
/// ```
/// use compositor::window::{WindowState, UiMode};
///
/// let win = WindowState::new(100, 100, 800, 600);
/// assert_eq!(win.mode, UiMode::Direct);
/// assert_eq!(win.x, 100);
/// ```
#[derive(Debug, Clone)]
pub struct WindowState {
    /// Window position (top-left X).
    pub x: i32,
    /// Window position (top-left Y).
    pub y: i32,
    /// Window width in pixels.
    pub width: i32,
    /// Window height in pixels.
    pub height: i32,
    /// UI mode for this window.
    pub mode: UiMode,
    /// Window title (from xdg_toplevel).
    pub title: String,
    /// Whether the window has been mapped (has a buffer).
    pub mapped: bool,
}

impl WindowState {
    /// Create a new window state at a given position and size.
    ///
    /// # Examples
    ///
    /// ```
    /// use compositor::window::WindowState;
    ///
    /// let win = WindowState::new(50, 50, 1024, 768);
    /// assert!(win.mapped);
    /// ```
    #[must_use]
    pub fn new(x: i32, y: i32, width: i32, height: i32) -> Self {
        Self {
            x,
            y,
            width,
            height,
            mode: UiMode::default(),
            title: String::new(),
            mapped: true,
        }
    }

    /// Check whether a point falls inside this window.
    ///
    /// # Examples
    ///
    /// ```
    /// use compositor::window::WindowState;
    ///
    /// let win = WindowState::new(10, 10, 100, 100);
    /// assert!(win.contains(50, 50));
    /// assert!(!win.contains(200, 200));
    /// ```
    #[must_use]
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x
            && px < self.x + self.width
            && py >= self.y
            && py < self.y + self.height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_colors_are_correct_alpha() {
        for mode in [UiMode::Direct, UiMode::Assisted, UiMode::Autonomous, UiMode::Focus] {
            let c = mode.color();
            assert!((c[3] - 1.0).abs() < f32::EPSILON, "{mode:?} alpha not 1.0");
        }
    }

    #[test]
    fn mode_labels_not_empty() {
        for mode in [UiMode::Direct, UiMode::Assisted, UiMode::Autonomous, UiMode::Focus] {
            assert!(!mode.label().is_empty());
        }
    }

    #[test]
    fn mode_cycle_returns_to_start() {
        let start = UiMode::Direct;
        let cycled = start.next().next().next().next();
        assert_eq!(start, cycled);
    }

    #[test]
    fn window_state_defaults() {
        let win = WindowState::new(0, 0, 640, 480);
        assert_eq!(win.mode, UiMode::Direct);
        assert!(win.title.is_empty());
        assert!(win.mapped);
    }

    #[test]
    fn window_contains_boundary() {
        let win = WindowState::new(10, 10, 100, 100);
        // Top-left corner is inside.
        assert!(win.contains(10, 10));
        // Bottom-right edge is outside (exclusive).
        assert!(!win.contains(110, 110));
    }

    #[test]
    fn focus_color_is_gray() {
        let c = UiMode::Focus.color();
        // Gray should have R ≈ G ≈ B.
        assert!((c[0] - c[1]).abs() < 0.05);
        assert!((c[1] - c[2]).abs() < 0.1);
    }
}
