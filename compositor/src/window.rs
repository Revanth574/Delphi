// SPDX-License-Identifier: MIT

//! Window state and UI mode management.
//!
//! Each window in Delphi carries an independent UI mode
//! (Direct, Assisted, Autonomous, Focus) displayed as a 12px
//! colored circle in the title bar. This module defines the
//! per-window state and mode types.

use serde::{Deserialize, Serialize};

/// Title bar height in pixels (server-side decoration).
pub const TITLE_BAR_HEIGHT: i32 = 30;

/// Window border width for resize hit detection.
pub const BORDER_WIDTH: i32 = 4;

/// Mode badge circle diameter in pixels.
pub const MODE_BADGE_SIZE: i32 = 12;

/// Close button width in title bar.
pub const CLOSE_BUTTON_WIDTH: i32 = 30;

/// Title bar background color (dark gray-blue).
pub const TITLE_BAR_COLOR: [f32; 4] = [0.15, 0.15, 0.20, 1.0];

/// Focused title bar color (slightly brighter).
pub const TITLE_BAR_FOCUSED_COLOR: [f32; 4] = [0.20, 0.20, 0.28, 1.0];

/// Close button color (red).
pub const CLOSE_BUTTON_COLOR: [f32; 4] = [0.85, 0.20, 0.20, 1.0];

/// Result of hit-testing a point against a window.
///
/// # Examples
///
/// ```
/// use compositor::window::HitZone;
///
/// let zone = HitZone::TitleBar;
/// assert_ne!(zone, HitZone::ClientArea);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitZone {
    /// The window title bar (drag to move).
    TitleBar,
    /// The close button in the title bar.
    CloseButton,
    /// The client content area.
    ClientArea,
    /// A resize edge.
    ResizeEdge(ResizeEdge),
    /// Outside the window entirely.
    Outside,
}

/// Which edge of the window is being resized.
///
/// # Examples
///
/// ```
/// use compositor::window::ResizeEdge;
///
/// let edge = ResizeEdge::Right;
/// assert_ne!(edge, ResizeEdge::Left);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeEdge {
    /// Left edge.
    Left,
    /// Right edge.
    Right,
    /// Top edge.
    Top,
    /// Bottom edge.
    Bottom,
}

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

    /// Hit-test a point against this window's zones.
    ///
    /// Returns which part of the window the point falls in:
    /// title bar, close button, client area, resize edge, or outside.
    ///
    /// # Examples
    ///
    /// ```
    /// use compositor::window::{WindowState, HitZone};
    ///
    /// let win = WindowState::new(10, 10, 200, 200);
    /// assert_eq!(win.hit_test(50, 15), HitZone::TitleBar);
    /// assert_eq!(win.hit_test(50, 100), HitZone::ClientArea);
    /// ```
    #[must_use]
    pub fn hit_test(&self, px: i32, py: i32) -> HitZone {
        // Check resize edges first (extend slightly outside window).
        if let Some(edge) = self.check_resize_edge(px, py) {
            return HitZone::ResizeEdge(edge);
        }

        if !self.contains(px, py) {
            return HitZone::Outside;
        }

        // Close button (top-right of title bar).
        if py < self.y + TITLE_BAR_HEIGHT
            && px >= self.x + self.width - CLOSE_BUTTON_WIDTH
        {
            return HitZone::CloseButton;
        }

        // Title bar.
        if py < self.y + TITLE_BAR_HEIGHT {
            return HitZone::TitleBar;
        }

        HitZone::ClientArea
    }

    /// Check if a point is on a resize edge of this window.
    #[must_use]
    fn check_resize_edge(&self, px: i32, py: i32) -> Option<ResizeEdge> {
        let bw = BORDER_WIDTH;
        let in_x = px >= self.x - bw && px < self.x + self.width + bw;
        let in_y = py >= self.y - bw && py < self.y + self.height + bw;

        if !in_x || !in_y {
            return None;
        }

        if px < self.x && in_y {
            Some(ResizeEdge::Left)
        } else if px >= self.x + self.width && in_y {
            Some(ResizeEdge::Right)
        } else if py < self.y && in_x {
            Some(ResizeEdge::Top)
        } else if py >= self.y + self.height && in_x {
            Some(ResizeEdge::Bottom)
        } else {
            None
        }
    }

    /// Get the client area rectangle (below the title bar).
    ///
    /// # Examples
    ///
    /// ```
    /// use compositor::window::WindowState;
    ///
    /// let win = WindowState::new(10, 10, 800, 600);
    /// let (cx, cy, cw, ch) = win.client_rect();
    /// assert_eq!(cy, 10 + 30); // Below title bar.
    /// ```
    #[must_use]
    pub fn client_rect(&self) -> (i32, i32, i32, i32) {
        (
            self.x,
            self.y + TITLE_BAR_HEIGHT,
            self.width,
            (self.height - TITLE_BAR_HEIGHT).max(0),
        )
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

    #[test]
    fn hit_test_title_bar() {
        let win = WindowState::new(10, 10, 200, 200);
        // Inside title bar (y < 10 + 30 = 40).
        assert_eq!(win.hit_test(50, 20), HitZone::TitleBar);
    }

    #[test]
    fn hit_test_close_button() {
        let win = WindowState::new(10, 10, 200, 200);
        // Close button: top-right corner of title bar.
        assert_eq!(win.hit_test(200, 20), HitZone::CloseButton);
    }

    #[test]
    fn hit_test_client_area() {
        let win = WindowState::new(10, 10, 200, 200);
        // Below title bar.
        assert_eq!(win.hit_test(50, 100), HitZone::ClientArea);
    }

    #[test]
    fn hit_test_outside() {
        let win = WindowState::new(10, 10, 200, 200);
        assert_eq!(win.hit_test(500, 500), HitZone::Outside);
    }

    #[test]
    fn hit_test_resize_edge_right() {
        let win = WindowState::new(10, 10, 200, 200);
        // Just outside right edge.
        assert_eq!(
            win.hit_test(211, 100),
            HitZone::ResizeEdge(ResizeEdge::Right),
        );
    }

    #[test]
    fn client_rect_below_title_bar() {
        let win = WindowState::new(10, 10, 800, 600);
        let (cx, cy, cw, ch) = win.client_rect();
        assert_eq!(cx, 10);
        assert_eq!(cy, 10 + TITLE_BAR_HEIGHT);
        assert_eq!(cw, 800);
        assert_eq!(ch, 600 - TITLE_BAR_HEIGHT);
    }

    #[test]
    fn title_bar_constants_reasonable() {
        const { assert!(TITLE_BAR_HEIGHT > 0) };
        const { assert!(BORDER_WIDTH > 0) };
        const { assert!(MODE_BADGE_SIZE > 0) };
        const { assert!(CLOSE_BUTTON_WIDTH > 0) };
    }
}
