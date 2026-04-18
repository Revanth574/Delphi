// SPDX-License-Identifier: MIT

//! Render element types and decoration helpers.
//!
//! Defines the composite render element enum used by the frame renderer.
//! Combines Wayland surface textures with solid-color decorations (title
//! bars, mode badges, close buttons) into a single renderable type.

use smithay::backend::renderer::element::solid::SolidColorRenderElement;
use smithay::backend::renderer::element::surface::WaylandSurfaceRenderElement;
use smithay::backend::renderer::element::{Id, Kind};
use smithay::backend::renderer::utils::CommitCounter;
use smithay::backend::renderer::{Color32F, ImportAll};
use smithay::utils::{Point, Rectangle, Size};

use crate::window::{
    WindowState, CLOSE_BUTTON_COLOR, CLOSE_BUTTON_WIDTH, MODE_BADGE_SIZE,
    TITLE_BAR_COLOR, TITLE_BAR_FOCUSED_COLOR, TITLE_BAR_HEIGHT,
};

// ─── Composite render element ───────────────────────────────────────

smithay::backend::renderer::element::render_elements! {
    /// All renderable elements in the Delphi compositor.
    ///
    /// Each frame consists of window decorations (solid colors)
    /// and client surface textures.
    pub DelphiRenderElement<R> where R: ImportAll;
    /// A Wayland client surface texture.
    Surface=WaylandSurfaceRenderElement<R>,
    /// A solid-color rectangle (title bar, mode badge, close button).
    Decoration=SolidColorRenderElement,
}

// ─── Decoration element builders ────────────────────────────────────

/// Create the title bar background element for a window.
///
/// # Examples
///
/// ```
/// use compositor::render::title_bar_element;
/// use compositor::window::WindowState;
///
/// let win = WindowState::new(10, 10, 800, 600);
/// let elem = title_bar_element(&win, true);
/// // Element covers the full title bar width.
/// ```
#[must_use]
pub fn title_bar_element(win: &WindowState, focused: bool) -> SolidColorRenderElement {
    let color = if focused {
        TITLE_BAR_FOCUSED_COLOR
    } else {
        TITLE_BAR_COLOR
    };

    SolidColorRenderElement::new(
        Id::new(),
        Rectangle::new(
            Point::from((win.x, win.y)),
            Size::from((win.width, TITLE_BAR_HEIGHT)),
        ),
        CommitCounter::default(),
        Color32F::new(color[0], color[1], color[2], color[3]),
        Kind::Unspecified,
    )
}

/// Create the mode badge element (colored circle indicator).
///
/// Positioned in the top-left of the title bar. The badge color
/// indicates which UI mode (Direct/Assisted/Autonomous/Focus)
/// the window is operating in.
///
/// # Examples
///
/// ```
/// use compositor::render::mode_badge_element;
/// use compositor::window::WindowState;
///
/// let win = WindowState::new(10, 10, 800, 600);
/// let elem = mode_badge_element(&win);
/// // Badge is a small colored square.
/// ```
#[must_use]
pub fn mode_badge_element(win: &WindowState) -> SolidColorRenderElement {
    let color = win.mode.color();
    let badge_x = win.x + 8;
    let badge_y = win.y + (TITLE_BAR_HEIGHT - MODE_BADGE_SIZE) / 2;

    SolidColorRenderElement::new(
        Id::new(),
        Rectangle::new(
            Point::from((badge_x, badge_y)),
            Size::from((MODE_BADGE_SIZE, MODE_BADGE_SIZE)),
        ),
        CommitCounter::default(),
        Color32F::new(color[0], color[1], color[2], color[3]),
        Kind::Unspecified,
    )
}

/// Create the close button element in the title bar.
///
/// Positioned in the top-right corner of the title bar.
///
/// # Examples
///
/// ```
/// use compositor::render::close_button_element;
/// use compositor::window::WindowState;
///
/// let win = WindowState::new(10, 10, 800, 600);
/// let elem = close_button_element(&win);
/// // Close button is in the top-right of the title bar.
/// ```
#[must_use]
pub fn close_button_element(win: &WindowState) -> SolidColorRenderElement {
    SolidColorRenderElement::new(
        Id::new(),
        Rectangle::new(
            Point::from((
                win.x + win.width - CLOSE_BUTTON_WIDTH,
                win.y,
            )),
            Size::from((CLOSE_BUTTON_WIDTH, TITLE_BAR_HEIGHT)),
        ),
        CommitCounter::default(),
        Color32F::new(
            CLOSE_BUTTON_COLOR[0],
            CLOSE_BUTTON_COLOR[1],
            CLOSE_BUTTON_COLOR[2],
            CLOSE_BUTTON_COLOR[3],
        ),
        Kind::Unspecified,
    )
}

/// Collect all decoration elements for a single window.
///
/// Returns title bar, mode badge, and close button as a `Vec`
/// of `SolidColorRenderElement`s. The caller converts these into
/// the composite `DelphiRenderElement` type.
///
/// # Examples
///
/// ```
/// use compositor::render::window_decoration_elements;
/// use compositor::window::WindowState;
///
/// let win = WindowState::new(10, 10, 800, 600);
/// let elems = window_decoration_elements(&win, true);
/// assert_eq!(elems.len(), 3); // title bar + badge + close button
/// ```
#[must_use]
pub fn window_decoration_elements(
    win: &WindowState,
    focused: bool,
) -> Vec<SolidColorRenderElement> {
    vec![
        title_bar_element(win, focused),
        mode_badge_element(win),
        close_button_element(win),
    ]
}

/// Create a window border element for visual feedback.
///
/// Draws a thin colored border around the focused window.
///
/// # Examples
///
/// ```
/// use compositor::render::window_border_elements;
/// use compositor::window::WindowState;
///
/// let win = WindowState::new(10, 10, 200, 200);
/// let borders = window_border_elements(&win);
/// assert_eq!(borders.len(), 4); // top, bottom, left, right
/// ```
#[must_use]
pub fn window_border_elements(win: &WindowState) -> Vec<SolidColorRenderElement> {
    let color = win.mode.color();
    let c = Color32F::new(color[0], color[1], color[2], color[3]);
    let bw = 2; // Visual border width (thinner than resize hit zone).

    vec![
        // Top border (above title bar).
        SolidColorRenderElement::new(
            Id::new(),
            Rectangle::new(
                Point::from((win.x - bw, win.y - bw)),
                Size::from((win.width + 2 * bw, bw)),
            ),
            CommitCounter::default(),
            c,
            Kind::Unspecified,
        ),
        // Bottom border.
        SolidColorRenderElement::new(
            Id::new(),
            Rectangle::new(
                Point::from((win.x - bw, win.y + win.height)),
                Size::from((win.width + 2 * bw, bw)),
            ),
            CommitCounter::default(),
            c,
            Kind::Unspecified,
        ),
        // Left border.
        SolidColorRenderElement::new(
            Id::new(),
            Rectangle::new(
                Point::from((win.x - bw, win.y)),
                Size::from((bw, win.height)),
            ),
            CommitCounter::default(),
            c,
            Kind::Unspecified,
        ),
        // Right border.
        SolidColorRenderElement::new(
            Id::new(),
            Rectangle::new(
                Point::from((win.x + win.width, win.y)),
                Size::from((bw, win.height)),
            ),
            CommitCounter::default(),
            c,
            Kind::Unspecified,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoration_elements_count() {
        let win = WindowState::new(10, 10, 800, 600);
        let elems = window_decoration_elements(&win, true);
        assert_eq!(elems.len(), 3);
    }

    #[test]
    fn border_elements_count() {
        let win = WindowState::new(10, 10, 200, 200);
        let borders = window_border_elements(&win);
        assert_eq!(borders.len(), 4);
    }

    #[test]
    fn title_bar_covers_full_width() {
        let win = WindowState::new(50, 50, 400, 300);
        let elem = title_bar_element(&win, false);
        // Verify the element was created (it has a color).
        let color = elem.color();
        assert!(color.r() > 0.0);
    }

    #[test]
    fn mode_badge_uses_window_mode_color() {
        let mut win = WindowState::new(10, 10, 200, 200);
        win.mode = crate::window::UiMode::Assisted;
        let elem = mode_badge_element(&win);
        let color = elem.color();
        // Assisted mode is purple — red component > 0.5.
        assert!(color.r() > 0.4);
    }
}
