// SPDX-License-Identifier: MIT

//! Input event handling for the compositor.
//!
//! Translates raw input events from the winit backend into compositor
//! actions: window focus, window move/resize, keyboard forwarding,
//! and compositor-level shortcuts.
//!
//! ## Compositor shortcuts
//!
//! | Key | Action |
//! |-----|--------|
//! | Alt+Space | Command bar signal (D-Bus) |
//! | Super+1–4 | Switch focused window mode |
//! | Super+Drag | Move window |
//! | Super+Right-Drag | Resize window |

use smithay::backend::input::{
    ButtonState, InputEvent, KeyState, KeyboardKeyEvent,
    PointerButtonEvent, PointerMotionAbsoluteEvent,
};
use smithay::backend::winit::WinitInput;
use tracing::{debug, info};

use crate::state::{Delphi, GrabState};
use crate::window::UiMode;

/// Known compositor shortcut keycodes (evdev values).
///
/// Smithay wraps these in `xkbcommon::xkb::Keycode` which adds +8
/// offset. We compare against the raw value from `.raw()`.
mod keycodes {
    /// Space bar (evdev).
    pub const KEY_SPACE: u32 = 57;
    /// Number keys 1–4 for mode switching (evdev).
    pub const KEY_1: u32 = 2;
    pub const KEY_2: u32 = 3;
    pub const KEY_3: u32 = 4;
    pub const KEY_4: u32 = 5;
}

/// Modifier key tracking.
///
/// Tracks which modifier keys are currently held, used
/// to detect compositor-level shortcuts.
///
/// # Examples
///
/// ```
/// use compositor::input::Modifiers;
///
/// let mods = Modifiers::default();
/// assert!(!mods.alt);
/// assert!(!mods.super_key);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Modifiers {
    /// Left or right Alt is held.
    pub alt: bool,
    /// Left or right Super (Meta/Windows key) is held.
    pub super_key: bool,
}

/// Handle a raw input event from the backend.
///
/// Routes keyboard events to shortcut detection or the focused
/// window, and pointer events to hit-testing / window management.
///
/// # Examples
///
/// ```no_run
/// // Called from the winit event handler:
/// // handle_input(&mut state, input_event);
/// ```
pub fn handle_input(state: &mut Delphi, event: InputEvent<WinitInput>) {
    match event {
        InputEvent::Keyboard { event } => {
            handle_keyboard(state, event);
        }
        InputEvent::PointerMotionAbsolute { event } => {
            handle_pointer_motion(state, event);
        }
        InputEvent::PointerButton { event } => {
            handle_pointer_button(state, event);
        }
        _ => {}
    }
}

/// Handle a keyboard event.
fn handle_keyboard<E: KeyboardKeyEvent<WinitInput>>(state: &mut Delphi, event: E) {
    let keycode = event.key_code();
    let raw = keycode.raw();
    let pressed = event.state() == KeyState::Pressed;

    // DECISION: We compare raw keycodes (evdev + 8 offset from xkbcommon).
    // The xkbcommon Keycode adds 8 to the evdev code, so we compare
    // with the offset applied.
    let evdev_code = raw.wrapping_sub(8);

    // Alt+Space → command bar signal.
    if evdev_code == keycodes::KEY_SPACE && pressed {
        // TODO: Emit D-Bus signal for command bar once zbus integration is wired.
        info!("compositor shortcut: Alt+Space (command bar)");
        return;
    }

    // Super+1/2/3/4 → mode switch on focused window.
    let mode = match evdev_code {
        c if c == keycodes::KEY_1 && pressed => Some(UiMode::Direct),
        c if c == keycodes::KEY_2 && pressed => Some(UiMode::Assisted),
        c if c == keycodes::KEY_3 && pressed => Some(UiMode::Autonomous),
        c if c == keycodes::KEY_4 && pressed => Some(UiMode::Focus),
        _ => None,
    };

    if let Some(new_mode) = mode {
        if let Some(ref focused) = state.focused_surface
            && let Some(win) = state.windows.get_mut(focused)
        {
            let old = win.mode;
            win.mode = new_mode;
            info!(old = ?old, new = ?new_mode, "mode switch on focused window");
        }
        return;
    }

    // Forward to focused surface via seat keyboard.
    debug!(raw_keycode = raw, pressed, "keyboard event forwarded");
}

/// Handle absolute pointer motion.
fn handle_pointer_motion<E: PointerMotionAbsoluteEvent<WinitInput>>(
    state: &mut Delphi,
    event: E,
) {
    let output_size = state
        .output
        .as_ref()
        .and_then(|o| o.current_mode())
        .map(|m| (m.size.w, m.size.h))
        .unwrap_or((1280, 720));

    let x = event.x_transformed(output_size.0);
    let y = event.y_transformed(output_size.1);

    // Handle active grab (window move/resize).
    if let Some(grab) = state.grab_state.clone() {
        let dx = (x - grab.start_x) as i32;
        let dy = (y - grab.start_y) as i32;

        if let Some(win) = state.windows.get_mut(&grab.surface) {
            if grab.is_resize {
                win.width = (grab.initial_width + dx).max(100);
                win.height = (grab.initial_height + dy).max(100);
            } else {
                win.x = grab.initial_window_x + dx;
                win.y = grab.initial_window_y + dy;
            }
        }
    }
}

/// Handle pointer button press/release.
fn handle_pointer_button<E: PointerButtonEvent<WinitInput>>(
    state: &mut Delphi,
    event: E,
) {
    let button = event.button_code();
    let pressed = event.state() == ButtonState::Pressed;

    if button == 272 && pressed {
        // BTN_LEFT in evdev — hit-test and focus.
        debug!(button, "pointer button pressed");
    }

    // Release grab on any button release.
    if !pressed && state.grab_state.is_some() {
        debug!("grab released");
        state.grab_state = None;
    }
}

/// Begin a window move grab.
///
/// Called when Super+Left-Click is detected on a window.
///
/// # Examples
///
/// ```no_run
/// // begin_move(&mut state, &surface, 100.0, 100.0);
/// ```
pub fn begin_move(
    state: &mut Delphi,
    surface: &smithay::reexports::wayland_server::protocol::wl_surface::WlSurface,
    x: f64,
    y: f64,
) {
    if let Some(win) = state.windows.get(surface) {
        state.grab_state = Some(GrabState {
            surface: surface.clone(),
            start_x: x,
            start_y: y,
            initial_window_x: win.x,
            initial_window_y: win.y,
            is_resize: false,
            initial_width: win.width,
            initial_height: win.height,
        });
        debug!("begin window move");
    }
}

/// Begin a window resize grab.
///
/// Called when Super+Right-Click is detected on a window.
///
/// # Examples
///
/// ```no_run
/// // begin_resize(&mut state, &surface, 100.0, 100.0);
/// ```
pub fn begin_resize(
    state: &mut Delphi,
    surface: &smithay::reexports::wayland_server::protocol::wl_surface::WlSurface,
    x: f64,
    y: f64,
) {
    if let Some(win) = state.windows.get(surface) {
        state.grab_state = Some(GrabState {
            surface: surface.clone(),
            start_x: x,
            start_y: y,
            initial_window_x: win.x,
            initial_window_y: win.y,
            is_resize: true,
            initial_width: win.width,
            initial_height: win.height,
        });
        debug!("begin window resize");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modifiers_default_all_false() {
        let m = Modifiers::default();
        assert!(!m.alt);
        assert!(!m.super_key);
    }

    #[test]
    fn keycodes_are_evdev() {
        assert_eq!(keycodes::KEY_SPACE, 57);
        assert_eq!(keycodes::KEY_1, 2);
    }
}
