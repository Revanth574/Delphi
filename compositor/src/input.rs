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
//! | Super+1-4 | Switch focused window mode |
//! | Alt+F4 | Close focused window |
//! | Title bar drag | Move window |
//! | Edge drag | Resize window |

use smithay::backend::input::{
    ButtonState, InputEvent, KeyState, KeyboardKeyEvent,
    PointerButtonEvent, PointerMotionAbsoluteEvent,
};
use smithay::backend::winit::WinitInput;
use tracing::{debug, info};

use crate::state::{Delphi, GrabState};
use crate::window::{HitZone, ResizeEdge, UiMode};

/// Known compositor shortcut keycodes (evdev values).
///
/// Smithay wraps these in `xkbcommon::xkb::Keycode` which adds +8
/// offset. We compare against the raw value minus 8.
mod keycodes {
    /// Space bar (evdev).
    pub const KEY_SPACE: u32 = 57;
    /// Number keys 1-4 for mode switching (evdev).
    pub const KEY_1: u32 = 2;
    pub const KEY_2: u32 = 3;
    pub const KEY_3: u32 = 4;
    pub const KEY_4: u32 = 5;
    /// F4 key for Alt+F4 close (evdev).
    pub const KEY_F4: u32 = 62;
    /// Left Alt (evdev).
    pub const KEY_LEFTALT: u32 = 56;
    /// Right Alt (evdev).
    pub const KEY_RIGHTALT: u32 = 100;
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

/// Shared modifier state for the compositor.
///
/// Updated on every keyboard event to track Alt/Super state.
static MODIFIER_STATE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

const ALT_BIT: u8 = 1;

/// Check if Alt is currently held.
#[must_use]
fn is_alt_held() -> bool {
    MODIFIER_STATE.load(std::sync::atomic::Ordering::Relaxed) & ALT_BIT != 0
}

/// Update modifier tracking state.
fn update_modifiers(evdev_code: u32, pressed: bool) {
    if evdev_code == keycodes::KEY_LEFTALT || evdev_code == keycodes::KEY_RIGHTALT {
        if pressed {
            MODIFIER_STATE.fetch_or(ALT_BIT, std::sync::atomic::Ordering::Relaxed);
        } else {
            MODIFIER_STATE.fetch_and(!ALT_BIT, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Last known pointer position for hit testing on click.
///
/// Updated on every pointer motion event.
pub static POINTER_X: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(0);
pub static POINTER_Y: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(0);

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
    let evdev_code = raw.wrapping_sub(8);

    // Track modifier state.
    update_modifiers(evdev_code, pressed);

    // Alt+F4 -> close focused window.
    if evdev_code == keycodes::KEY_F4 && pressed && is_alt_held() {
        close_focused_window(state);
        return;
    }

    // Alt+Space -> command bar signal.
    if evdev_code == keycodes::KEY_SPACE && pressed && is_alt_held() {
        info!("compositor shortcut: Alt+Space (command bar)");
        return;
    }

    // Super+1/2/3/4 -> mode switch on focused window.
    if let Some(new_mode) = mode_from_keycode(evdev_code, pressed) {
        apply_mode_switch(state, new_mode);
        return;
    }

    debug!(raw_keycode = raw, pressed, "keyboard event forwarded");
}

/// Map evdev keycodes to UI modes (Super+1 through Super+4).
fn mode_from_keycode(evdev_code: u32, pressed: bool) -> Option<UiMode> {
    if !pressed {
        return None;
    }
    match evdev_code {
        c if c == keycodes::KEY_1 => Some(UiMode::Direct),
        c if c == keycodes::KEY_2 => Some(UiMode::Assisted),
        c if c == keycodes::KEY_3 => Some(UiMode::Autonomous),
        c if c == keycodes::KEY_4 => Some(UiMode::Focus),
        _ => None,
    }
}

/// Apply a mode switch to the focused window.
fn apply_mode_switch(state: &mut Delphi, new_mode: UiMode) {
    if let Some(ref focused) = state.focused_surface
        && let Some(win) = state.windows.get_mut(focused)
    {
        let old = win.mode;
        win.mode = new_mode;
        info!(old = ?old, new = ?new_mode, "mode switch on focused window");
    }
}

/// Close the currently focused window via xdg_toplevel.send_close().
fn close_focused_window(state: &mut Delphi) {
    if let Some(ref focused) = state.focused_surface
        && let Some(toplevel) = state.toplevels.get(focused)
    {
        info!("Alt+F4: closing focused window");
        toplevel.send_close();
    }
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

    // Store pointer position for button handler.
    POINTER_X.store(x as i32, std::sync::atomic::Ordering::Relaxed);
    POINTER_Y.store(y as i32, std::sync::atomic::Ordering::Relaxed);

    handle_grab_motion(state, x, y);
}

/// Apply grab-based motion (move or resize).
fn handle_grab_motion(state: &mut Delphi, x: f64, y: f64) {
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

    // Release grab on any button release.
    if !pressed && state.grab_state.is_some() {
        debug!("grab released");
        state.grab_state = None;
        return;
    }

    // BTN_LEFT = 272 in evdev.
    if button == 272 && pressed {
        handle_left_click(state);
    }
}

/// Process a left-click: hit-test, focus, drag, resize, or close.
fn handle_left_click(state: &mut Delphi) {
    let px = POINTER_X.load(std::sync::atomic::Ordering::Relaxed);
    let py = POINTER_Y.load(std::sync::atomic::Ordering::Relaxed);

    // Hit-test back-to-front to find topmost window.
    let hit = find_hit_window(state, px, py);

    let Some((surface, zone)) = hit else {
        // Clicked on desktop background.
        state.focus_surface(None);
        return;
    };

    // Focus the clicked window.
    state.focus_surface(Some(&surface.clone()));

    match zone {
        HitZone::TitleBar => {
            begin_move(state, &surface, f64::from(px), f64::from(py));
        }
        HitZone::CloseButton => {
            if let Some(toplevel) = state.toplevels.get(&surface) {
                info!("close button clicked");
                toplevel.send_close();
            }
        }
        HitZone::ResizeEdge(edge) => {
            begin_edge_resize(state, &surface, edge, f64::from(px), f64::from(py));
        }
        HitZone::ClientArea => {
            debug!("click in client area");
        }
        HitZone::Outside => {}
    }
}

/// Find which window and zone a point hits (topmost first).
fn find_hit_window(
    state: &Delphi,
    px: i32,
    py: i32,
) -> Option<(
    smithay::reexports::wayland_server::protocol::wl_surface::WlSurface,
    HitZone,
)> {
    for surface in state.stacking_order.iter().rev() {
        if let Some(win) = state.windows.get(surface) {
            let zone = win.hit_test(px, py);
            if zone != HitZone::Outside {
                return Some((surface.clone(), zone));
            }
        }
    }
    None
}

/// Begin a window move grab from a title bar click.
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

/// Begin a window resize grab from an edge click.
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

/// Begin a resize from a specific edge (adjusts axis constraints).
fn begin_edge_resize(
    state: &mut Delphi,
    surface: &smithay::reexports::wayland_server::protocol::wl_surface::WlSurface,
    _edge: ResizeEdge,
    x: f64,
    y: f64,
) {
    // DECISION: For simplicity, all edge resizes use bottom-right
    // behavior initially. Per-edge constraints (lock one axis) will
    // be added in a future iteration.
    begin_resize(state, surface, x, y);
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
        assert_eq!(keycodes::KEY_F4, 62);
    }

    #[test]
    fn mode_from_keycode_maps_correctly() {
        assert_eq!(mode_from_keycode(keycodes::KEY_1, true), Some(UiMode::Direct));
        assert_eq!(mode_from_keycode(keycodes::KEY_2, true), Some(UiMode::Assisted));
        assert_eq!(mode_from_keycode(keycodes::KEY_3, true), Some(UiMode::Autonomous));
        assert_eq!(mode_from_keycode(keycodes::KEY_4, true), Some(UiMode::Focus));
        assert_eq!(mode_from_keycode(keycodes::KEY_1, false), None);
        assert_eq!(mode_from_keycode(99, true), None);
    }

    #[test]
    fn modifier_state_tracks_alt() {
        // Reset state.
        MODIFIER_STATE.store(0, std::sync::atomic::Ordering::Relaxed);
        assert!(!is_alt_held());

        update_modifiers(keycodes::KEY_LEFTALT, true);
        assert!(is_alt_held());

        update_modifiers(keycodes::KEY_LEFTALT, false);
        assert!(!is_alt_held());
    }
}
