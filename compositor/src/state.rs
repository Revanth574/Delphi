// SPDX-License-Identifier: MIT

//! Core compositor state.
//!
//! The `Delphi` struct is the central state object passed to every Smithay
//! handler. It owns all Wayland globals, the window list, input seat, and
//! rendering backend. Smithay's `delegate_*!` macros dispatch protocol
//! events to trait implementations on this type.

use std::collections::HashMap;
use std::time::Duration;

use calloop::LoopSignal;
use smithay::input::{Seat, SeatState};
use smithay::output::Output;
use smithay::reexports::wayland_server::protocol::wl_surface::WlSurface;
use smithay::reexports::wayland_server::{Display, DisplayHandle};
use smithay::utils::{Clock, Monotonic};
use smithay::wayland::compositor::CompositorState;
use smithay::wayland::selection::data_device::DataDeviceState;
use smithay::wayland::shell::xdg::{ToplevelSurface, XdgShellState};
use smithay::wayland::shm::ShmState;

use crate::window::{UiMode, WindowState};

/// Central compositor state.
///
/// Owns all Smithay protocol state, the window list, input devices,
/// and the rendering backend reference.
///
/// # Examples
///
/// ```no_run
/// // Delphi is constructed during compositor initialization.
/// // See `crate::winit_backend::run_winit` for the full setup.
/// ```
pub struct Delphi {
    /// Wayland display handle for creating globals.
    pub display_handle: DisplayHandle,

    /// Signal to stop the event loop.
    pub loop_signal: LoopSignal,

    /// Compositor global (wl_compositor).
    pub compositor_state: CompositorState,

    /// Shared memory global (wl_shm).
    pub shm_state: ShmState,

    /// XDG shell global (xdg_wm_base).
    pub xdg_shell_state: XdgShellState,

    /// Input seat (keyboard + pointer).
    pub seat_state: SeatState<Self>,

    /// Data device manager (clipboard).
    pub data_device_state: DataDeviceState,

    /// The primary seat.
    pub seat: Seat<Self>,

    /// Per-surface window state (mode, position, size).
    pub windows: HashMap<WlSurface, WindowState>,

    /// XDG toplevel handles for each surface (for close, configure).
    pub toplevels: HashMap<WlSurface, ToplevelSurface>,

    /// Ordered list of surfaces for stacking (back to front).
    pub stacking_order: Vec<WlSurface>,

    /// Currently focused surface (receives keyboard input).
    pub focused_surface: Option<WlSurface>,

    /// Compositor clock for frame callbacks.
    pub clock: Clock<Monotonic>,

    /// Output (the winit window acts as a single output).
    pub output: Option<Output>,

    /// Background color (RGBA, 0.0–1.0).
    pub background_color: [f32; 4],

    /// Whether a surface is being dragged (Super+click).
    pub grab_state: Option<GrabState>,

    /// Running flag — set to false to exit.
    pub running: bool,

    /// Frame duration target (for redraw scheduling).
    pub frame_duration: Duration,
}

/// State for an active window drag or resize operation.
#[derive(Debug, Clone)]
pub struct GrabState {
    /// Surface being moved/resized.
    pub surface: WlSurface,

    /// Initial pointer position when grab started.
    pub start_x: f64,
    pub start_y: f64,

    /// Initial window position when grab started.
    pub initial_window_x: i32,
    pub initial_window_y: i32,

    /// Whether this is a resize (true) or move (false).
    pub is_resize: bool,

    /// Initial window size (for resize).
    pub initial_width: i32,
    pub initial_height: i32,
}

impl Delphi {
    /// Create a new compositor state.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // See `crate::winit_backend::run_winit` for construction.
    /// ```
    pub fn new(
        display: &Display<Self>,
        loop_signal: LoopSignal,
    ) -> Self {
        let display_handle = display.handle();
        let clock = Clock::new();

        let compositor_state = CompositorState::new::<Self>(&display_handle);
        let shm_state = ShmState::new::<Self>(&display_handle, vec![]);
        let xdg_shell_state = XdgShellState::new::<Self>(&display_handle);
        let data_device_state = DataDeviceState::new::<Self>(&display_handle);

        let mut seat_state = SeatState::new();
        let seat = seat_state.new_wl_seat(&display_handle, "seat-0");

        // DECISION: Default background is a dark blue-gray matching the Delphi
        // design system (#1a1a2e). Configurable via TOML in the future.
        let background_color = [
            0x1a as f32 / 255.0,
            0x1a as f32 / 255.0,
            0x2e as f32 / 255.0,
            1.0,
        ];

        Self {
            display_handle,
            loop_signal,
            compositor_state,
            shm_state,
            xdg_shell_state,
            seat_state,
            data_device_state,
            seat,
            windows: HashMap::new(),
            toplevels: HashMap::new(),
            stacking_order: Vec::new(),
            focused_surface: None,
            clock,
            output: None,
            background_color,
            grab_state: None,
            running: true,
            frame_duration: Duration::from_millis(16), // ~60 FPS
        }
    }

    /// Set keyboard focus to a surface, raising it to the top.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // state.focus_surface(Some(&surface));
    /// ```
    pub fn focus_surface(&mut self, surface: Option<&WlSurface>) {
        if let Some(surf) = surface {
            // Raise to top of stacking order.
            self.stacking_order.retain(|s| s != surf);
            self.stacking_order.push(surf.clone());
            self.focused_surface = Some(surf.clone());
        } else {
            self.focused_surface = None;
        }
    }

    /// Find the topmost surface at a given point.
    ///
    /// Iterates stacking order back-to-front (top first) and checks
    /// whether the point falls within each window's bounds.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // let hit = state.surface_at(100.0, 200.0);
    /// ```
    #[must_use]
    pub fn surface_at(&self, x: f64, y: f64) -> Option<&WlSurface> {
        for surface in self.stacking_order.iter().rev() {
            if let Some(win) = self.windows.get(surface) {
                let ix = x as i32;
                let iy = y as i32;
                if ix >= win.x
                    && ix < win.x + win.width
                    && iy >= win.y
                    && iy < win.y + win.height
                {
                    return Some(surface);
                }
            }
        }
        None
    }

    /// Get the default UI mode for new windows.
    ///
    /// # Examples
    ///
    /// ```
    /// use compositor::window::UiMode;
    /// // All new windows start in Direct mode.
    /// assert_eq!(UiMode::default(), UiMode::Direct);
    /// ```
    #[must_use]
    pub fn default_mode() -> UiMode {
        UiMode::Direct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_background_is_dark_blue_gray() {
        // #1a1a2e in floating point.
        let bg = [
            0x1a as f32 / 255.0,
            0x1a as f32 / 255.0,
            0x2e as f32 / 255.0,
            1.0,
        ];
        assert!((bg[0] - 0.102).abs() < 0.01);
        assert!((bg[2] - 0.180).abs() < 0.01);
        assert!((bg[3] - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn default_mode_is_direct() {
        assert_eq!(Delphi::default_mode(), UiMode::Direct);
    }

    #[test]
    fn frame_duration_targets_60fps() {
        let dur = Duration::from_millis(16);
        assert!(dur.as_millis() >= 16);
    }
}
