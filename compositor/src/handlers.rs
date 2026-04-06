// SPDX-License-Identifier: MIT

//! Smithay protocol handler implementations.
//!
//! Each handler trait corresponds to a Wayland protocol global
//! (compositor, shm, xdg_shell, seat, data_device, output). The
//! `delegate_*!` macros at the bottom wire protocol dispatching
//! to these impls.

use smithay::backend::renderer::utils::on_commit_buffer_handler;
use smithay::delegate_compositor;
use smithay::delegate_data_device;
use smithay::delegate_output;
use smithay::delegate_seat;
use smithay::delegate_shm;
use smithay::delegate_xdg_shell;
use smithay::input::pointer::CursorImageStatus;
use smithay::input::{Seat, SeatHandler};
use smithay::output::Output;
use smithay::reexports::wayland_server::protocol::wl_buffer::WlBuffer;
use smithay::reexports::wayland_server::protocol::wl_output::WlOutput;
use smithay::reexports::wayland_server::protocol::wl_seat::WlSeat;
use smithay::reexports::wayland_server::protocol::wl_surface::WlSurface;
use smithay::utils::Serial;
use smithay::wayland::buffer::BufferHandler;
use smithay::wayland::compositor::{CompositorHandler, CompositorState};
use smithay::wayland::output::OutputHandler;
use smithay::wayland::selection::data_device::{
    ClientDndGrabHandler, DataDeviceHandler, DataDeviceState, ServerDndGrabHandler,
};
use smithay::wayland::selection::SelectionHandler;
use smithay::wayland::shell::xdg::{
    PopupSurface, PositionerState, ToplevelSurface, XdgShellHandler, XdgShellState,
};
use smithay::wayland::shm::{ShmHandler, ShmState};
use tracing::{debug, info};

use crate::state::Delphi;
use crate::window::WindowState;

// ─── Compositor (wl_compositor) ───────────────────────────────────

impl CompositorHandler for Delphi {
    fn compositor_state(&mut self) -> &mut CompositorState {
        &mut self.compositor_state
    }

    fn commit(&mut self, surface: &WlSurface) {
        on_commit_buffer_handler::<Self>(surface);
    }

    fn client_compositor_state<'a>(
        &self,
        client: &'a smithay::reexports::wayland_server::Client,
    ) -> &'a smithay::wayland::compositor::CompositorClientState {
        &client.get_data::<crate::ClientState>().unwrap().compositor
    }
}

delegate_compositor!(Delphi);

// ─── Shared memory (wl_shm) ──────────────────────────────────────

impl BufferHandler for Delphi {
    fn buffer_destroyed(&mut self, _buffer: &WlBuffer) {}
}

impl ShmHandler for Delphi {
    fn shm_state(&self) -> &ShmState {
        &self.shm_state
    }
}

delegate_shm!(Delphi);

// ─── XDG Shell (xdg_wm_base) ─────────────────────────────────────

impl XdgShellHandler for Delphi {
    fn xdg_shell_state(&mut self) -> &mut XdgShellState {
        &mut self.xdg_shell_state
    }

    fn new_toplevel(&mut self, surface: ToplevelSurface) {
        // Place new windows at a cascading offset.
        let offset = (self.windows.len() as i32) * 30;
        let x = 50 + offset;
        let y = 50 + offset;
        let width = 800;
        let height = 600;

        let wl_surface = surface.wl_surface().clone();
        let win = WindowState::new(x, y, width, height);

        info!(
            x,
            y,
            width,
            height,
            mode = ?win.mode,
            "new toplevel window"
        );

        self.windows.insert(wl_surface.clone(), win);
        self.stacking_order.push(wl_surface.clone());
        self.focus_surface(Some(&wl_surface));

        // Send the initial configure so the client can start rendering.
        surface.send_configure();
    }

    fn new_popup(&mut self, surface: PopupSurface, _positioner: PositionerState) {
        let _ = surface.send_configure();
        debug!("new popup surface");
    }

    fn grab(&mut self, _surface: PopupSurface, _seat: WlSeat, _serial: Serial) {}

    fn reposition_request(
        &mut self,
        _surface: PopupSurface,
        _positioner: PositionerState,
        _token: u32,
    ) {
    }

    fn toplevel_destroyed(&mut self, surface: ToplevelSurface) {
        let wl_surface = surface.wl_surface();
        self.windows.remove(wl_surface);
        self.stacking_order.retain(|s| s != wl_surface);

        if self.focused_surface.as_ref() == Some(wl_surface) {
            let next = self.stacking_order.last().cloned();
            self.focused_surface = next;
        }

        info!(
            "toplevel destroyed, {} windows remaining",
            self.windows.len()
        );
    }
}

delegate_xdg_shell!(Delphi);

// ─── Seat (wl_seat) ──────────────────────────────────────────────

impl SeatHandler for Delphi {
    type KeyboardFocus = WlSurface;
    type PointerFocus = WlSurface;
    type TouchFocus = WlSurface;

    fn seat_state(&mut self) -> &mut smithay::input::SeatState<Self> {
        &mut self.seat_state
    }

    fn focus_changed(&mut self, _seat: &Seat<Self>, focused: Option<&WlSurface>) {
        debug!(?focused, "keyboard focus changed");
    }

    fn cursor_image(&mut self, _seat: &Seat<Self>, _image: CursorImageStatus) {}
}

delegate_seat!(Delphi);

// ─── Data device (wl_data_device_manager) ─────────────────────────

impl SelectionHandler for Delphi {
    type SelectionUserData = ();
}

impl DataDeviceHandler for Delphi {
    fn data_device_state(&self) -> &DataDeviceState {
        &self.data_device_state
    }
}

impl ClientDndGrabHandler for Delphi {}
impl ServerDndGrabHandler for Delphi {}

delegate_data_device!(Delphi);

// ─── Output (wl_output) ──────────────────────────────────────────

impl OutputHandler for Delphi {
    fn output_bound(&mut self, _output: Output, _wl_output: WlOutput) {}
}

delegate_output!(Delphi);
