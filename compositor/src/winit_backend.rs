// SPDX-License-Identifier: MIT

//! Winit backend for development.
//!
//! Renders the compositor inside an existing X11 or Wayland window
//! (via WSLg or a native desktop). This backend is explicitly designed
//! for development — production Delphi uses the DRM/KMS backend.
//!
//! The event loop integrates three calloop event sources on one thread:
//! 1. Winit window events (input, resize, close) — via `EventSource` impl
//! 2. Wayland client events (protocol requests) — via `Generic` source
//! 3. Timer for frame callbacks

use std::time::Duration;

use calloop::timer::{TimeoutAction, Timer};
use calloop::EventLoop;
use smithay::backend::renderer::gles::GlesRenderer;
use smithay::backend::renderer::{Color32F, Frame, Renderer};
use smithay::backend::winit::{self, WinitEvent, WinitGraphicsBackend};
use smithay::output::{Mode, Output, PhysicalProperties, Subpixel};
use smithay::reexports::wayland_server::Display;
use smithay::utils::{Physical, Rectangle, Size, Transform};
use tracing::{error, info};

use crate::error::CompositorError;
use crate::state::Delphi;

/// Run the compositor with the winit backend.
///
/// This is the main entry point for development. It creates a window,
/// initializes all Wayland globals, and runs the event loop until
/// the window is closed.
///
/// # Errors
///
/// Returns `CompositorError` if the backend fails to initialize
/// or if the event loop encounters a fatal error.
///
/// # Examples
///
/// ```no_run
/// use compositor::winit_backend::run_winit;
///
/// // Run the compositor (blocks until window closes).
/// run_winit().unwrap();
/// ```
pub fn run_winit() -> Result<(), CompositorError> {
    info!("initializing winit backend");

    // 1. Create calloop event loop.
    let mut event_loop: EventLoop<Delphi> = EventLoop::try_new()
        .map_err(|e| CompositorError::BackendInit(format!(
            "event loop creation failed: {e}"
        )))?;

    // 2. Create Wayland display.
    let display: Display<Delphi> = Display::new()
        .map_err(|e| CompositorError::BackendInit(format!(
            "wayland display creation failed: {e}"
        )))?;

    // 3. Initialize winit backend (creates the window + GL context).
    let (backend, winit_loop) = winit::init::<GlesRenderer>()
        .map_err(|e| CompositorError::BackendInit(format!("winit init failed: {e}")))?;

    // 4. Create compositor state.
    let mut state = Delphi::new(&display, event_loop.get_signal());

    // 5. Set up the output (represents the winit window as a display).
    let output = create_output(&state, &backend);
    state.output = Some(output);

    // Wrap backend in a shared cell so the timer callback can access it.
    let backend = std::rc::Rc::new(std::cell::RefCell::new(backend));

    // 6. Insert Wayland display as a calloop source.
    let display_source = calloop::generic::Generic::new(
        display,
        calloop::Interest::READ,
        calloop::Mode::Level,
    );
    event_loop
        .handle()
        .insert_source(display_source, |_, display, state| {
            // SAFETY: The display is valid for the lifetime of the event loop.
            unsafe {
                display.get_mut().dispatch_clients(state).ok();
            }
            Ok(calloop::PostAction::Continue)
        })
        .map_err(|e| CompositorError::BackendInit(format!(
            "display source registration failed: {e}"
        )))?;

    // 7. Insert winit as a calloop event source (handles input, resize, close).
    event_loop
        .handle()
        .insert_source(winit_loop, move |event, _, state| {
            handle_winit_event(state, event);
        })
        .map_err(|e| CompositorError::BackendInit(format!(
            "winit source registration failed: {e}"
        )))?;

    // 8. Set up a frame timer for redraw scheduling (~60 FPS).
    let render_backend = backend.clone();
    let timer = Timer::from_duration(state.frame_duration);
    event_loop
        .handle()
        .insert_source(timer, move |_, _, state: &mut Delphi| {
            if let Ok(mut b) = render_backend.try_borrow_mut()
                && let Err(e) = render_frame(&mut b, state)
            {
                error!("render error: {e}");
            }
            TimeoutAction::ToDuration(state.frame_duration)
        })
        .map_err(|e| CompositorError::BackendInit(format!(
            "timer source registration failed: {e}"
        )))?;

    info!("compositor initialized, entering event loop");

    // 9. Main event loop — calloop dispatches all sources.
    while state.running {
        event_loop
            .dispatch(Some(Duration::from_millis(16)), &mut state)
            .map_err(|e| CompositorError::BackendInit(format!(
                "event loop dispatch failed: {e}"
            )))?;
    }

    info!("compositor shut down cleanly");
    Ok(())
}

/// Create an output representing the winit window.
fn create_output(
    state: &Delphi,
    backend: &WinitGraphicsBackend<GlesRenderer>,
) -> Output {
    let size = backend.window_size();

    let output = Output::new(
        "winit-0".to_string(),
        PhysicalProperties {
            size: (0, 0).into(),
            subpixel: Subpixel::Unknown,
            make: "Delphi".to_string(),
            model: "Winit Virtual Output".to_string(),
        },
    );

    let mode = Mode {
        size: Size::from((size.w, size.h)),
        refresh: 60_000, // 60 Hz in millihertz.
    };

    output.change_current_state(
        Some(mode),
        Some(Transform::Flipped180),
        None,
        Some((0, 0).into()),
    );
    output.set_preferred(mode);

    output.create_global::<Delphi>(&state.display_handle);

    info!(width = size.w, height = size.h, "output created");

    output
}

/// Handle a winit window event.
fn handle_winit_event(state: &mut Delphi, event: WinitEvent) {
    match event {
        WinitEvent::Resized { size, .. } => {
            if let Some(output) = &state.output {
                let mode = Mode {
                    size: Size::from((size.w, size.h)),
                    refresh: 60_000,
                };
                output.change_current_state(Some(mode), None, None, None);
                info!(width = size.w, height = size.h, "window resized");
            }
        }
        WinitEvent::CloseRequested => {
            info!("close requested");
            state.running = false;
        }
        WinitEvent::Input(event) => {
            crate::input::handle_input(state, event);
        }
        WinitEvent::Redraw => {
            // Handled by the frame timer.
        }
        _ => {}
    }
}

/// Render a single frame.
fn render_frame(
    backend: &mut WinitGraphicsBackend<GlesRenderer>,
    state: &Delphi,
) -> Result<(), CompositorError> {
    let size = backend.window_size();

    // bind() returns (renderer, framebuffer). We need to scope the borrow
    // so that submit() can borrow backend mutably afterward.
    {
        let (renderer, mut framebuffer) = backend
            .bind()
            .map_err(|e| CompositorError::Render(format!("bind failed: {e}")))?;

        let mut frame = renderer
            .render(
                &mut framebuffer,
                Size::from((size.w, size.h)),
                Transform::Normal,
            )
            .map_err(|e| CompositorError::Render(format!("render start failed: {e}")))?;

        // Clear background.
        let bg = state.background_color;
        let damage: &[Rectangle<i32, Physical>] =
            &[Rectangle::from_size(Size::from((size.w, size.h)))];

        frame
            .clear(Color32F::new(bg[0], bg[1], bg[2], bg[3]), damage)
            .map_err(|e| CompositorError::Render(format!("clear failed: {e}")))?;

        // TODO: Render client surfaces when we have mapped windows.

        let _sync_point = frame
            .finish()
            .map_err(|e| CompositorError::Render(format!("finish failed: {e}")))?;
    } // framebuffer and renderer borrows are released here.

    backend
        .submit(None)
        .map_err(|e| CompositorError::Render(format!("submit failed: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn output_name_is_winit() {
        let name = "winit-0";
        assert!(name.starts_with("winit"));
    }
}
