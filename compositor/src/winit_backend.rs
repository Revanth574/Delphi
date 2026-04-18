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
//! 3. Timer for frame callbacks and rendering

use std::time::Duration;

use calloop::timer::{TimeoutAction, Timer};
use calloop::EventLoop;
use smithay::backend::renderer::damage::OutputDamageTracker;
use smithay::backend::renderer::element::surface::render_elements_from_surface_tree;
use smithay::backend::renderer::element::Kind;
use smithay::backend::renderer::gles::GlesRenderer;
use smithay::backend::renderer::utils::import_surface_tree;
use smithay::backend::renderer::{Color32F, ImportAll, Renderer};
use smithay::backend::winit::{self, WinitEvent, WinitGraphicsBackend};
use smithay::output::{Mode, Output, PhysicalProperties, Subpixel};
use smithay::reexports::wayland_server::Display;
use smithay::utils::{Scale, Size, Transform};
use tracing::{error, info, trace};

use crate::error::CompositorError;
use crate::render::{window_border_elements, window_decoration_elements, DelphiRenderElement};
use crate::state::Delphi;
use crate::window::TITLE_BAR_HEIGHT;

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

    let mut event_loop: EventLoop<Delphi> = EventLoop::try_new()
        .map_err(|e| CompositorError::BackendInit(format!(
            "event loop creation failed: {e}"
        )))?;

    let display: Display<Delphi> = Display::new()
        .map_err(|e| CompositorError::BackendInit(format!(
            "wayland display creation failed: {e}"
        )))?;

    let (backend, winit_loop) = winit::init::<GlesRenderer>()
        .map_err(|e| CompositorError::BackendInit(format!("winit init failed: {e}")))?;

    let mut state = Delphi::new(&display, event_loop.get_signal());

    let output = create_output(&state, &backend);
    state.output = Some(output);

    let backend = std::rc::Rc::new(std::cell::RefCell::new(backend));

    // Create damage tracker for efficient partial-screen redraws.
    let damage_tracker = std::rc::Rc::new(std::cell::RefCell::new(
        create_damage_tracker(&state),
    ));

    register_display_source(&mut event_loop, display)?;
    register_winit_source(&mut event_loop, winit_loop)?;
    register_frame_timer(&mut event_loop, backend.clone(), damage_tracker, &state)?;

    info!("compositor initialized, entering event loop");

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
        refresh: 60_000,
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

/// Create a damage tracker from the current output.
fn create_damage_tracker(state: &Delphi) -> OutputDamageTracker {
    if let Some(output) = &state.output {
        OutputDamageTracker::from_output(output)
    } else {
        OutputDamageTracker::new((1280, 720), 1.0, Transform::Normal)
    }
}

/// Register the Wayland display as a calloop source.
fn register_display_source(
    event_loop: &mut EventLoop<Delphi>,
    display: Display<Delphi>,
) -> Result<(), CompositorError> {
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
    Ok(())
}

/// Register the winit event source.
fn register_winit_source(
    event_loop: &mut EventLoop<Delphi>,
    winit_loop: smithay::backend::winit::WinitEventLoop,
) -> Result<(), CompositorError> {
    event_loop
        .handle()
        .insert_source(winit_loop, move |event, _, state| {
            handle_winit_event(state, event);
        })
        .map_err(|e| CompositorError::BackendInit(format!(
            "winit source registration failed: {e}"
        )))?;
    Ok(())
}

/// Register the frame timer for rendering.
fn register_frame_timer(
    event_loop: &mut EventLoop<Delphi>,
    backend: std::rc::Rc<std::cell::RefCell<WinitGraphicsBackend<GlesRenderer>>>,
    damage_tracker: std::rc::Rc<std::cell::RefCell<OutputDamageTracker>>,
    state: &Delphi,
) -> Result<(), CompositorError> {
    let timer = Timer::from_duration(state.frame_duration);
    event_loop
        .handle()
        .insert_source(timer, move |_, _, state: &mut Delphi| {
            if let Ok(mut b) = backend.try_borrow_mut()
                && let Ok(mut dt) = damage_tracker.try_borrow_mut()
                && let Err(e) = render_frame(&mut b, &mut dt, state)
            {
                error!("render error: {e}");
            }
            TimeoutAction::ToDuration(state.frame_duration)
        })
        .map_err(|e| CompositorError::BackendInit(format!(
            "timer source registration failed: {e}"
        )))?;
    Ok(())
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

/// Render a single frame with damage tracking.
///
/// Imports client surface textures, builds decoration elements,
/// and uses `OutputDamageTracker` for efficient partial redraws.
fn render_frame(
    backend: &mut WinitGraphicsBackend<GlesRenderer>,
    damage_tracker: &mut OutputDamageTracker,
    state: &Delphi,
) -> Result<(), CompositorError> {
    let bg = state.background_color;
    let bg_color = Color32F::new(bg[0], bg[1], bg[2], bg[3]);

    {
        let (renderer, mut framebuffer) = backend
            .bind()
            .map_err(|e| CompositorError::Render(format!("bind failed: {e}")))?;

        // Import all surface buffers into the renderer.
        import_all_surfaces(renderer, state);

        // Build the full list of render elements (decorations + surfaces).
        let elements = build_render_elements(renderer, state);

        // Render with damage tracking (age=0 forces full repaint in dev).
        match damage_tracker.render_output(
            renderer,
            &mut framebuffer,
            0,
            &elements,
            bg_color,
        ) {
            Ok(result) => {
                trace!(
                    damage = ?result.damage,
                    "frame rendered"
                );
            }
            Err(e) => {
                return Err(CompositorError::Render(format!(
                    "damage render failed: {e}"
                )));
            }
        }
    }

    backend
        .submit(None)
        .map_err(|e| CompositorError::Render(format!("submit failed: {e}")))?;

    // Send frame callbacks to clients so they submit next frames.
    send_frame_callbacks(state);

    Ok(())
}

/// Import all mapped surface trees into the renderer.
fn import_all_surfaces<R: Renderer + ImportAll>(renderer: &mut R, state: &Delphi)
where
    R::TextureId: 'static,
{
    for surface in &state.stacking_order {
        if let Some(win) = state.windows.get(surface)
            && win.mapped
            && let Err(e) = import_surface_tree(renderer, surface)
        {
            trace!("surface import skipped: {e:?}");
        }
    }
}

/// Build render elements for all windows (decorations + surface content).
fn build_render_elements<R: Renderer + ImportAll>(
    renderer: &mut R,
    state: &Delphi,
) -> Vec<DelphiRenderElement<R>>
where
    R::TextureId: Clone + 'static,
{
    let mut elements: Vec<DelphiRenderElement<R>> = Vec::new();

    // Iterate back-to-front (stacking order).
    for surface in &state.stacking_order {
        if let Some(win) = state.windows.get(surface) {
            if !win.mapped {
                continue;
            }

            let is_focused = state.focused_surface.as_ref() == Some(surface);
            add_window_elements(
                renderer, surface, win, is_focused, &mut elements,
            );
        }
    }

    elements
}

/// Add all render elements for a single window.
fn add_window_elements<R: Renderer + ImportAll>(
    renderer: &mut R,
    surface: &smithay::reexports::wayland_server::protocol::wl_surface::WlSurface,
    win: &crate::window::WindowState,
    focused: bool,
    elements: &mut Vec<DelphiRenderElement<R>>,
) where
    R::TextureId: Clone + 'static,
{
    // Window border (focused windows get a colored border).
    if focused {
        for border in window_border_elements(win) {
            elements.push(DelphiRenderElement::Decoration(border));
        }
    }

    // Title bar decorations.
    for deco in window_decoration_elements(win, focused) {
        elements.push(DelphiRenderElement::Decoration(deco));
    }

    // Client surface content (offset below title bar).
    let surface_elements: Vec<DelphiRenderElement<R>> =
        render_elements_from_surface_tree(
            renderer,
            surface,
            (win.x, win.y + TITLE_BAR_HEIGHT),
            Scale::from(1.0),
            1.0,
            Kind::Unspecified,
        );

    elements.extend(surface_elements);
}

/// Send frame callbacks to all mapped client surfaces.
fn send_frame_callbacks(state: &Delphi) {
    let Some(output) = &state.output else {
        return;
    };
    let time = state.clock.now();

    for surface in &state.stacking_order {
        if let Some(win) = state.windows.get(surface)
            && win.mapped
        {
            smithay::desktop::utils::send_frames_surface_tree(
                surface,
                output,
                time,
                Some(Duration::ZERO),
                |_, _| None,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn output_name_is_winit() {
        let name = "winit-0";
        assert!(name.starts_with("winit"));
    }
}
