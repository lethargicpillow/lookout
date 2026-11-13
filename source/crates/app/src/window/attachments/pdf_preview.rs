//! Read-only PDF preview using system Poppler utilities. All subprocess and
//! filesystem work runs off the GTK thread; no shell or embedded browser.

use gtk::{glib, prelude::*, subclass::prelude::*};
use std::cell::{Cell, RefCell};
use std::fs;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MIN_ZOOM: u32 = 50;
const MAX_ZOOM: u32 = 400;
const DEFAULT_ZOOM: u32 = 100;
const ZOOM_MARKS: [u32; 8] = [50, 100, 150, 200, 250, 300, 350, 400];
const TOOL_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_PNG_BYTES: u64 = 64 * 1024 * 1024;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("lookout-pdf-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_tool(command: &mut Command) -> Result<(), String> {
    let mut child = command.env("LC_ALL", "C").stdin(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "PDF preview requires Poppler (install poppler-utils).".to_string()
            } else {
                "Could not start the PDF renderer.".to_string()
            }
        })?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err("Could not read this PDF. It may be encrypted or damaged.".into()),
            Ok(None) if start.elapsed() < TOOL_TIMEOUT => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("PDF rendering timed out or failed.".into());
            }
        }
    }
}

fn page_count(info: &str) -> Option<u32> {
    info.lines().find_map(|line| line.strip_prefix("Pages:"))
        .and_then(|value| value.trim().parse::<u32>().ok()).filter(|n| *n > 0)
}

fn render_size(zoom: u32) -> u32 {
    900 * zoom.clamp(MIN_ZOOM, MAX_ZOOM) / 100
}

fn zoom_value(value: f64) -> u32 {
    value.round().clamp(MIN_ZOOM as f64, MAX_ZOOM as f64) as u32
}

fn snap_zoom(value: f64) -> Option<f64> {
    ZOOM_MARKS.iter().copied().map(f64::from)
        .find(|mark| (value - mark).abs() <= 2.0)
}

fn scaled_dimension(pixels: i32, source_zoom: u32, target_zoom: u32) -> i32 {
    ((pixels as f64 * target_zoom as f64 / source_zoom.max(1) as f64).round() as i32).max(1)
}

// A viewport centre expressed in page coordinates, independent of zoom.
// When the page fits, its centre is the anchor on that axis.
fn view_anchor(value: f64, lower: f64, viewport: f64, extent: f64) -> f64 {
    if extent <= 0.0 { return 0.5; }
    let inset = ((viewport - extent) / 2.0).max(0.0);
    ((value - lower + viewport / 2.0 - inset) / extent).clamp(0.0, 1.0)
}

fn anchor_position(anchor: f64, lower: f64, viewport: f64, extent: f64) -> f64 {
    let inset = ((viewport - extent) / 2.0).max(0.0);
    (lower + anchor * extent + inset - viewport / 2.0)
        .clamp(lower, lower + (extent - viewport).max(0.0))
}

fn set_scroll(adjustment: &gtk::Adjustment, value: f64) {
    let lower = adjustment.lower();
    adjustment.set_value(value.clamp(lower, (adjustment.upper() - adjustment.page_size()).max(lower)));
}

// A texture's intrinsic dimensions must not determine its GTK layout:
// the same raster is drawn immediately at every slider position, including
// zooming down, until Poppler supplies a sharper raster at the final zoom.
mod canvas_imp {
    use super::*;

    #[derive(Default)]
    pub struct PageCanvas {
        pub texture: RefCell<Option<gtk::gdk::Texture>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PageCanvas {
        const NAME: &'static str = "LookoutPdfPageCanvas";
        type Type = super::PageCanvas;
        type ParentType = gtk::Widget;
    }

    impl ObjectImpl for PageCanvas {}
    impl WidgetImpl for PageCanvas {
        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let widget = self.obj();
            if let Some(texture) = self.texture.borrow().as_ref() {
                snapshot.append_texture(texture, &gtk::graphene::Rect::new(
                    0.0, 0.0, widget.width() as f32, widget.height() as f32,
                ));
            }
        }
    }
}

glib::wrapper! {
    pub struct PageCanvas(ObjectSubclass<canvas_imp::PageCanvas>)
        @extends gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl PageCanvas {
    fn new() -> Self { glib::Object::builder().build() }

    fn clear(&self) {
        self.imp().texture.replace(None);
        self.set_visible(false);
        self.queue_draw();
    }

    fn set_texture(&self, texture: gtk::gdk::Texture) {
        self.imp().texture.replace(Some(texture));
        self.queue_draw();
    }

    fn resize_for_zoom(&self, source: u32, target: u32) {
        if let Some(texture) = self.imp().texture.borrow().as_ref() {
            self.set_size_request(
                scaled_dimension(texture.width(), source, target),
                scaled_dimension(texture.height(), source, target),
            );
            self.queue_draw();
        }
    }
}

struct Rendered {
    png: Vec<u8>,
    pages: u32,
}

fn render_page(bytes: &[u8], page: u32, zoom: u32, known_pages: u32) -> Result<Rendered, String> {
    let scratch = Scratch::new().map_err(|_| "Could not create a private PDF preview directory.".to_string())?;
    let input = scratch.0.join("attachment.pdf");
    fs::write(&input, bytes).map_err(|_| "Could not prepare PDF preview.".to_string())?;
    let pages = if known_pages > 0 {
        known_pages
    } else {
        let info_path = scratch.0.join("info.txt");
        let output = fs::File::create(&info_path).map_err(|_| "Could not prepare PDF metadata.".to_string())?;
        run_tool(Command::new("pdfinfo").arg(&input).stdout(Stdio::from(output)))?;
        let mut info = String::new();
        fs::File::open(&info_path)
            .and_then(|f| f.take(256 * 1024).read_to_string(&mut info))
            .map_err(|_| "Could not read PDF metadata.".to_string())?;
        page_count(&info).ok_or_else(|| "Could not determine the PDF page count.".to_string())?
    };
    if page == 0 || page > pages {
        return Err("PDF page is outside the document.".into());
    }
    let page_arg = page.to_string();
    let size_arg = render_size(zoom).to_string();
    let prefix = scratch.0.join("page");
    run_tool(Command::new("pdftoppm")
        .args(["-f", &page_arg, "-l", &page_arg, "-singlefile", "-png", "-scale-to", &size_arg])
        .arg(&input).arg(&prefix).stdout(Stdio::null()))?;
    let image = fs::File::open(scratch.0.join("page.png"))
        .map_err(|_| "PDF renderer did not produce a page.".to_string())?;
    let mut png = Vec::new();
    image.take(MAX_PNG_BYTES + 1).read_to_end(&mut png)
        .map_err(|_| "Could not read the rendered page.".to_string())?;
    if png.is_empty() || png.len() as u64 > MAX_PNG_BYTES {
        return Err("The rendered PDF page is too large or empty.".into());
    }
    Ok(Rendered { png, pages })
}

// Weak widget references avoid cycles with button handlers and let a closed
// preview disappear while a worker finishes its current render.
struct Preview {
    bytes: Arc<Vec<u8>>,
    page: Cell<u32>,
    pages: Cell<u32>,
    zoom: Cell<u32>,
    busy: Cell<bool>,
    picture: glib::WeakRef<PageCanvas>,
    scroller: glib::WeakRef<gtk::ScrolledWindow>,
    pending_anchor: Cell<Option<(f64, f64)>>,
    anchor_revision: Cell<u64>,
    counter: glib::WeakRef<gtk::Label>,
    status: glib::WeakRef<gtk::Label>,
    previous: glib::WeakRef<gtk::Button>,
    next: glib::WeakRef<gtk::Button>,
    slider: glib::WeakRef<gtk::Scale>,
    zoom_label: glib::WeakRef<gtk::Label>,
    zoom_revision: Cell<u64>,
    rendered_zoom: Cell<Option<u32>>,
    retry: glib::WeakRef<gtk::Button>,
}
impl Preview {
    fn controls(&self) {
        let idle = !self.busy.get();
        let known = self.pages.get() > 0;
        if let Some(label) = self.counter.upgrade() {
            label.set_text(&format!("{} / {}",
                self.page.get(), if known { self.pages.get().to_string() } else { "…".into() }));
        }
        if let Some(label) = self.zoom_label.upgrade() {
            label.set_text(&format!("{}%", self.zoom.get()));
        }
        if let Some(slider) = self.slider.upgrade() {
            // Do not interrupt a drag when rendering starts. Changes are
            // coalesced and the newest requested zoom wins.
            slider.set_sensitive(known);
        }
        for (button, enabled) in [
            (&self.previous, self.page.get() > 1),
            (&self.next, known && self.page.get() < self.pages.get()),
            (&self.retry, true),
        ] {
            if let Some(button) = button.upgrade() {
                button.set_sensitive(idle && enabled);
            }
        }
    }

    fn capture_anchor(&self) -> (f64, f64) {
        if let Some(anchor) = self.pending_anchor.get() { return anchor; }
        let (Some(picture), Some(scroller)) = (self.picture.upgrade(), self.scroller.upgrade()) else {
            return (0.5, 0.5);
        };
        let h = scroller.hadjustment();
        let v = scroller.vadjustment();
        (
            view_anchor(h.value(), h.lower(), h.page_size(), picture.width_request() as f64),
            view_anchor(v.value(), v.lower(), v.page_size(), picture.height_request() as f64),
        )
    }

    fn cancel_anchor(&self) {
        self.pending_anchor.set(None);
        self.anchor_revision.set(self.anchor_revision.get().wrapping_add(1));
    }

    fn restore_anchor(self: &Rc<Self>, anchor: (f64, f64)) {
        self.pending_anchor.set(Some(anchor));
        let revision = self.anchor_revision.get().wrapping_add(1);
        self.anchor_revision.set(revision);
        let Some(scroller) = self.scroller.upgrade() else { return; };
        let weak = Rc::downgrade(self);
        // GTK updates scroll ranges at allocation time, not when the size
        // request changes. Apply only after the viewport has the new range.
        // Rapid slider moves reuse the same anchor and supersede this tick.
        let frames = Cell::new(0u8);
        scroller.add_tick_callback(move |_, _| {
            let Some(preview) = weak.upgrade() else { return glib::ControlFlow::Break; };
            if preview.anchor_revision.get() != revision || preview.pending_anchor.get().is_none() {
                return glib::ControlFlow::Break;
            }
            let (Some(picture), Some(scroller)) = (preview.picture.upgrade(), preview.scroller.upgrade()) else {
                return glib::ControlFlow::Break;
            };
            let h = scroller.hadjustment();
            let v = scroller.vadjustment();
            let w = picture.width_request() as f64;
            let height = picture.height_request() as f64;
            let ready = h.page_size() > 0.0 && v.page_size() > 0.0
                && (picture.width() as f64 - w).abs() <= 2.0
                && (picture.height() as f64 - height).abs() <= 2.0
                && (h.upper() - h.lower() - w.max(h.page_size())).abs() <= 2.0
                && (v.upper() - v.lower() - height.max(v.page_size())).abs() <= 2.0;
            frames.set(frames.get() + 1);
            if !ready && frames.get() < 8 { return glib::ControlFlow::Continue; }
            if h.page_size() > 0.0 && v.page_size() > 0.0 {
                set_scroll(&h, anchor_position(anchor.0, h.lower(), h.page_size(), w));
                set_scroll(&v, anchor_position(anchor.1, v.lower(), v.page_size(), height));
            }
            preview.pending_anchor.set(None);
            glib::ControlFlow::Break
        });
    }

    fn request_zoom(self: &Rc<Self>, value: f64) {
        let zoom = zoom_value(value);
        if self.zoom.replace(zoom) == zoom { return; }
        if let (Some(picture), Some(source)) = (self.picture.upgrade(), self.rendered_zoom.get()) {
            let anchor = self.capture_anchor();
            picture.resize_for_zoom(source, zoom);
            self.restore_anchor(anchor);
        }
        self.controls();
        self.schedule_render();
    }

    fn schedule_render(self: &Rc<Self>) {
        let revision = self.zoom_revision.get().wrapping_add(1);
        self.zoom_revision.set(revision);
        let weak = Rc::downgrade(self);
        glib::timeout_add_local_once(Duration::from_millis(180), move || {
            let Some(preview) = weak.upgrade() else { return; };
            if preview.zoom_revision.get() == revision
                && !preview.busy.get()
                && preview.rendered_zoom.get() != Some(preview.zoom.get())
            {
                preview.begin();
            }
        });
    }

    fn begin(self: &Rc<Self>) {
        if self.busy.replace(true) { return; }
        self.controls();
        // Keep the last raster visible while refining its resolution.
        // Only a first load or a page change needs the loading placeholder.
        if let Some(label) = self.status.upgrade() {
            label.set_text("Rendering PDF page…");
            label.set_visible(self.rendered_zoom.get().is_none());
        }
        if let Some(retry) = self.retry.upgrade() { retry.set_visible(false); }
        let bytes = self.bytes.clone();
        let (page, zoom, pages) = (self.page.get(), self.zoom.get(), self.pages.get());
        let (tx, rx) = async_channel::bounded(1);
        let started = std::thread::Builder::new().name("lookout-pdf-preview".into()).spawn(move || {
            let _ = tx.send_blocking(render_page(&bytes, page, zoom, pages));
        });
        if started.is_err() {
            self.finish(zoom, Err("Could not start PDF preview worker.".into()));
            return;
        }
        let preview = self.clone();
        glib::spawn_future_local(async move {
            let result = rx.recv().await.unwrap_or_else(|_| Err("PDF preview worker stopped.".into()));
            preview.finish(zoom, result);
        });
    }

    fn finish(self: &Rc<Self>, rendered_zoom: u32, result: Result<Rendered, String>) {
        self.busy.set(false);
        if self.picture.upgrade().is_none() { return; }
        // A completed raster is still useful at the current zoom even if
        // the slider moved while Poppler was running. Display it scaled to
        // the current target, then coalesce the next high-resolution render.
        if let Ok(rendered) = &result {
            self.pages.set(rendered.pages);
        }
        let (Some(picture), Some(status), Some(retry)) =
            (self.picture.upgrade(), self.status.upgrade(), self.retry.upgrade()) else { return; };
        let result = result.and_then(|rendered| {
            self.pages.set(rendered.pages);
            gtk::gdk::Texture::from_bytes(&glib::Bytes::from(rendered.png.as_slice()))
                .map_err(|_| "Could not decode the rendered PDF page.".to_string())
        });
        match result {
            Ok(texture) => {
                let first = self.rendered_zoom.get().is_none();
                // First open/new page: centre horizontally, start at top.
                // Resolution refinement must retain a manual pan, not reset.
                let anchor = if first { (0.5, 0.0) } else { self.capture_anchor() };
                let old_size = (picture.width_request(), picture.height_request());
                self.rendered_zoom.set(Some(rendered_zoom));
                picture.set_texture(texture);
                picture.resize_for_zoom(rendered_zoom, self.zoom.get());
                picture.set_visible(true);
                if first || old_size != (picture.width_request(), picture.height_request()) {
                    self.restore_anchor(anchor);
                }
                status.set_visible(false);
                retry.set_visible(false);
            }
            Err(message) => {
                // A failed refinement must not blank a readable page.
                // Leave its previous raster intact, with a Retry action.
                status.set_text(&message);
                status.set_visible(true);
                retry.set_visible(true);
            }
        }
        self.controls();
        if self.zoom.get() != rendered_zoom {
            self.schedule_render();
        }
    }
}

pub(super) fn show(content: &gtk::Box, bytes: &[u8]) {
    // Only the titlebar is above the document. Navigation and zoom occupy
    // the narrow side rails, not a horizontal toolbar.
    let body = gtk::Box::builder().orientation(gtk::Orientation::Horizontal)
        .vexpand(true).hexpand(true).build();
    let navigation = gtk::Box::builder().orientation(gtk::Orientation::Vertical)
        .spacing(6).margin_start(8).margin_end(8).valign(gtk::Align::Center).build();
    let previous = gtk::Button::from_icon_name("go-up-symbolic");
    previous.set_tooltip_text(Some("Previous page"));
    let next = gtk::Button::from_icon_name("go-down-symbolic");
    next.set_tooltip_text(Some("Next page"));
    let counter = gtk::Label::new(None);
    counter.set_tooltip_text(Some("Current page / Total pages"));
    let retry = gtk::Button::with_label("Retry");
    navigation.append(&previous);
    navigation.append(&counter);
    navigation.append(&next);
    navigation.append(&retry);
    body.append(&navigation);
    body.append(&gtk::Separator::new(gtk::Orientation::Vertical));

    let status = gtk::Label::new(None);
    status.set_wrap(true);
    status.set_justify(gtk::Justification::Center);
    status.set_halign(gtk::Align::Center);
    status.set_valign(gtk::Align::Center);
    status.set_margin_start(12);
    status.set_margin_end(12);
    status.set_can_target(false);
    let picture = PageCanvas::new();
    picture.set_halign(gtk::Align::Center);
    picture.set_valign(gtk::Align::Center);
    picture.set_hexpand(true);
    picture.set_vexpand(true);
    crate::privacy::mark_blur_all(&picture);
    // The viewport scrolls a full-size holder, not the aligned canvas
    // directly. Centre smaller pages in both axes; larger pages expose
    // their full dimensions through the scroll adjustments.
    let page_holder = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    page_holder.set_hexpand(true);
    page_holder.set_vexpand(true);
    page_holder.append(&picture);
    let viewport = gtk::Viewport::builder().child(&page_holder).build();
    let scroller = gtk::ScrolledWindow::builder().child(&viewport)
        .hscrollbar_policy(gtk::PolicyType::Automatic)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .propagate_natural_width(false).propagate_natural_height(false)
        .overlay_scrolling(false).vexpand(true).hexpand(true).build();
    let document = gtk::Overlay::new();
    document.set_hexpand(true);
    document.set_vexpand(true);
    document.set_child(Some(&scroller));
    document.add_overlay(&status);
    body.append(&document);
    body.append(&gtk::Separator::new(gtk::Orientation::Vertical));

    let zoom_rail = gtk::Box::builder().orientation(gtk::Orientation::Vertical)
        .spacing(8).margin_start(8).margin_end(8).margin_top(24).margin_bottom(24)
        .valign(gtk::Align::Fill).vexpand(true).build();
    let slider = gtk::Scale::with_range(gtk::Orientation::Vertical, MIN_ZOOM as f64, MAX_ZOOM as f64, 1.0);
    slider.set_inverted(true);
    slider.set_draw_value(false);
    slider.set_digits(0);
    slider.set_size_request(-1, 320);
    slider.set_vexpand(true);
    slider.set_value(DEFAULT_ZOOM as f64);
    slider.set_tooltip_text(Some("PDF zoom"));
    for percent in ZOOM_MARKS {
        slider.add_mark(percent as f64, gtk::PositionType::Right, Some(&format!("{percent}%")));
    }
    // Snap only direct pointer jumps, not arrow-key increments, so users
    // can still move in exact one-percent steps around every marked value.
    slider.connect_change_value(|scale, scroll, value| {
        if scroll == gtk::ScrollType::Jump {
            if let Some(mark) = snap_zoom(value) {
                scale.set_value(mark);
                return glib::Propagation::Stop;
            }
        }
        glib::Propagation::Proceed
    });
    let zoom_label = gtk::Label::new(Some("100%"));
    zoom_rail.append(&slider);
    zoom_rail.append(&zoom_label);
    body.append(&zoom_rail);
    content.append(&body);

    let preview = Rc::new(Preview {
        bytes: Arc::new(bytes.to_vec()), page: Cell::new(1), pages: Cell::new(0),
        zoom: Cell::new(DEFAULT_ZOOM), busy: Cell::new(false),
        picture: picture.downgrade(), scroller: scroller.downgrade(),
        pending_anchor: Cell::new(None), anchor_revision: Cell::new(0),
        counter: counter.downgrade(), status: status.downgrade(),
        previous: previous.downgrade(), next: next.downgrade(),
        slider: slider.downgrade(), zoom_label: zoom_label.downgrade(),
        zoom_revision: Cell::new(0), rendered_zoom: Cell::new(None), retry: retry.downgrade(),
    });
    for (button, action) in [(&previous, 0), (&next, 1), (&retry, 2)] {
        let preview = preview.clone();
        let scroller = scroller.downgrade();
        button.connect_clicked(move |_| {
            if preview.busy.get() { return; }
            match action {
                0 if preview.page.get() > 1 => preview.page.set(preview.page.get() - 1),
                1 if preview.page.get() < preview.pages.get() => preview.page.set(preview.page.get() + 1),
                2 => {},
                _ => return,
            }
            if action != 2 {
                preview.cancel_anchor();
                preview.rendered_zoom.set(None);
                if let Some(picture) = preview.picture.upgrade() { picture.clear(); }
                if let Some(scroller) = scroller.upgrade() {
                    for adjustment in [scroller.hadjustment(), scroller.vadjustment()] {
                        adjustment.set_value(adjustment.lower());
                    }
                }
            }
            preview.begin();
        });
    }
    {
        let preview = preview.clone();
        slider.connect_value_changed(move |slider| preview.request_zoom(slider.value()));
    }

    // Pan from the stationary viewport, not the moving page widget.
    // Drag offsets remain in viewport coordinates as the page scrolls.
    let drag = gtk::GestureDrag::new();
    drag.set_button(1);
    drag.set_propagation_phase(gtk::PropagationPhase::Capture);
    let origin = Rc::new(Cell::new(None::<(f64, f64)>));
    {
        let origin = origin.clone();
        let weak = Rc::downgrade(&preview);
        let viewport = viewport.downgrade();
        drag.connect_drag_begin(move |gesture, _, _| {
            let Some(preview) = weak.upgrade() else { return; };
            let Some(scroller) = preview.scroller.upgrade() else { return; };
            let h = scroller.hadjustment();
            let v = scroller.vadjustment();
            if h.upper() - h.lower() <= h.page_size() && v.upper() - v.lower() <= v.page_size() {
                gesture.set_state(gtk::EventSequenceState::Denied);
                return;
            }
            preview.cancel_anchor();
            origin.set(Some((h.value(), v.value())));
            gesture.set_state(gtk::EventSequenceState::Claimed);
            if let Some(viewport) = viewport.upgrade() { viewport.set_cursor_from_name(Some("grabbing")); }
        });
    }
    {
        let origin = origin.clone();
        let weak = Rc::downgrade(&preview);
        drag.connect_drag_update(move |_, dx, dy| {
            let Some((x, y)) = origin.get() else { return; };
            let Some(preview) = weak.upgrade() else { return; };
            let Some(scroller) = preview.scroller.upgrade() else { return; };
            set_scroll(&scroller.hadjustment(), x - dx);
            set_scroll(&scroller.vadjustment(), y - dy);
        });
    }
    {
        let origin = origin.clone();
        let viewport = viewport.downgrade();
        drag.connect_drag_end(move |_, _, _| {
            origin.set(None);
            if let Some(viewport) = viewport.upgrade() { viewport.set_cursor_from_name(Some("grab")); }
        });
    }
    {
        let viewport = viewport.downgrade();
        drag.connect_cancel(move |_, _| {
            origin.set(None);
            if let Some(viewport) = viewport.upgrade() { viewport.set_cursor_from_name(Some("grab")); }
        });
    }
    viewport.set_cursor_from_name(Some("grab"));
    viewport.add_controller(drag);
    // A new manual scroll must win over a pending zoom allocation.
    let scroll = gtk::EventControllerScroll::new(gtk::EventControllerScrollFlags::BOTH_AXES);
    scroll.set_propagation_phase(gtk::PropagationPhase::Capture);
    let weak = Rc::downgrade(&preview);
    scroll.connect_scroll(move |_, _, _| {
        if let Some(preview) = weak.upgrade() { preview.cancel_anchor(); }
        glib::Propagation::Proceed
    });
    viewport.add_controller(scroll);
    preview.begin();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_zoom_keeps_viewport_centre_and_clamps_at_edges() {
        assert_eq!(view_anchor(0.0, 0.0, 800.0, 400.0), 0.5);
        assert_eq!(anchor_position(0.5, 0.0, 800.0, 1600.0), 400.0);
        assert_eq!(view_anchor(400.0, 0.0, 800.0, 1600.0), 0.5);
        assert_eq!(view_anchor(800.0, 0.0, 400.0, 2000.0), 0.5);
        assert_eq!(anchor_position(0.5, 0.0, 400.0, 4000.0), 1800.0);
        assert_eq!(anchor_position(0.0, 0.0, 400.0, 2000.0), 0.0);
        assert_eq!(anchor_position(1.0, 0.0, 400.0, 2000.0), 1600.0);
        assert_eq!(anchor_position(0.9, 0.0, 800.0, 400.0), 0.0);
    }

    #[test]
    fn pdf_metadata_and_zoom_are_bounded() {
        assert_eq!(page_count("Title: Example\nPages:           12\n"), Some(12));
        assert_eq!(page_count("Pages: 0"), None);
        assert_eq!(page_count("Pages: invalid"), None);
        assert_eq!(page_count("Title: no page count"), None);
        assert_eq!(render_size(0), 450);
        assert_eq!(render_size(50), 450);
        assert_eq!(render_size(100), 900);
        assert_eq!(render_size(137), 1233);
        assert_eq!(render_size(400), 3600);
        assert_eq!(render_size(u32::MAX), 3600);
        assert_eq!(zoom_value(137.4), 137);
        assert_eq!(snap_zoom(99.0), Some(100.0));
        assert_eq!(snap_zoom(103.0), None);
        assert_eq!(snap_zoom(399.0), Some(400.0));
        assert_eq!(scaled_dimension(900, 100, 50), 450);
        assert_eq!(scaled_dimension(900, 100, 400), 3600);
        assert_eq!(scaled_dimension(3600, 400, 137), 1233);
    }
}
