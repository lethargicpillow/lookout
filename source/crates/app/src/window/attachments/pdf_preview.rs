//! Read-only PDF preview using system Poppler utilities. All subprocess and
//! filesystem work runs off the GTK thread; no shell or embedded browser.

use gtk::{glib, prelude::*, subclass::prelude::*};
use std::cell::{Cell, OnceCell, RefCell};
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
const WHEEL_ZOOM_STEP: u32 = 10;
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

fn wheel_zoom(current: u32, dy: f64) -> u32 {
    // Discrete wheel deltas: up enlarges, down reduces. Keep the
    // exact intermediate percentage when the slider was used last.
    if dy == 0.0 { return current; }
    let steps = dy.abs().round().max(1.0).min(35.0) as u32;
    let change = WHEEL_ZOOM_STEP * steps;
    if dy < 0.0 {
        current.saturating_add(change).min(MAX_ZOOM)
    } else {
        current.saturating_sub(change).max(MIN_ZOOM)
    }
}

fn snap_zoom(value: f64) -> Option<f64> {
    ZOOM_MARKS.iter().copied().map(f64::from)
        .find(|mark| (value - mark).abs() <= 2.0)
}

#[cfg(test)]
fn scaled_dimension(pixels: i32, source_zoom: u32, target_zoom: u32) -> i32 {
    ((pixels as f64 * target_zoom as f64 / source_zoom.max(1) as f64).round() as i32).max(1)
}

// A page point and the viewport pixel at which it must remain.
// None means the viewport centre (slider zoom); Some is the mouse cursor.
#[derive(Clone, Copy)]
struct ZoomAnchor {
    page: (f64, f64),
    cursor: Option<(f64, f64)>,
}

fn view_anchor(value: f64, lower: f64, viewport: f64, extent: f64, offset: f64) -> f64 {
    if extent <= 0.0 { return 0.5; }
    let inset = ((viewport - extent) / 2.0).max(0.0);
    ((value - lower + offset - inset) / extent).clamp(0.0, 1.0)
}

fn anchor_position(anchor: f64, lower: f64, viewport: f64, extent: f64, offset: f64) -> f64 {
    let inset = ((viewport - extent) / 2.0).max(0.0);
    (lower + anchor * extent + inset - offset)
        .clamp(lower, lower + (extent - viewport).max(0.0))
}

fn viewport_offset(cursor: Option<(f64, f64)>, width: f64, height: f64) -> (f64, f64) {
    let (x, y) = cursor.unwrap_or((width / 2.0, height / 2.0));
    (x.clamp(0.0, width.max(0.0)), y.clamp(0.0, height.max(0.0)))
}

fn event_cursor(event: &gtk::gdk::Event, viewport: &PageCanvas) -> Option<(f64, f64)> {
    let (x, y) = event.position()?;
    let window = viewport.root().and_downcast::<gtk::Window>()?;
    let (nx, ny) = window.surface_transform();
    // Match GTK's event-to-widget translation, including CSD shadows.
    let point = window.compute_point(viewport, &gtk::graphene::Point::new(
        (x - nx) as f32, (y - ny) as f32,
    ))?;
    Some((point.x() as f64, point.y() as f64))
}

fn set_scroll(adjustment: &gtk::Adjustment, value: f64) {
    let lower = adjustment.lower();
    adjustment.set_value(value.clamp(lower, (adjustment.upper() - adjustment.page_size()).max(lower)));
}

fn scroll_pixels(dx: f64, dy: f64, surface: bool, shift: bool) -> (f64, f64) {
    let factor = if surface { 1.0 } else { 48.0 };
    let (dx, dy) = if shift && dx == 0.0 { (dy, 0.0) } else { (dx, dy) };
    (dx * factor, dy * factor)
}

// Fixed-size viewport: zoom changes only the texture transform and two
// adjustment ranges, never the GTK widget's size request or allocation.
// Both scrollbars occupy permanent space so crossing a fit threshold
// cannot resize the viewport in the middle of a zoom gesture.
mod canvas_imp {
    use super::*;

    #[derive(Default)]
    pub struct PageCanvas {
        pub texture: RefCell<Option<gtk::gdk::Texture>>,
        pub adjustments: OnceCell<(gtk::Adjustment, gtk::Adjustment)>,
        pub base_size: Cell<(f64, f64)>,
        pub extent: Cell<(f64, f64)>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PageCanvas {
        const NAME: &'static str = "LookoutPdfPageCanvas";
        type Type = super::PageCanvas;
        type ParentType = gtk::Widget;
    }

    impl ObjectImpl for PageCanvas {}
    impl WidgetImpl for PageCanvas {
        fn size_allocate(&self, width: i32, height: i32, baseline: i32) {
            self.parent_size_allocate(width, height, baseline);
            let widget = self.obj();
            if self.adjustments.get().is_some() {
                // Window resize is separate from zoom. Keep the centre
                // of the previous viewport, then update ranges in one pass.
                let anchor = widget.capture_anchor(None);
                widget.apply_geometry(self.extent.get(), anchor, width as f64, height as f64);
            }
        }

        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let widget = self.obj();
            let Some((h, v)) = self.adjustments.get() else { return; };
            if let Some(texture) = self.texture.borrow().as_ref() {
                let (w, height) = self.extent.get();
                let vw = widget.width() as f64;
                let vh = widget.height() as f64;
                if w <= 0.0 || height <= 0.0 || vw <= 0.0 || vh <= 0.0 { return; }
                let x = ((vw - w) / 2.0).max(0.0) - h.value();
                let y = ((vh - height) / 2.0).max(0.0) - v.value();
                snapshot.push_clip(&gtk::graphene::Rect::new(0.0, 0.0, vw as f32, vh as f32));
                snapshot.append_texture(texture, &gtk::graphene::Rect::new(
                    x as f32, y as f32, w as f32, height as f32,
                ));
                snapshot.pop();
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
    fn new() -> Self {
        let canvas: Self = glib::Object::builder().build();
        let h = gtk::Adjustment::new(0.0, 0.0, 0.0, 48.0, 100.0, 0.0);
        let v = gtk::Adjustment::new(0.0, 0.0, 0.0, 48.0, 100.0, 0.0);
        for adjustment in [&h, &v] {
            let weak = canvas.downgrade();
            adjustment.connect_value_changed(move |_| {
                if let Some(canvas) = weak.upgrade() { canvas.queue_draw(); }
            });
        }
        let _ = canvas.imp().adjustments.set((h, v));
        canvas
    }

    fn hadjustment(&self) -> gtk::Adjustment { self.imp().adjustments.get().unwrap().0.clone() }
    fn vadjustment(&self) -> gtk::Adjustment { self.imp().adjustments.get().unwrap().1.clone() }

    fn capture_anchor(&self, cursor: Option<(f64, f64)>) -> ZoomAnchor {
        let h = self.hadjustment();
        let v = self.vadjustment();
        let (w, height) = self.imp().extent.get();
        let (x, y) = viewport_offset(cursor, h.page_size(), v.page_size());
        ZoomAnchor {
            page: (
                view_anchor(h.value(), h.lower(), h.page_size(), w, x),
                view_anchor(v.value(), v.lower(), v.page_size(), height, y),
            ),
            cursor,
        }
    }

    fn apply_geometry(&self, extent: (f64, f64), anchor: ZoomAnchor, vw: f64, vh: f64) {
        self.imp().extent.set(extent);
        let (w, height) = extent;
        let vw = vw.max(0.0);
        let vh = vh.max(0.0);
        let (x, y) = viewport_offset(anchor.cursor, vw, vh);
        // Configure value and range together. There is no intermediate
        // clamping against the old size and no delayed correction tick.
        self.hadjustment().configure(
            anchor_position(anchor.page.0, 0.0, vw, w, x),
            0.0, w.max(vw), 48.0, (vw * 0.9).max(1.0), vw,
        );
        self.vadjustment().configure(
            anchor_position(anchor.page.1, 0.0, vh, height, y),
            0.0, height.max(vh), 48.0, (vh * 0.9).max(1.0), vh,
        );
        self.queue_draw();
    }

    fn clear(&self) {
        self.imp().texture.replace(None);
        self.imp().base_size.set((0.0, 0.0));
        self.apply_geometry((0.0, 0.0), ZoomAnchor { page: (0.5, 0.0), cursor: None },
            self.width() as f64, self.height() as f64);
    }

    fn set_texture(&self, texture: gtk::gdk::Texture, source_zoom: u32, target_zoom: u32) {
        let first = self.imp().texture.borrow().is_none();
        if first {
            // Freeze logical page geometry on the first raster. Later
            // Poppler rasters can differ by a pixel due to rounding; they
            // refine the texture only, never move the page or scrollbar.
            let factor = 100.0 / source_zoom.max(1) as f64;
            self.imp().base_size.set((texture.width() as f64 * factor, texture.height() as f64 * factor));
        }
        self.imp().texture.replace(Some(texture));
        if first {
            let (w, h) = self.imp().base_size.get();
            let scale = target_zoom as f64 / 100.0;
            self.apply_geometry((w * scale, h * scale),
                ZoomAnchor { page: (0.5, 0.0), cursor: None },
                self.width() as f64, self.height() as f64);
        } else {
            self.queue_draw();
        }
    }

    fn zoom_to(&self, target: u32, cursor: Option<(f64, f64)>) {
        let anchor = self.capture_anchor(cursor);
        let (w, h) = self.imp().base_size.get();
        let scale = target as f64 / 100.0;
        self.apply_geometry((w * scale, h * scale), anchor, self.width() as f64, self.height() as f64);
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
    wheel_cursor: Cell<Option<(f64, f64)>>,
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

    fn request_zoom(self: &Rc<Self>, value: f64) {
        let zoom = zoom_value(value);
        let cursor = self.wheel_cursor.take();
        if self.zoom.replace(zoom) == zoom { return; }
        if let Some(picture) = self.picture.upgrade() {
            picture.zoom_to(zoom, cursor);
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
                self.rendered_zoom.set(Some(rendered_zoom));
                picture.set_texture(texture, rendered_zoom, self.zoom.get());
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
    picture.set_hexpand(true);
    picture.set_vexpand(true);
    picture.set_overflow(gtk::Overflow::Hidden);
    crate::privacy::mark_blur_all(&picture);
    // Permanent scrollbar slots keep viewport geometry stable at every zoom.
    let horizontal = gtk::Scrollbar::new(gtk::Orientation::Horizontal, Some(&picture.hadjustment()));
    let vertical = gtk::Scrollbar::new(gtk::Orientation::Vertical, Some(&picture.vadjustment()));
    let grid = gtk::Grid::new();
    grid.set_hexpand(true);
    grid.set_vexpand(true);
    grid.attach(&picture, 0, 0, 1, 1);
    grid.attach(&vertical, 1, 0, 1, 1);
    grid.attach(&horizontal, 0, 1, 1, 1);
    let document = gtk::Overlay::new();
    document.set_hexpand(true);
    document.set_vexpand(true);
    document.set_child(Some(&grid));
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
    slider.set_tooltip_text(Some("Document zoom (Ctrl + mouse wheel)"));
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
    zoom_label.set_width_chars(4);
    zoom_rail.append(&slider);
    zoom_rail.append(&zoom_label);
    body.append(&zoom_rail);
    content.append(&body);

    let preview = Rc::new(Preview {
        bytes: Arc::new(bytes.to_vec()), page: Cell::new(1), pages: Cell::new(0),
        zoom: Cell::new(DEFAULT_ZOOM), busy: Cell::new(false),
        picture: picture.downgrade(), wheel_cursor: Cell::new(None),
        counter: counter.downgrade(), status: status.downgrade(),
        previous: previous.downgrade(), next: next.downgrade(),
        slider: slider.downgrade(), zoom_label: zoom_label.downgrade(),
        zoom_revision: Cell::new(0), rendered_zoom: Cell::new(None), retry: retry.downgrade(),
    });
    for (button, action) in [(&previous, 0), (&next, 1), (&retry, 2)] {
        let preview = preview.clone();
        button.connect_clicked(move |_| {
            if preview.busy.get() { return; }
            match action {
                0 if preview.page.get() > 1 => preview.page.set(preview.page.get() - 1),
                1 if preview.page.get() < preview.pages.get() => preview.page.set(preview.page.get() + 1),
                2 => {},
                _ => return,
            }
            if action != 2 {
                preview.rendered_zoom.set(None);
                if let Some(picture) = preview.picture.upgrade() { picture.clear(); }
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
        let viewport = picture.downgrade();
        drag.connect_drag_begin(move |gesture, _, _| {
            let Some(preview) = weak.upgrade() else { return; };
            let Some(scroller) = preview.picture.upgrade() else { return; };
            let h = scroller.hadjustment();
            let v = scroller.vadjustment();
            if h.upper() - h.lower() <= h.page_size() && v.upper() - v.lower() <= v.page_size() {
                gesture.set_state(gtk::EventSequenceState::Denied);
                return;
            }
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
            let Some(scroller) = preview.picture.upgrade() else { return; };
            set_scroll(&scroller.hadjustment(), x - dx);
            set_scroll(&scroller.vadjustment(), y - dy);
        });
    }
    {
        let origin = origin.clone();
        let viewport = picture.downgrade();
        drag.connect_drag_end(move |_, _, _| {
            origin.set(None);
            if let Some(viewport) = viewport.upgrade() { viewport.set_cursor_from_name(Some("grab")); }
        });
    }
    {
        let viewport = picture.downgrade();
        drag.connect_cancel(move |_, _| {
            origin.set(None);
            if let Some(viewport) = viewport.upgrade() { viewport.set_cursor_from_name(Some("grab")); }
        });
    }
    picture.set_cursor_from_name(Some("grab"));
    picture.add_controller(drag);
    // This is the sole wheel dispatcher. There is no GtkScrolledWindow
    // or kinetic wheel controller to race the zoom.
    // Capture raw events to preserve smooth deltas, modifier state and
    // the pointer position, and consume both ordinary and Ctrl scrolling.
    let scroll = gtk::EventControllerLegacy::new();
    scroll.set_propagation_phase(gtk::PropagationPhase::Capture);
    let weak = Rc::downgrade(&preview);
    let weak_viewport = picture.downgrade();
    let smooth = Cell::new(0.0f64);
    scroll.connect_event(move |_, event| {
        let Some(event_scroll) = event.downcast_ref::<gtk::gdk::ScrollEvent>() else {
            return glib::Propagation::Proceed;
        };
        let modifiers = event.modifier_state();
        let ctrl = modifiers.contains(gtk::gdk::ModifierType::CONTROL_MASK);
        let shift = modifiers.contains(gtk::gdk::ModifierType::SHIFT_MASK);
        let Some(preview) = weak.upgrade() else { return glib::Propagation::Stop; };
        if event_scroll.is_stop() {
            smooth.set(0.0);
            return glib::Propagation::Stop;
        }
        let direction = event_scroll.direction();
        let (dx, dy) = match direction {
            gtk::gdk::ScrollDirection::Up => (0.0, -1.0),
            gtk::gdk::ScrollDirection::Down => (0.0, 1.0),
            gtk::gdk::ScrollDirection::Left => (-1.0, 0.0),
            gtk::gdk::ScrollDirection::Right => (1.0, 0.0),
            gtk::gdk::ScrollDirection::Smooth => event_scroll.deltas(),
            _ => (0.0, 0.0),
        };
        let surface = direction == gtk::gdk::ScrollDirection::Smooth
            && event_scroll.unit() == gtk::gdk::ScrollUnit::Surface;
        tracing::trace!(ctrl, shift, dx, dy, "PDF wheel dispatch");
        if !ctrl {
            smooth.set(0.0);
            if let Some(scroller) = preview.picture.upgrade() {
                let (x, y) = scroll_pixels(dx, dy, surface, shift);
                let h = scroller.hadjustment();
                let v = scroller.vadjustment();
                set_scroll(&h, h.value() + x);
                set_scroll(&v, v.value() + y);
            }
            return glib::Propagation::Stop;
        }
        let dy = if direction == gtk::gdk::ScrollDirection::Smooth {
            let delta = if surface { dy / 40.0 } else { dy };
            let total = smooth.get() + delta;
            let steps = total.trunc();
            smooth.set(total - steps);
            steps
        } else { dy };
        if preview.pages.get() > 0 && dy != 0.0 {
            let zoom = wheel_zoom(preview.zoom.get(), dy);
            if zoom != preview.zoom.get() {
                if let Some(slider) = preview.slider.upgrade() {
                    preview.wheel_cursor.set(weak_viewport.upgrade()
                        .and_then(|viewport| event_cursor(event, &viewport)));
                    slider.set_value(zoom as f64);
                    preview.wheel_cursor.set(None);
                }
            }
        }
        // No ordinary scrolling or page navigation while Ctrl is held,
        // including horizontal events and when already at a zoom limit.
        glib::Propagation::Stop
    });
    document.add_controller(scroll);
    preview.begin();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_zoom_keeps_viewport_centre_and_clamps_at_edges() {
        assert_eq!(view_anchor(0.0, 0.0, 800.0, 400.0, 400.0), 0.5);
        assert_eq!(anchor_position(0.5, 0.0, 800.0, 1600.0, 400.0), 400.0);
        assert_eq!(view_anchor(400.0, 0.0, 800.0, 1600.0, 400.0), 0.5);
        assert_eq!(view_anchor(800.0, 0.0, 400.0, 2000.0, 200.0), 0.5);
        assert_eq!(anchor_position(0.5, 0.0, 400.0, 4000.0, 200.0), 1800.0);
        assert_eq!(anchor_position(0.0, 0.0, 400.0, 2000.0, 200.0), 0.0);
        assert_eq!(anchor_position(1.0, 0.0, 400.0, 2000.0, 200.0), 1600.0);
        assert_eq!(anchor_position(0.9, 0.0, 800.0, 400.0, 400.0), 0.0);
    }

    #[test]
    fn pdf_zoom_keeps_the_point_under_the_cursor() {
        let p = view_anchor(300.0, 0.0, 800.0, 1600.0, 600.0);
        assert_eq!(p, 0.5625);
        let offset = anchor_position(p, 0.0, 800.0, 3200.0, 600.0);
        assert_eq!(offset, 1200.0);
        assert_eq!(view_anchor(offset, 0.0, 800.0, 3200.0, 600.0), p);
        let p = view_anchor(0.0, 0.0, 800.0, 400.0, 550.0);
        assert_eq!(p, 0.875);
        assert_eq!(anchor_position(p, 0.0, 800.0, 1600.0, 550.0), 800.0);
        assert_eq!(viewport_offset(Some((600.0, 120.0)), 800.0, 500.0), (600.0, 120.0));
    }

    #[test]
    fn pdf_zoom_round_trip_is_stable_without_layout() {
        let viewport = 640.0;
        let cursor = 380.0;
        let mut extent = 900.0;
        let mut offset = 110.0;
        let initial = offset;
        for next in [990.0, 1080.0, 1800.0, 3600.0, 1800.0, 1080.0, 990.0, 900.0] {
            let point = view_anchor(offset, 0.0, viewport, extent, cursor);
            offset = anchor_position(point, 0.0, viewport, next, cursor);
            extent = next;
        }
        assert!((offset - initial).abs() < 1e-9);
    }

    #[test]
    fn pdf_wheel_scroll_units_and_shift() {
        assert_eq!(scroll_pixels(0.0, 1.0, false, false), (0.0, 48.0));
        assert_eq!(scroll_pixels(0.0, -1.0, false, true), (-48.0, 0.0));
        assert_eq!(scroll_pixels(12.0, -7.0, true, false), (12.0, -7.0));
        assert_eq!(scroll_pixels(1.0, 2.0, false, true), (48.0, 96.0));
    }

    #[test]
    fn pdf_wheel_zoom_uses_slider_range() {
        assert_eq!(wheel_zoom(100, -1.0), 110);
        assert_eq!(wheel_zoom(137, 1.0), 127);
        assert_eq!(wheel_zoom(137, -2.0), 157);
        assert_eq!(wheel_zoom(395, -1.0), 400);
        assert_eq!(wheel_zoom(55, 1.0), 50);
        assert_eq!(wheel_zoom(400, -1.0), 400);
        assert_eq!(wheel_zoom(50, 1.0), 50);
        assert_eq!(wheel_zoom(137, 0.0), 137);
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
