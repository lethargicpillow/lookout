//! Convert untrusted Office attachments to a temporary PDF and hand it to the
//! existing PDF viewer. The original bytes remain in AttachmentPreview for
//! Open/Save. Never fall back to an unsandboxed office process.

use gtk::{glib, prelude::*};
use std::fs;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_PDF_BYTES: u64 = 64 * 1024 * 1024;
const SOFFICE: &str = "/usr/bin/libreoffice";
const BWRAP: &str = "/usr/bin/bwrap";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OfficeKind { Docx, Xlsx, Doc, Xls }

impl OfficeKind {
    fn extension(self) -> &'static str {
        match self { Self::Docx => "docx", Self::Xlsx => "xlsx", Self::Doc => "doc", Self::Xls => "xls" }
    }
    fn filter(self) -> &'static str {
        match self { Self::Docx | Self::Doc => "pdf:writer_pdf_Export", Self::Xlsx | Self::Xls => "pdf:calc_pdf_Export" }
    }
}

// Highest macro security, in a fresh profile with no trusted locations.
// Network and access to the user's home are independently denied by bwrap.
const PROFILE_SETTINGS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry">
  <item oor:path="/org.openoffice.Office.Common/Security/Scripting">
    <prop oor:name="MacroSecurityLevel" oor:op="fuse"><value>3</value></prop>
  </item>
</oor:items>"#;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("lookout-office-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Build a fresh filesystem and PID/network namespace. No user home,
/// session bus, display socket, host /run, or host /tmp is mounted.
/// Only the private conversion directory is writable on the host.
fn sandbox_command(work: &Path, kind: OfficeKind) -> Command {
    let mut cmd = Command::new(BWRAP);
    cmd.args([
        "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/etc/fonts", "/etc/fonts",
        "--ro-bind-try", "/etc/libreoffice", "/etc/libreoffice",
        "--ro-bind-try", "/etc/alternatives", "/etc/alternatives",
        "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--ro-bind-try", "/etc/passwd", "/etc/passwd",
        "--ro-bind-try", "/etc/group", "/etc/group",
        "--ro-bind-try", "/var/cache/fontconfig", "/var/cache/fontconfig",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--dir", "/run", "--dir", "/home", "--dir", "/var/tmp",
        "--bind",
    ]).arg(work).args([
        "/work", "--chdir", "/work",
        "--setenv", "HOME", "/work/home",
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "XDG_CONFIG_HOME", "/work/home/.config",
        "--setenv", "XDG_CACHE_HOME", "/work/home/.cache",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "SAL_USE_VCLPLUGIN", "svp",
        "--setenv", "SAL_DISABLESKIA", "1",
        "--setenv", "SAL_DISABLEGL", "1",
        "--",
        SOFFICE, "-env:UserInstallation=file:///work/profile",
        "--headless", "--nologo", "--nodefault", "--nofirststartwizard", "--norestore",
        "--convert-to", kind.filter(), "--outdir", "/work/out",
    ]).arg(format!("/work/attachment.{}", kind.extension()));
    cmd
}

// Refuse to execute the converter if the actual cgroup limits are absent.
// A systemd installation without a delegated memory controller must not
// silently turn a mail preview into an unbounded LibreOffice process.
// All arguments are passed as positional parameters, never interpolated.
const CHECK_LIMITS: &str = r#"
IFS=: read -r hierarchy controllers group < /proc/self/cgroup || exit 125
[ "$hierarchy" = 0 ] || exit 125
read -r max < "/sys/fs/cgroup$group/memory.max" || exit 125
read -r swap < "/sys/fs/cgroup$group/memory.swap.max" || exit 125
[ "$max" -le 2147483648 ] 2>/dev/null || exit 125
[ "$swap" = 0 ] || exit 125
exec "$@"
"#;

fn limited_command(work: &Path, kind: OfficeKind, unit: &str) -> Command {
    let sandbox = sandbox_command(work, kind);
    let mut cmd = Command::new(SYSTEMD_RUN);
    cmd.args(["--user", "--wait", "--pipe", "--collect", "--quiet", "--unit"])
        .arg(unit)
        .args([
            "--property=MemoryHigh=1536M",
            "--property=MemoryMax=2G",
            "--property=MemorySwapMax=0",
            "--property=TasksMax=128",
            "--property=OOMPolicy=kill",
            "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=60s",
            "--property=TimeoutStopSec=3s",
            "--", "/bin/sh", "-c", CHECK_LIMITS, "lookout-office",
        ])
        .arg(sandbox.get_program())
        .args(sandbox.get_args());
    cmd
}

fn stop_conversion(unit: &str) {
    let _ = Command::new(SYSTEMCTL)
        .args(["--user", "stop", unit])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .status();
}

/// Extension and MIME are routing hints, not proof of an Office document.
/// Inspect only the ZIP central directory; do not inflate document contents
/// in the mail process. Actual parsing is confined to the limited sandbox.
fn validate_container(bytes: &[u8], kind: OfficeKind) -> Result<(), String> {
    const OLE: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
    let invalid = || "The attachment is not a supported Office document, or is damaged or encrypted. Use Open or Save.".to_string();
    let required = match kind {
        OfficeKind::Doc | OfficeKind::Xls => {
            return if bytes.starts_with(OLE) { Ok(()) } else { Err(invalid()) };
        }
        OfficeKind::Docx => "word/document.xml",
        OfficeKind::Xlsx => "xl/workbook.xml",
    };
    let archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|_| invalid())?;
    // Very large central directories are not useful for a preview.
    if archive.len() > 10_000 { return Err(invalid()); }
    let mut has_manifest = false;
    let mut has_document = false;
    for name in archive.file_names() {
        let name = name.map_err(|_| invalid())?;
        if name == "[Content_Types].xml" { has_manifest = true; }
        if name == required { has_document = true; }
        if name.to_ascii_lowercase().ends_with("vbaproject.bin") {
            return Err("Macro-enabled Office documents are not supported in preview. Use Open or Save.".into());
        }
    }
    if has_manifest && has_document { Ok(()) } else { Err(invalid()) }
}

fn convert(bytes: &[u8], kind: OfficeKind, cancelled: &AtomicBool) -> Result<Vec<u8>, String> {
    validate_container(bytes, kind)?;
    if !Path::new(SOFFICE).is_file() {
        return Err("Office preview requires LibreOffice Writer and Calc. Use Open or Save.".into());
    }
    if !Path::new(BWRAP).is_file() {
        return Err("Office preview requires Bubblewrap (install bubblewrap). Use Open or Save.".into());
    }
    if !Path::new(SYSTEMD_RUN).is_file() || !Path::new(SYSTEMCTL).is_file() {
        return Err("Office preview requires systemd user resource limits. Use Open or Save.".into());
    }
    let scratch = Scratch::new().map_err(|_| "Could not create a private conversion directory.".to_string())?;
    let prepare = || -> std::io::Result<()> {
        fs::create_dir(scratch.0.join("home"))?;
        fs::create_dir(scratch.0.join("out"))?;
        fs::create_dir_all(scratch.0.join("profile/user"))?;
        fs::write(scratch.0.join("profile/user/registrymodifications.xcu"), PROFILE_SETTINGS)?;
        fs::write(scratch.0.join(format!("attachment.{}", kind.extension())), bytes)?;
        Ok(())
    };
    prepare().map_err(|_| "Could not prepare the office attachment.".to_string())?;

    let unit = format!("lookout-office-{}.service", uuid::Uuid::new_v4());
    let mut child = limited_command(&scratch.0, kind, &unit)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|_| "Could not start the isolated office converter.".to_string())?;
    let start = Instant::now();
    loop {
        if cancelled.load(Ordering::Relaxed) || start.elapsed() >= TIMEOUT {
            stop_conversion(&unit);
            let _ = child.kill();
            let _ = child.wait();
            return Err("Office preview cancelled or timed out. Use Open or Save.".into());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return Err("Office conversion failed or exceeded its resource limit. Check LibreOffice, Bubblewrap and systemd user memory limits, or use Open or Save.".into()),
            Ok(None) => std::thread::sleep(Duration::from_millis(40)),
            Err(_) => {
                stop_conversion(&unit);
                let _ = child.kill();
                let _ = child.wait();
                return Err("Office conversion stopped unexpectedly.".into());
            }
        }
    }

    let path = scratch.0.join("out/attachment.pdf");
    let file = fs::File::open(path).map_err(|_| "LibreOffice did not produce a PDF. The document may be protected, damaged or unsupported.".to_string())?;
    let mut pdf = Vec::new();
    file.take(MAX_PDF_BYTES + 1).read_to_end(&mut pdf)
        .map_err(|_| "Could not read the converted document.".to_string())?;
    if pdf.len() as u64 > MAX_PDF_BYTES || !pdf.starts_with(b"%PDF-") {
        return Err("The converted document is too large or is not a valid PDF. Use Open or Save.".into());
    }
    Ok(pdf)
}

pub(super) fn show(content: &gtk::Box, bytes: &[u8], kind: OfficeKind) {
    // Closing or replacing the preview cancels its process. Minimize does
    // not unmap the box on every backend, so only cancel on destruction or
    // on window close rather than on ordinary visibility changes.
    super::preview_status(content, "Preparing office document…");
    let cancelled = Arc::new(AtomicBool::new(false));
    if let Some(window) = content.root().and_downcast::<gtk::Window>() {
        let flag = cancelled.clone();
        window.connect_close_request(move |_| {
            flag.store(true, Ordering::Relaxed);
            glib::Propagation::Proceed
        });
    }
    let bytes = bytes.to_vec();
    let flag = cancelled.clone();
    let (tx, rx) = async_channel::bounded(1);
    let started = std::thread::Builder::new().name("lookout-office-preview".into()).spawn(move || {
        let _ = tx.send_blocking(convert(&bytes, kind, &flag));
    });
    if started.is_err() {
        super::preview_status(content, "Could not start office preview worker. Use Open or Save.");
        return;
    }
    let weak = content.downgrade();
    glib::spawn_future_local(async move {
        let result = rx.recv().await.unwrap_or_else(|_| Err("Office preview worker stopped.".into()));
        if cancelled.load(Ordering::Relaxed) { return; }
        let Some(content) = weak.upgrade() else { return; };
        match result {
            Ok(pdf) => {
                while let Some(child) = content.first_child() { content.remove(&child); }
                super::pdf_preview::show(&content, &pdf);
            }
            Err(message) => super::preview_status(&content, &message),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn office_conversion_has_mandatory_memory_and_runtime_limits() {
        let cmd = limited_command(Path::new("/tmp/lookout-test"), OfficeKind::Docx, "lookout-test.service");
        assert_eq!(cmd.get_program(), SYSTEMD_RUN);
        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        for required in ["--user", "--property=MemoryMax=2G", "--property=MemorySwapMax=0", "--property=OOMPolicy=kill", "--property=KillMode=control-group", "--property=RuntimeMaxSec=60s", CHECK_LIMITS, BWRAP, "SAL_DISABLESKIA", "SAL_DISABLEGL"] {
            assert!(args.iter().any(|a| a == required), "missing {required}");
        }
    }

    #[test]
    fn office_container_check_distinguishes_documents_from_ordinary_archives() {
        use std::io::Write;
        fn package(entries: &[&str]) -> Vec<u8> {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            for &entry in entries {
                writer.start_file(entry, zip::write::SimpleFileOptions::default()).unwrap();
                writer.write_all(b"fixture").unwrap();
            }
            writer.finish().unwrap().into_inner()
        }
        let docx = package(&["[Content_Types].xml", "word/document.xml"]);
        let xlsx = package(&["[Content_Types].xml", "xl/workbook.xml"]);
        let macro_doc = package(&["[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"]);
        assert!(validate_container(&docx, OfficeKind::Docx).is_ok());
        assert!(validate_container(&xlsx, OfficeKind::Xlsx).is_ok());
        assert!(validate_container(&docx, OfficeKind::Xlsx).is_err());
        assert!(validate_container(&package(&["notes.txt"]), OfficeKind::Docx).is_err());
        assert!(validate_container(&macro_doc, OfficeKind::Docx).is_err());
        assert!(validate_container(b"not a document", OfficeKind::Doc).is_err());
    }

    #[test]
    fn office_sandbox_keeps_documents_isolated() {
        for (kind, filter, extension) in [
            (OfficeKind::Docx, "pdf:writer_pdf_Export", "docx"),
            (OfficeKind::Xlsx, "pdf:calc_pdf_Export", "xlsx"),
            (OfficeKind::Doc, "pdf:writer_pdf_Export", "doc"),
            (OfficeKind::Xls, "pdf:calc_pdf_Export", "xls"),
        ] {
            let cmd = sandbox_command(Path::new("/tmp/lookout-test"), kind);
            assert_eq!(cmd.get_program(), BWRAP);
            let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
            for required in ["--unshare-all", "--clearenv", "--die-with-parent", filter, "-env:UserInstallation=file:///work/profile"] {
                assert!(args.iter().any(|a| a == required), "missing {required}");
            }
            assert!(args.iter().any(|a| a == &format!("/work/attachment.{extension}")));
            assert!(!args.iter().any(|a| a == "--share-net"));
            assert!(PROFILE_SETTINGS.contains("<value>3</value>"));
        }
    }
}
