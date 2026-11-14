//! Native full Exchange OAB transport and validation. The GAL decoder and
//! SQLite import remain in oab_decode/oab_cache. The untrusted compressed
//! payload is unpacked by a short-lived instance of this binary, not Python.
use aws_lc_rs::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use curl::easy::{Auth, Easy, HttpVersion};
use quick_xml::{events::Event, Reader};
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    ffi::{c_char, c_int, c_void, CString},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MAX_BOOK: u64 = 256 * 1024 * 1024;
const MAX_XML: u64 = 2 * 1024 * 1024;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub(crate) enum Error {
    // Compatibility with servers that only offer NTLM inside Negotiate.
    LegacyNegotiate,
    Failure(String),
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::Failure(s.to_owned())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Manifest {
    name: String,
    size: u64,
    expanded: u64,
    sha: String,
}

#[derive(Default)]
struct Full {
    name: String,
    size: String,
    expanded: String,
    sha: String,
}

#[derive(Default)]
struct List {
    name: String,
    fulls: Vec<Full>,
}

fn safe_name(name: &str) -> bool {
    name.len() > 4
        && name.to_ascii_lowercase().ends_with(".lzx")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn manifest(data: &[u8]) -> Option<Manifest> {
    if data.is_empty() || data.len() as u64 > MAX_XML {
        return None;
    }
    let mut reader = Reader::from_str(std::str::from_utf8(data).ok()?);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<String> = Vec::new();
    let mut lists: Vec<List> = Vec::new();
    let mut root_seen = false;
    loop {
        match reader.read_event().ok()? {
            Event::Start(e) => {
                stack.push(std::str::from_utf8(e.name().as_ref()).ok()?.to_owned());
                if stack.len() > 32 {
                    return None;
                }
                if stack.len() == 1 {
                    if root_seen || stack[0] != "OAB" {
                        return None;
                    }
                    root_seen = true;
                }
                if stack == ["OAB", "OAL"] {
                    if lists.len() >= 256 {
                        return None;
                    }
                    let mut list = List::default();
                    for attr in e.attributes() {
                        let attr = attr.ok()?;
                        if attr.key.as_ref() == b"name" {
                            list.name = attr.decode_and_unescape_value(reader.decoder()).ok()?.into_owned();
                        }
                    }
                    lists.push(list);
                } else if stack == ["OAB", "OAL", "Full"] {
                    let list = lists.last_mut()?;
                    if list.fulls.len() >= 2 {
                        return None;
                    }
                    let mut full = Full::default();
                    for attr in e.attributes() {
                        let attr = attr.ok()?;
                        let field = match attr.key.as_ref() {
                            b"size" => &mut full.size,
                            b"uncompressedsize" => &mut full.expanded,
                            b"SHA" => &mut full.sha,
                            _ => continue,
                        };
                        *field = attr.decode_and_unescape_value(reader.decoder()).ok()?.into_owned();
                    }
                    list.fulls.push(full);
                }
            }
            Event::Empty(e) => {
                if stack == ["OAB", "OAL"] && e.name().as_ref() == b"Full" {
                    // Count empty Full entries as well: they must not hide a
                    // second ambiguous entry or masquerade as a valid book.
                    let list = lists.last_mut()?;
                    if list.fulls.len() >= 2 {
                        return None;
                    }
                    list.fulls.push(Full::default());
                }
            }
            Event::Text(t) => {
                let text = t.decode().ok()?;
                if stack.is_empty() && !text.trim().is_empty() {
                    return None;
                }
                if stack == ["OAB", "OAL", "Full"] {
                    lists.last_mut()?.fulls.last_mut()?.name.push_str(&quick_xml::escape::unescape(&text).ok()?);
                }
            }
            Event::CData(t) if stack == ["OAB", "OAL", "Full"] => {
                lists.last_mut()?.fulls.last_mut()?.name.push_str(&t.decode().ok()?);
            }
            Event::DocType(_) | Event::GeneralRef(_) => return None,
            Event::End(_) => {
                stack.pop()?;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !root_seen || !stack.is_empty() {
        return None;
    }
    let lists: Vec<List> = lists.into_iter().filter(|l| !l.fulls.is_empty()).collect();
    let default: Vec<&List> = lists.iter().filter(|l| l.name.trim_matches('\\').eq_ignore_ascii_case("default global address list")).collect();
    let selected = if default.len() == 1 {
        default[0]
    } else if lists.len() == 1 {
        &lists[0]
    } else {
        return None;
    };
    if selected.fulls.len() != 1 {
        return None;
    }
    let full = &selected.fulls[0];
    let size = full.size.parse::<u64>().ok()?;
    let expanded = full.expanded.parse::<u64>().ok()?;
    let sha = full.sha.to_ascii_lowercase();
    let name = full.name.trim();
    if !safe_name(name)
        || !(1..=MAX_BOOK).contains(&size)
        || !(1..=MAX_BOOK).contains(&expanded)
        || sha.len() != 40
        || !sha.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some(Manifest { name: name.to_owned(), size, expanded, sha })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes.iter().flat_map(|&b| [HEX[(b >> 4) as usize] as char, HEX[(b & 15) as usize] as char]).collect()
}

fn fingerprint(url: &str, manifest: &Manifest) -> String {
    // Keep compatibility with the existing persisted Python fingerprint.
    format!("{:x}", Sha256::digest(format!("{url}\n{}\n{}", manifest.name, manifest.sha).as_bytes()))
}

fn payload_url(url: &Url, name: &str) -> Option<Url> {
    if !safe_name(name) {
        return None;
    }
    let result = url.join(name).ok()?;
    if result.origin() != url.origin() || result.query().is_some() || result.fragment().is_some() {
        return None;
    }
    Some(result)
}

#[derive(Clone, Copy)]
enum Scheme {
    Ntlm,
    Basic,
}

#[derive(Default)]
struct Reply {
    status: u32,
    challenges: Vec<String>,
}

impl Reply {
    fn has_scheme(&self, scheme: &str) -> bool {
        self.challenges.iter().any(|s| s.split(',').any(|p| p.split_whitespace().next().is_some_and(|w| w.eq_ignore_ascii_case(scheme))))
    }
}

struct Downloaded {
    reply: Reply,
    bytes: u64,
    sha: String,
}

fn curl_error(error: curl::Error) -> Error {
    if error.is_operation_timedout() {
        "OAB request timed out".into()
    } else if error.is_couldnt_connect() || error.is_couldnt_resolve_host() || error.is_couldnt_resolve_proxy() {
        "OAB connection or DNS resolution failed".into()
    } else if error.is_ssl_connect_error() || error.is_peer_failed_verification() || error.is_ssl_certproblem() || error.is_ssl_cacert_badfile() {
        "OAB TLS certificate or handshake failed".into()
    } else {
        "OAB HTTP transport failed".into()
    }
}

struct Session<'a> {
    login: &'a str,
    password: &'a str,
    deadline: Instant,
}

impl Session<'_> {
    // Keep all legs of one NTLM challenge on the same HTTP/1.1 connection.
    // A separate Easy handle per request ensures no auth leaks across hosts.
    fn get(
        &self,
        url: &Url,
        limit: u64,
        sink: &mut impl Write,
        scheme: Option<Scheme>,
    ) -> Result<Downloaded, Error> {
        let remaining = self.deadline.checked_duration_since(Instant::now()).ok_or("OAB request timed out")?;
        if remaining.is_zero() {
            return Err("OAB request timed out".into());
        }
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err("Invalid OAB URL".into());
        }
        let mut easy = Easy::new();
        easy.url(url.as_str()).map_err(curl_error)?;
        easy.proxy("").map_err(curl_error)?;
        easy.follow_location(false).map_err(curl_error)?;
        easy.ssl_verify_peer(true).map_err(curl_error)?;
        easy.ssl_verify_host(true).map_err(curl_error)?;
        easy.http_version(HttpVersion::V11).map_err(curl_error)?;
        easy.connect_timeout(remaining.min(Duration::from_secs(15))).map_err(curl_error)?;
        easy.timeout(remaining.min(Duration::from_secs(60))).map_err(curl_error)?;
        easy.accept_encoding("").map_err(curl_error)?;
        easy.useragent("Lookout Exchange OAB").map_err(curl_error)?;
        if let Some(scheme) = scheme {
            let mut auth = Auth::new();
            match scheme {
                Scheme::Ntlm => { auth.ntlm(true); }
                Scheme::Basic => { auth.basic(true); }
            }
            easy.username(self.login).map_err(curl_error)?;
            easy.password(self.password).map_err(curl_error)?;
            easy.http_auth(&auth).map_err(curl_error)?;
        }
        let reply = RefCell::new(Reply::default());
        let mut header_bytes = 0usize;
        let mut bytes = 0u64;
        let mut digest = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        let mut overflow = false;
        let mut io_failed = false;
        let result = {
            let mut transfer = easy.transfer();
            transfer.header_function(|line| {
                header_bytes += line.len();
                if header_bytes > 64 * 1024 {
                    return false;
                }
                let line = String::from_utf8_lossy(line);
                let mut r = reply.borrow_mut();
                if line.starts_with("HTTP/") {
                    *r = Reply::default();
                    r.status = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                } else if let Some((key, value)) = line.split_once(':') {
                    if key.eq_ignore_ascii_case("WWW-Authenticate") {
                        r.challenges.push(value.trim().to_owned());
                    }
                }
                true
            }).map_err(curl_error)?;
            transfer.write_function(|data| {
                // Do not write an NTLM intermediate response, login page
                // returned with non-200 status, or HTTP redirect body.
                if reply.borrow().status == 200 {
                    if bytes + data.len() as u64 > limit {
                        overflow = true;
                        return Ok(0);
                    }
                    if sink.write_all(data).is_err() {
                        io_failed = true;
                        return Ok(0);
                    }
                    bytes += data.len() as u64;
                    digest.update(data);
                }
                Ok(data.len())
            }).map_err(curl_error)?;
            transfer.perform()
        };
        let mut reply = reply.into_inner();
        reply.status = easy.response_code().map_err(curl_error)?;
        if overflow {
            return Err("OAB integrity check failed".into());
        }
        if io_failed {
            return Err("OAB temporary file write failed".into());
        }
        if let Err(error) = result {
            if !(scheme.is_some() && matches!(reply.status, 401 | 403)) {
                return Err(curl_error(error));
            }
        }
        Ok(Downloaded { reply, bytes, sha: hex(digest.finish().as_ref()) })
    }

    fn fetch(&self, url: &Url, limit: u64, sink: &mut impl Write, stage: &str) -> Result<Downloaded, Error> {
        let mut result = self.get(url, limit, sink, None)?;
        if result.reply.status == 401 {
            let scheme = if result.reply.has_scheme("NTLM") {
                if !curl::Version::get().feature_ntlm() {
                    return Err(Error::LegacyNegotiate);
                }
                Scheme::Ntlm
            } else if result.reply.has_scheme("Negotiate") {
                return Err(Error::LegacyNegotiate);
            } else if result.reply.has_scheme("Basic") {
                Scheme::Basic
            } else {
                return Err("OAB authentication rejected".into());
            };
            // The anonymous 401 contributed no bytes to the sink.
            result = self.get(url, limit, sink, Some(scheme))?;
        }
        match result.reply.status {
            200 => Ok(result),
            401 | 403 => Err("OAB authentication rejected".into()),
            301 | 302 | 303 | 307 | 308 => Err("OAB server returned a redirect".into()),
            status => Err(Error::Failure(format!("OAB {stage} failed (HTTP {status})"))),
        }
    }
}

pub(crate) fn download(
    url: &str,
    login: &str,
    password: &str,
    known: Option<&str>,
    dir: &Path,
) -> Result<Option<String>, Error> {
    if !crate::oab_sync::valid_url(url) {
        return Err("Invalid OAB URL".into());
    }
    let endpoint = Url::parse(url).map_err(|_| Error::from("Invalid OAB URL"))?;
    let session = Session { login, password, deadline: Instant::now() + TOTAL_TIMEOUT };
    let mut xml = Vec::new();
    session.fetch(&endpoint, MAX_XML, &mut xml, "manifest")?;
    let book = manifest(&xml).ok_or("Invalid or ambiguous OAB manifest")?;
    let next = fingerprint(url, &book);
    if known == Some(next.as_str()) {
        return Ok(None);
    }
    let payload = payload_url(&endpoint, &book.name).ok_or("Invalid OAB download URL")?;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.join("full.lzx"))
        .map_err(|_| "Cannot create private OAB download file")?;
    let downloaded = session.fetch(&payload, book.size, &mut file, "download")?;
    if downloaded.bytes != book.size || downloaded.sha != book.sha {
        return Err("OAB integrity check failed".into());
    }
    file.flush().map_err(|_| "OAB temporary file write failed")?;
    drop(file);
    unpack_in_worker(dir, book.expanded, session.deadline)?;
    if fs::metadata(dir.join("full.oab")).map_err(|_| "OAB decompression failed")?.len() != book.expanded {
        return Err("OAB integrity check failed".into());
    }
    Ok(Some(next))
}

fn unpack_in_worker(dir: &Path, expanded: u64, deadline: Instant) -> Result<(), Error> {
    let executable = std::env::current_exe().map_err(|_| "Cannot locate OAB decompression worker")?;
    let mut child = Command::new(executable)
        .arg("--unpack-oab-internal")
        .arg(expanded.to_string())
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot start OAB decompression worker")?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) if status.code() == Some(2) => return Err("Install libmspack (libmspack0t64 on Ubuntu 24.04/26.04)".into()),
            Ok(Some(_)) => return Err("OAB decompression failed".into()),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("OAB request timed out".into());
            }
        }
    }
}

// libmspack's published C ABI: the first member of msoab_decompressor
// is the full-book decompress function. It is obtained from the library
// constructor and released through its matching destructor.
#[repr(C)]
struct MspackOab {
    decompress: unsafe extern "C" fn(*mut MspackOab, *const c_char, *const c_char) -> c_int,
}
type Create = unsafe extern "C" fn(*mut c_void) -> *mut MspackOab;
type Destroy = unsafe extern "C" fn(*mut MspackOab);

struct Library(*mut c_void);

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: handle was returned by a successful dlopen.
        unsafe { libc::dlclose(self.0); }
    }
}

// This entry point is called before GTK or application state initialization,
// only in the disposable unpack worker. It has no password or network
// request. RLIMIT_FSIZE bounds the decompressor even on malformed data.
pub(crate) fn unpack_worker(expanded: u64) -> i32 {
    if !(1..=MAX_BOOK).contains(&expanded) {
        return 1;
    }
    let Ok(input) = fs::symlink_metadata("full.lzx") else { return 1 };
    if !input.is_file() || input.len() == 0 || input.len() > MAX_BOOK || fs::symlink_metadata("full.oab").is_ok() {
        return 1;
    }
    let limit = libc::rlimit { rlim_cur: expanded as libc::rlim_t, rlim_max: expanded as libc::rlim_t };
    // SAFETY: limit points to a valid rlimit; changes apply only to this
    // child process. Use the private scratch directory and private output.
    unsafe {
        libc::umask(0o077);
        if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
            return 1;
        }
    }
    let name = CString::new("libmspack.so.0").expect("static library name");
    // SAFETY: NUL-terminated library name; symbols are resolved from this
    // exact handle and the library stays alive until the object is freed.
    unsafe {
        let handle = libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            return 2;
        }
        let _library = Library(handle);
        let create = libc::dlsym(handle, c"mspack_create_oab_decompressor".as_ptr());
        let destroy = libc::dlsym(handle, c"mspack_destroy_oab_decompressor".as_ptr());
        if create.is_null() || destroy.is_null() {
            return 2;
        }
        let create: Create = std::mem::transmute(create);
        let destroy: Destroy = std::mem::transmute(destroy);
        let ptr = create(std::ptr::null_mut());
        if ptr.is_null() {
            return 1;
        }
        let status = ((*ptr).decompress)(ptr, c"full.lzx".as_ptr(), c"full.oab".as_ptr());
        destroy(ptr);
        if status == 0 { 0 } else { 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn full(name: &str) -> String {
        format!(r#"<Full size="3" uncompressedsize="5" SHA="{SHA}">{name}</Full>"#)
    }

    #[test]
    fn native_oab_manifest_selects_default_list() {
        let xml = format!(r#"<OAB><OAL name="Other">{}</OAL><OAL name="\Default Global Address List">{}</OAL></OAB>"#, full("other.lzx"), full("full.lzx"));
        let m = manifest(xml.as_bytes()).unwrap();
        assert_eq!(m, Manifest { name: "full.lzx".into(), size: 3, expanded: 5, sha: SHA.into() });
        let url = Url::parse("https://ex2.example.test/OAB/guid/oab.xml").unwrap();
        assert_eq!(payload_url(&url, &m.name).unwrap().as_str(), "https://ex2.example.test/OAB/guid/full.lzx");
    }

    #[test]
    fn native_oab_rejects_ambiguous_or_unsafe_manifest() {
        for xml in [
            format!("<OAB><OAL>{}{}</OAL></OAB>", full("one.lzx"), full("two.lzx")),
            format!("<OAB><OAL>{}</OAL><OAL>{}</OAL></OAB>", full("one.lzx"), full("two.lzx")),
            format!("<OAB><OAL>{}<Full/></OAL></OAB>", full("one.lzx")),
            format!("<OAB><OAL>{}</OAL></OAB>", full("../full.lzx")),
            format!("<OAB><OAL>{}</OAL></OAB>", full("https://evil.test/full.lzx")),
            format!("<OAB><OAL>{}</OAL></OAB>", full("a.lzx").replace("size=\"3\"", "size=\"0\"")),
            format!("<OAB><OAL>{}</OAL></OAB>", full("a.lzx").replace(SHA, "bad")),
            format!("<!DOCTYPE OAB><OAB><OAL>{}</OAL></OAB>", full("a.lzx")),
            "<html>login page</html>".into(),
        ] {
            assert!(manifest(xml.as_bytes()).is_none(), "{xml}");
        }
    }

    #[test]
    fn native_oab_legacy_sha_and_fingerprint() {
        let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        context.update(b"a");
        context.update(b"bc");
        assert_eq!(hex(context.finish().as_ref()), "a9993e364706816aba3e25717850c26c9cd0d89d");
        let xml = format!("<OAB><OAL>{}</OAL></OAB>", full("full.lzx"));
        let book = manifest(xml.as_bytes()).unwrap();
        assert_eq!(fingerprint("https://ex2.example.test/oab.xml", &book), format!("{:x}", Sha256::digest(format!("https://ex2.example.test/oab.xml\nfull.lzx\n{SHA}").as_bytes())));
    }

    #[test]
    fn native_oab_no_cross_origin_payload() {
        let url = Url::parse("https://ex2.example.test/OAB/id/oab.xml").unwrap();
        assert!(payload_url(&url, "https://evil.test/a.lzx").is_none());
        assert!(payload_url(&url, "../a.lzx").is_none());
        assert!(payload_url(&url, "a.lzx?x=1").is_none());
        assert!(payload_url(&url, "a.lzx").is_some());
    }
}
