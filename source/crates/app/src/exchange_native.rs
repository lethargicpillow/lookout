//! Exchange POX discovery. Rust owns discovery policy, XML parsing, trust
//! boundaries and candidate selection. libcurl owns the connection-bound
//! NTLM handshake (including TLS channel bindings), not a subprocess.
use super::{domain, Discovery};
use curl::easy::{Auth, Easy, HttpVersion, List};
use quick_xml::{events::Event, Reader};
use reqwest::Url;
use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    time::{Duration, Instant},
};

const PATH: &str = "/autodiscover/autodiscover.xml";
const LIMIT: usize = 512 * 1024;
const AUTH_ERROR: &str = "Exchange rejected the password. Check your credentials before retrying.";
const NOT_FOUND: &str = "Autodiscover could not locate your mailbox. Check network/VPN access and your organization's Autodiscover configuration.";

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Authentication,
    NotFound,
    InvalidAddress,
    Transport(&'static str),
}

impl Error {
    pub(super) fn message(&self) -> &'static str {
        match self {
            Self::Authentication => AUTH_ERROR,
            Self::NotFound => NOT_FOUND,
            Self::InvalidAddress => "Enter a valid email address",
            Self::Transport(message) => message,
        }
    }
}

fn secure_url(value: &str) -> Option<Url> {
    if value.is_empty()
        || value.chars().any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        || !value.starts_with("https://")
    {
        return None;
    }
    // Even an empty userinfo component is not a valid server endpoint.
    if value[8..].split('/').next()?.contains('@') {
        return None;
    }
    let u = Url::parse(value).ok()?;
    let host = u.host_str()?;
    domain(&format!("x@{host}"))?;
    if u.scheme() != "https"
        || u.port_or_known_default() != Some(443)
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_some()
    {
        return None;
    }
    Some(u)
}

fn related(host: &str, original: &str) -> bool {
    host == original || host.ends_with(&format!(".{original}"))
}

fn cloud(host: &str) -> bool {
    matches!(
        host,
        "autodiscover.outlook.com"
            | "autodiscover-s.outlook.com"
            | "outlook.office365.com"
            | "outlook.office.com"
            | "login.microsoftonline.com"
    )
}

fn candidates(host: &str) -> Vec<Url> {
    [
        format!("https://{host}{PATH}"),
        format!("https://autodiscover.{host}{PATH}"),
    ]
    .iter()
    .filter_map(|s| secure_url(s))
    .collect()
}

fn manifest_url(value: &str) -> Option<Url> {
    let mut u = secure_url(value.trim())?;
    let path = u.path().to_owned();
    if path.to_ascii_lowercase().ends_with("/oab.xml") {
        return Some(u);
    }
    if path.ends_with('/')
        || path
            .rsplit('/')
            .next()
            .is_some_and(|last| uuid::Uuid::parse_str(last).is_ok())
    {
        u.set_path(&format!("{}/oab.xml", path.trim_end_matches('/')));
        return Some(u);
    }
    None
}

#[derive(Default, Debug)]
struct Protocol {
    kind: String,
    ews: String,
    as_url: String,
    oab: String,
}

impl Protocol {
    fn priority(&self) -> u8 {
        match self.kind.trim().to_ascii_uppercase().as_str() {
            "EXPR" => 0,
            "EXHTTP" => 1,
            "EXCH" => 2,
            _ => 3,
        }
    }

    fn ews_url(&self) -> Option<Url> {
        [&self.ews, &self.as_url]
            .into_iter()
            .filter_map(|s| secure_url(s.trim()))
            .find(|u| u.path().eq_ignore_ascii_case("/ews/exchange.asmx"))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Pox {
    Exchange { ews: Url, oab: Vec<Url> },
    Cloud,
    RedirectAddress(String),
    RedirectUrl(String),
}

fn oab_candidates(protocols: &[Protocol], selected: usize, ews: &Url) -> Vec<Url> {
    let mut published = Vec::new();
    let mut other = Vec::new();
    for i in std::iter::once(selected).chain((0..protocols.len()).filter(|i| *i != selected)) {
        let p = &protocols[i];
        let Some(url) = manifest_url(&p.oab) else {
            continue;
        };
        if i == selected
            || p.kind.trim().eq_ignore_ascii_case("EXPR")
            || (p.kind.trim().eq_ignore_ascii_case("EXHTTP") && url.host_str() == ews.host_str())
        {
            published.push(url);
        } else {
            other.push(url);
        }
    }

    // An internal published GUID path may be reachable on the advertised
    // external EWS origin. This is only a candidate until its manifest GET
    // succeeds. Never invent a hostname or a mailbox GUID.
    let mut derived: Vec<Url> = published
        .iter()
        .chain(&other)
        .filter(|url| {
            url.path().to_ascii_lowercase().starts_with("/oab/")
                && url.host_str() != ews.host_str()
        })
        .map(|url| {
            let mut candidate = ews.clone();
            candidate.set_path(url.path());
            candidate
        })
        .collect();
    derived.sort_by_key(|u| u.path().eq_ignore_ascii_case("/oab/oab.xml"));
    let mut seen = HashSet::new();
    published
        .into_iter()
        .chain(derived)
        .chain(other)
        .filter(|url| seen.insert(url.clone()))
        .take(8)
        .collect()
}

// Preserve protocol block identity: EwsUrl/ASUrl and OABUrl must not be
// accidentally paired across EXCH/EXPR/EXHTTP blocks.
fn parse(data: &[u8]) -> Option<Pox> {
    if data.len() > LIMIT {
        return None;
    }
    let xml = std::str::from_utf8(data).ok()?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<String> = Vec::new();
    let mut protocols: Vec<Protocol> = Vec::new();
    let mut action = String::new();
    let mut redirect_address = String::new();
    let mut redirect_url = String::new();
    let mut online = String::new();
    let mut account_seen = false;
    loop {
        match reader.read_event().ok()? {
            Event::Start(e) => {
                stack.push(std::str::from_utf8(e.local_name().as_ref()).ok()?.to_owned());
                if stack.len() > 32 {
                    return None;
                }
                if stack == ["Autodiscover", "Response", "Account"] {
                    if account_seen {
                        return None;
                    }
                    account_seen = true;
                }
                if stack == ["Autodiscover", "Response", "Account", "Protocol"] {
                    if protocols.len() >= 128 {
                        return None;
                    }
                    protocols.push(Protocol::default());
                }
            }
            Event::Text(t) => {
                let decoded = t.decode().ok()?;
                let text = quick_xml::escape::unescape(&decoded).ok()?;
                let path: Vec<&str> = stack.iter().map(String::as_str).collect();
                let target = match path.as_slice() {
                    ["Autodiscover", "Response", "Account", "Action"] => &mut action,
                    ["Autodiscover", "Response", "Account", "RedirectAddr"] => &mut redirect_address,
                    ["Autodiscover", "Response", "Account", "RedirectUrl"] => &mut redirect_url,
                    ["Autodiscover", "Response", "Account", "MicrosoftOnline"] => &mut online,
                    ["Autodiscover", "Response", "Account", "Protocol", field] => {
                        let p = protocols.last_mut()?;
                        match *field {
                            "Type" => &mut p.kind,
                            "EwsUrl" => &mut p.ews,
                            "ASUrl" => &mut p.as_url,
                            "OABUrl" => &mut p.oab,
                            _ => continue,
                        }
                    }
                    _ => continue,
                };
                target.push_str(&text);
            }
            // Unknown XML entities must not be expanded or reinterpreted.
            Event::DocType(_) => return None,
            Event::End(_) => {
                stack.pop()?;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !account_seen || !stack.is_empty() {
        return None;
    }
    match action.trim().to_ascii_lowercase().as_str() {
        "redirectaddr" => return Some(Pox::RedirectAddress(redirect_address.trim().to_owned())),
        "redirecturl" => return Some(Pox::RedirectUrl(redirect_url.trim().to_owned())),
        "" | "settings" => {}
        _ => return None,
    }
    if online.trim().eq_ignore_ascii_case("true") {
        return Some(Pox::Cloud);
    }
    protocols.sort_by_key(Protocol::priority);
    for (i, protocol) in protocols.iter().enumerate() {
        if let Some(ews) = protocol.ews_url() {
            if ews.host_str().is_some_and(cloud) {
                return Some(Pox::Cloud);
            }
            let oab = oab_candidates(&protocols, i, &ews);
            return Some(Pox::Exchange { ews, oab });
        }
    }
    None
}

fn valid_manifest(data: &[u8]) -> bool {
    if data.is_empty() || data.len() > LIMIT {
        return false;
    }
    let Ok(xml) = std::str::from_utf8(data) else {
        return false;
    };
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<String> = Vec::new();
    let mut full_attributes = false;
    let mut valid = false;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                stack.push(String::from_utf8_lossy(e.name().as_ref()).into_owned());
                if stack.len() > 32 {
                    return false;
                }
                if stack == ["OAB", "OAL", "Full"] {
                    let mut size = false;
                    let mut sha = false;
                    for attribute in e.attributes() {
                        let Ok(a) = attribute else { return false };
                        match a.key.as_ref() {
                            b"size" => size = !a.value.is_empty(),
                            b"SHA" => sha = !a.value.is_empty(),
                            _ => {}
                        }
                    }
                    full_attributes = size && sha;
                }
            }
            Ok(Event::Text(t)) if stack == ["OAB", "OAL", "Full"] && full_attributes => {
                if let Ok(name) = t.decode() {
                    let name = name.trim();
                    valid |= name.to_ascii_lowercase().ends_with(".lzx")
                        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
                }
            }
            Ok(Event::End(_)) => {
                if stack.pop().is_none() {
                    return false;
                }
            }
            Ok(Event::Eof) => return valid && stack.is_empty(),
            Ok(Event::DocType(_)) | Err(_) => return false,
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scheme {
    Ntlm,
    Basic,
    NegotiateOnly,
}

#[derive(Default)]
struct Response {
    status: u32,
    challenges: Vec<String>,
    location: Option<String>,
    body: Vec<u8>,
}

impl crate::exchange_negotiate::Reply for Response {
    fn status(&self) -> u32 { self.status }
    fn challenges(&self) -> &[String] { &self.challenges }
}

impl Response {
    fn has_scheme(&self, scheme: &str) -> bool {
        self.challenges.iter().any(|value| {
            value.split(',').any(|part| {
                part.split_whitespace()
                    .next()
                    .is_some_and(|word| word.eq_ignore_ascii_case(scheme))
            })
        })
    }

    fn scheme(&self) -> Option<Scheme> {
        if self.has_scheme("NTLM") {
            Some(Scheme::Ntlm)
        } else if self.has_scheme("Negotiate") {
            Some(Scheme::NegotiateOnly)
        } else if self.has_scheme("Basic") {
            Some(Scheme::Basic)
        } else {
            None
        }
    }

    fn cloud_challenge(&self) -> bool {
        self.has_scheme("Bearer")
            && self.challenges.iter().any(|s| {
                let s = s.to_ascii_lowercase();
                s.contains("microsoftonline.com") || s.contains("outlook.com")
            })
    }
}

struct Credentials<'a> {
    scheme: Scheme,
    login: &'a str,
    password: &'a str,
}

trait Transport {
    fn request(
        &mut self,
        url: &Url,
        body: Option<&str>,
        credentials: Option<Credentials<'_>>,
    ) -> Option<Response>;

    fn srv(&mut self, host: &str) -> Vec<Url>;

    fn supports_ntlm(&self) -> bool;
    fn take_error(&mut self) -> Option<&'static str> { None }
}

struct CurlTransport {
    deadline: Instant,
    error: Option<&'static str>,
}

impl Transport for CurlTransport {
    fn request(
        &mut self,
        url: &Url,
        body: Option<&str>,
        credentials: Option<Credentials<'_>>,
    ) -> Option<Response> {
        let remaining = self.deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        // The sole HTTP exception is the anonymous redirect-only fallback.
        // Never send email addresses or credentials over that transport.
        if credentials.is_some() || body.is_some() {
            secure_url(url.as_str())?;
        }
        let mut easy = Easy::new();
        easy.url(url.as_str()).ok()?;
        easy.proxy("").ok()?;
        easy.follow_location(false).ok()?;
        easy.ssl_verify_peer(true).ok()?;
        easy.ssl_verify_host(true).ok()?;
        easy.http_version(HttpVersion::V11).ok()?;
        easy.connect_timeout(remaining.min(Duration::from_secs(5))).ok()?;
        easy.timeout(remaining.min(Duration::from_secs(10))).ok()?;
        easy.useragent("Lookout Exchange Autodiscover").ok()?;
        if let Some(xml) = body {
            easy.post(true).ok()?;
            easy.post_fields_copy(xml.as_bytes()).ok()?;
            let mut headers = List::new();
            headers.append("Content-Type: text/xml; charset=utf-8").ok()?;
            headers.append("Expect:").ok()?;
            easy.http_headers(headers).ok()?;
        }
        let authenticated = credentials.is_some();
        let negotiate = credentials.as_ref().filter(|c| c.scheme == Scheme::NegotiateOnly);
        if let Some(creds) = credentials.as_ref().filter(|c| c.scheme != Scheme::NegotiateOnly) {
            let mut auth = Auth::new();
            match creds.scheme {
                Scheme::Ntlm => {
                    auth.ntlm(true);
                }
                Scheme::Basic => {
                    auth.basic(true);
                }
                Scheme::NegotiateOnly => return None,
            }
            // libcurl performs all NTLM legs on one HTTP/1.1 connection.
            easy.username(creds.login).ok()?;
            easy.password(creds.password).ok()?;
            easy.http_auth(&auth).ok()?;
        }
        let mut once = |easy: &mut Easy| -> Result<Response, ()> {
            let response = RefCell::new(Response::default());
            let mut header_bytes = 0usize;
            let result = {
                let mut transfer = easy.transfer();
                transfer
                    .header_function(|line| {
                        header_bytes += line.len();
                        if header_bytes > 64 * 1024 {
                            return false;
                        }
                        let line = String::from_utf8_lossy(line);
                        let mut r = response.borrow_mut();
                        if line.starts_with("HTTP/") {
                            // Discard the headers/body of intermediate NTLM
                            // challenges and informational responses.
                            *r = Response::default();
                            r.status = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                        } else if let Some((key, value)) = line.split_once(':') {
                            if key.eq_ignore_ascii_case("WWW-Authenticate") {
                                r.challenges.push(value.trim().to_owned());
                            } else if key.eq_ignore_ascii_case("Location") {
                                r.location = Some(value.trim().to_owned());
                            }
                        }
                        true
                    })
                    .map_err(|_| ())?;
                transfer
                    .write_function(|data| {
                        let mut r = response.borrow_mut();
                        if r.status == 200 {
                            if r.body.len() + data.len() > LIMIT {
                                return Ok(0);
                            }
                            r.body.extend_from_slice(data);
                        }
                        Ok(data.len())
                    })
                    .map_err(|_| ())?;
                transfer.perform()
            };
            let mut response = response.into_inner();
            response.status = easy.response_code().map_err(|_| ())?;
            if result.is_err() && !(authenticated && negotiate.is_none() && matches!(response.status, 401 | 403)) {
                return Err(());
            }
            Ok(response)
        };
        if let Some(creds) = negotiate {
            let host = url.host_str()?;
            match crate::exchange_negotiate::perform(&mut easy, host, creds.login, creds.password, body.is_some(), self.deadline.min(Instant::now() + Duration::from_secs(10)), &mut once) {
                Ok(reply) => Some(reply),
                Err(crate::exchange_negotiate::Error::Protocol(message)) => { self.error = Some(message); None },
                Err(crate::exchange_negotiate::Error::Transport(())) => { self.error = Some("Exchange Negotiate HTTP transport failed"); None },
            }
        } else { once(&mut easy).ok() }
    }

    fn srv(&mut self, host: &str) -> Vec<Url> {
        if Instant::now() >= self.deadline {
            return Vec::new();
        }
        lookup_srv(host)
    }

    fn supports_ntlm(&self) -> bool {
        curl::Version::get().feature_ntlm()
    }
    fn take_error(&mut self) -> Option<&'static str> { self.error.take() }
}

fn pox_request(address: &str) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\">",
            "<Request><EMailAddress>{}</EMailAddress>",
            "<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>",
            "</Request></Autodiscover>"
        ),
        quick_xml::escape::escape(address)
    )
}

fn redirect_target(base: &Url, location: &str) -> Option<Url> {
    if location.chars().any(|c| c.is_whitespace() || c.is_control() || c == '\\') {
        return None;
    }
    let target = base.join(location).ok()?;
    secure_url(target.as_str())
}

fn is_redirect(status: u32) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

enum Probe {
    Verified,
    Unavailable,
    Authentication,
    Transport(&'static str),
}

fn probe_manifest(
    transport: &mut impl Transport,
    url: &Url,
    login: &str,
    password: &str,
) -> Probe {
    let Some(response) = transport.request(url, None, None) else {
        return Probe::Unavailable;
    };
    if response.status == 200 {
        return if valid_manifest(&response.body) {
            Probe::Verified
        } else {
            Probe::Unavailable
        };
    }
    if response.status != 401 || password.is_empty() {
        return Probe::Unavailable;
    }
    let Some(scheme) = response.scheme() else {
        return Probe::Unavailable;
    };
    if scheme == Scheme::Ntlm && !transport.supports_ntlm() {
        return Probe::Transport("Bundled libcurl lacks NTLM support");
    }
    let Some(response) = transport.request(url, None, Some(Credentials { scheme, login, password })) else {
        return transport.take_error().map_or(Probe::Unavailable, Probe::Transport);
    };
    match response.status {
        401 | 403 => Probe::Authentication,
        200 if valid_manifest(&response.body) => Probe::Verified,
        _ => Probe::Unavailable,
    }
}

fn choose_oab(
    urls: &[Url],
    authorized: impl Fn(&Url) -> bool,
    mut probe: impl FnMut(&Url) -> Probe,
) -> Result<Option<Url>, Error> {
    let trusted: Vec<&Url> = urls.iter().filter(|u| authorized(u)).collect();
    let mut transport_error = None;
    for url in &trusted {
        match probe(url) {
            Probe::Verified => return Ok(Some((*url).clone())),
            Probe::Authentication => {
                // Stop after a rejected password; do not try every server.
                return Ok(trusted.first().map(|u| (**u).clone()));
            }
            Probe::Transport(message) => transport_error = Some(message),
            Probe::Unavailable => {}
        }
    }
    if let Some(message) = transport_error {
        return Err(Error::Transport(message));
    }
    // Retain the published authorized fallback for the background retry.
    Ok(trusted.first().map(|u| (**u).clone()))
}

fn discover_with(
    transport: &mut impl Transport,
    email: &str,
    password: &str,
    approved: &[String],
) -> Result<Discovery, Error> {
    let original = domain(email).ok_or(Error::InvalidAddress)?;
    let authorized = |url: &Url| {
        url.host_str().is_some_and(|host| {
            related(host, &original) || approved.iter().any(|a| a.eq_ignore_ascii_case(host))
        })
    };
    let mut address = email.to_owned();
    let mut queue: VecDeque<(String, Url)> = candidates(&original)
        .into_iter()
        .map(|u| (address.clone(), u))
        .collect();
    let mut seen = HashSet::new();
    let mut fallback = HashSet::new();
    let mut redirects = 0;
    let mut auth_needed = false;
    let mut first_untrusted = None;
    while seen.len() < 24 {
        if queue.is_empty() {
            if let Some(d) = domain(&address) {
                if fallback.insert(d.clone()) {
                    if let Ok(url) = Url::parse(&format!("http://autodiscover.{d}{PATH}")) {
                        // HTTP fallback: no address, no cookies, no password.
                        if let Some(r) = transport.request(&url, None, None) {
                            if is_redirect(r.status) {
                                if let Some(target) = r.location.as_deref().and_then(secure_url) {
                                    queue.push_back((address.clone(), target));
                                }
                            }
                        }
                    }
                    queue.extend(transport.srv(&d).into_iter().map(|u| (address.clone(), u)));
                }
            }
        }
        let Some((next_address, url)) = queue.pop_front() else {
            break;
        };
        address = next_address;
        if !seen.insert((address.clone(), url.clone())) {
            continue;
        }
        let Some(host) = url.host_str() else { continue };
        if cloud(host) {
            return Ok(Discovery::Microsoft365);
        }
        let xml = pox_request(&address);
        let Some(mut response) = transport.request(&url, Some(&xml), None) else {
            continue;
        };
        if response.status == 401 && response.cloud_challenge() {
            return Ok(Discovery::Microsoft365);
        }
        if response.status == 401 {
            if let Some(scheme) = response.scheme() {
                auth_needed = true;
                if password.is_empty() {
                    continue;
                }
                if !authorized(&url) {
                    first_untrusted.get_or_insert_with(|| host.to_owned());
                    continue;
                }
                if scheme == Scheme::Ntlm && !transport.supports_ntlm() {
                    return Err(Error::Transport("Bundled libcurl lacks NTLM support"));
                }
                let Some(authenticated) = transport.request(
                    &url,
                    Some(&xml),
                    Some(Credentials { scheme, login: email, password }),
                ) else {
                    if let Some(message) = transport.take_error() { return Err(Error::Transport(message)); }
                    continue;
                };
                response = authenticated;
                if matches!(response.status, 401 | 403) {
                    return Err(Error::Authentication);
                }
            }
        }
        if is_redirect(response.status) {
            if redirects < 10 {
                if let Some(target) = response.location.as_deref().and_then(|s| redirect_target(&url, s)) {
                    redirects += 1;
                    queue.push_front((address.clone(), target));
                }
            }
            continue;
        }
        if response.status != 200 {
            continue;
        }
        match parse(&response.body) {
            Some(Pox::RedirectUrl(target)) if redirects < 10 => {
                if let Some(target) = secure_url(&target) {
                    redirects += 1;
                    queue.push_front((address.clone(), target));
                }
            }
            Some(Pox::RedirectAddress(target)) if redirects < 10 => {
                if let Some(d) = domain(&target) {
                    redirects += 1;
                    for u in candidates(&d).into_iter().rev() {
                        queue.push_front((target.clone(), u));
                    }
                }
            }
            Some(Pox::Cloud) => return Ok(Discovery::Microsoft365),
            Some(Pox::Exchange { ews, oab }) => {
                if !authorized(&ews) {
                    return Ok(Discovery::ApproveHost(ews.host_str().unwrap_or_default().to_owned()));
                }
                let selected = choose_oab(&oab, authorized, |endpoint| {
                    probe_manifest(transport, endpoint, email, password)
                })?;
                if selected.is_none() && !oab.is_empty() {
                    return Ok(Discovery::ApproveHost(oab[0].host_str().unwrap_or_default().to_owned()));
                }
                return Ok(Discovery::Exchange {
                    ews: Some(ews.to_string()),
                    oab: selected.map(|u| u.to_string()),
                });
            }
            _ => {}
        }
    }
    if let Some(host) = first_untrusted {
        Ok(Discovery::ApproveHost(host))
    } else if auth_needed && password.is_empty() {
        Ok(Discovery::PasswordRequired)
    } else {
        Err(Error::NotFound)
    }
}

pub(super) fn discover(
    email: &str,
    password: &str,
    approved: &[String],
) -> Result<Discovery, Error> {
    let mut transport = CurlTransport {
        deadline: Instant::now() + Duration::from_secs(110),
        error: None,
    };
    discover_with(&mut transport, email, password, approved)
}

// Reuse the bounded system DNS resolver shared by IMAP/SMTP discovery.
fn lookup_srv(host: &str) -> Vec<Url> {
    srv_urls(super::account_dns::srv(&format!("_autodiscover._tcp.{host}")))
}

fn srv_urls(records: Vec<super::account_dns::Srv>) -> Vec<Url> {
    records.into_iter().filter(|r| r.port == 443)
        .filter_map(|r| secure_url(&format!("https://{}{PATH}", r.host)))
        .take(8).collect()
}

#[cfg(test)]
fn parse_srv(packet: &[u8]) -> Option<Vec<Url>> {
    super::account_dns::parse_srv(packet, None).map(srv_urls)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<Autodiscover xmlns="urn:test"><Response><Account><Action>settings</Action>
      <Protocol><Type>EXCH</Type><EwsUrl>https://internal.example.test/EWS/Exchange.asmx</EwsUrl>
      <OABUrl>https://internal.example.test/OAB/12345678-1234-1234-1234-123456789abc/</OABUrl></Protocol>
      <Protocol><Type>EXPR</Type><EwsUrl>https://ex2.example.test/EWS/Exchange.asmx</EwsUrl>
      <OABUrl>https://ex1.example.test/OAB/</OABUrl></Protocol></Account></Response></Autodiscover>"#;

    #[test]
    fn native_exchange_external_protocol_and_verified_oab_fallback() {
        let Some(Pox::Exchange { ews, oab }) = parse(XML.as_bytes()) else {
            panic!("Exchange settings missing");
        };
        assert_eq!(ews.as_str(), "https://ex2.example.test/EWS/Exchange.asmx");
        assert_eq!(oab[0].as_str(), "https://ex1.example.test/OAB/oab.xml");
        let expected = "https://ex2.example.test/OAB/12345678-1234-1234-1234-123456789abc/oab.xml";
        assert_eq!(oab[1].as_str(), expected);
        let mut attempted = Vec::new();
        let chosen = choose_oab(&oab, |_| true, |url| {
            attempted.push(url.to_string());
            if url.as_str() == expected {
                Probe::Verified
            } else {
                Probe::Unavailable
            }
        }).unwrap().unwrap();
        assert_eq!(chosen.as_str(), expected);
        assert_eq!(attempted, vec![oab[0].to_string(), expected.to_owned()]);
        assert_eq!(choose_oab(&oab, |_| false, |_| panic!("untrusted probe")).unwrap(), None);
    }

    #[test]
    fn native_exchange_stops_after_rejected_oab_password() {
        let Some(Pox::Exchange { oab, .. }) = parse(XML.as_bytes()) else { panic!() };
        let mut attempts = 0;
        let chosen = choose_oab(&oab, |_| true, |_| {
            attempts += 1;
            Probe::Authentication
        }).unwrap();
        assert_eq!(attempts, 1);
        assert_eq!(chosen, Some(oab[0].clone()));
    }

    #[test]
    fn native_exchange_manifest_and_security() {
        assert!(!valid_manifest(b"<html>login page</html>"));
        assert!(valid_manifest(b"<OAB><OAL><Full size=\"123\" SHA=\"abcd\">full.lzx</Full></OAL></OAB>"));
        assert!(!valid_manifest(b"<OAB><OAL><Full size=\"123\" SHA=\"abcd\">../full.lzx</Full></OAL></OAB>"));
        assert!(!valid_manifest(b"<!DOCTYPE OAB><OAB/>"));
        for invalid in [
            "http://example.test/EWS/Exchange.asmx",
            "https://user:secret@example.test/EWS/Exchange.asmx",
            "https://@example.test/EWS/Exchange.asmx",
            "https://example.test:444/EWS/Exchange.asmx",
            "https://example.test/EWS/Exchange.asmx?foo=bar",
            "https://example.test\\evil.test/EWS/Exchange.asmx",
        ] {
            assert!(secure_url(invalid).is_none(), "{invalid}");
        }
        assert!(!related("evil-example.test", "example.test"));
        assert!(related("mail.example.test", "example.test"));
        assert!(parse(b"<!DOCTYPE a><a/>").is_none());
        assert_eq!(parse(b"<Autodiscover><Response><Account><MicrosoftOnline>true</MicrosoftOnline></Account></Response></Autodiscover>"), Some(Pox::Cloud));
        assert_eq!(parse(b"<Autodiscover><Response><Account><Action>redirectAddr</Action><RedirectAddr>a@other.test</RedirectAddr></Account></Response></Autodiscover>"), Some(Pox::RedirectAddress("a@other.test".into())));
    }

    #[test]
    fn native_exchange_curl_has_ntlm() {
        let version = curl::Version::get();
        assert!(version.vendored(), "expected bundled libcurl, got {}", version.version());
        assert!(version.feature_ntlm(), "libcurl {} lacks NTLM; check source/.cargo/config.toml and CFLAGS", version.version());
    }

    struct Fake {
        replies: VecDeque<Response>,
        requests: Vec<(String, bool, bool)>,
    }

    impl Transport for Fake {
        fn request(&mut self, url: &Url, body: Option<&str>, credentials: Option<Credentials<'_>>) -> Option<Response> {
            self.requests.push((url.to_string(), body.is_some(), credentials.is_some()));
            self.replies.pop_front()
        }
        fn srv(&mut self, _: &str) -> Vec<Url> { Vec::new() }
        fn supports_ntlm(&self) -> bool { true }
    }

    fn challenge() -> Response {
        Response { status: 401, challenges: vec!["Negotiate, NTLM".into()], ..Default::default() }
    }

    #[test]
    fn native_exchange_authenticated_discovery_checks_manifest() {
        let mut fake = Fake {
            replies: VecDeque::from([
                challenge(),
                Response { status: 200, body: XML.as_bytes().to_vec(), ..Default::default() },
                Response { status: 503, ..Default::default() },
                challenge(),
                Response { status: 200, body: b"<OAB><OAL><Full size=\"123\" SHA=\"abcd\">full.lzx</Full></OAL></OAB>".to_vec(), ..Default::default() },
            ]),
            requests: Vec::new(),
        };
        let result = discover_with(&mut fake, "alice@example.test", "secret", &[]).unwrap();
        let Discovery::Exchange { ews: Some(ews), oab: Some(oab) } = result else { panic!() };
        assert!(ews.starts_with("https://ex2.example.test/"));
        assert!(oab.starts_with("https://ex2.example.test/OAB/12345678"));
        assert_eq!(fake.requests.iter().map(|r| r.2).collect::<Vec<_>>(), vec![false, true, false, false, true]);
    }

    #[test]
    fn native_exchange_never_authenticates_unapproved_redirect() {
        let mut fake = Fake {
            replies: VecDeque::from([
                Response { status: 302, location: Some("https://unrelated.test/autodiscover/autodiscover.xml".into()), ..Default::default() },
                challenge(),
            ]),
            requests: Vec::new(),
        };
        let result = discover_with(&mut fake, "alice@example.test", "secret", &[]).unwrap();
        assert!(matches!(result, Discovery::ApproveHost(host) if host == "unrelated.test"));
        assert!(fake.requests.iter().all(|r| !r.2));
    }

    #[test]
    fn native_exchange_negotiate_only_routes_to_native_transport() {
        let mut fake = Fake {
            replies: VecDeque::from([
                Response { status: 401, challenges: vec!["Negotiate".into()], ..Default::default() },
                Response { status: 200, body: XML.as_bytes().to_vec(), ..Default::default() },
                Response { status: 200, body: b"<OAB><OAL><Full size=\"123\" SHA=\"abcd\">full.lzx</Full></OAL></OAB>".to_vec(), ..Default::default() },
            ]),
            requests: Vec::new(),
        };
        assert!(matches!(discover_with(&mut fake, "alice@example.test", "secret", &[]).unwrap(), Discovery::Exchange { .. }));
        assert_eq!(fake.requests.iter().map(|r| r.2).collect::<Vec<_>>(), vec![false, true, false]);
    }

    #[test]
    fn native_exchange_no_retry_after_rejected_password() {
        let mut fake = Fake {
            replies: VecDeque::from([challenge(), challenge()]),
            requests: Vec::new(),
        };
        assert_eq!(discover_with(&mut fake, "alice@example.test", "secret", &[]).unwrap_err(), Error::Authentication);
        assert_eq!(fake.requests.len(), 2);
    }

    #[test]
    fn native_exchange_srv_packet_is_bounded() {
        let mut packet = vec![0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        // Root owner, SRV IN, TTL, RDATA length.
        packet.extend_from_slice(&[0, 0, 33, 0, 1, 0, 0, 0, 0, 0, 25]);
        packet.extend_from_slice(&[0, 10, 0, 20, 1, 187]);
        packet.extend_from_slice(b"\x04mail\x07example\x04test\0");
        let urls = parse_srv(&packet).unwrap();
        assert_eq!(urls[0].as_str(), "https://mail.example.test/autodiscover/autodiscover.xml");
        assert!(parse_srv(&packet[..packet.len() - 1]).is_none());
        assert!(super::super::account_dns::dns_name(&[0xc0, 0], 0).is_none());
    }
}
