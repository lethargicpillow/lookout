//! Mail discovery and authenticated Exchange Autodiscover, plus local
//! gateway setup. Credentials are scoped to approved HTTPS hosts. Existing gateway
//! settings are read-only; a conflicting endpoint is never silently reused.
use std::{collections::HashMap, fs, io::Write, net::{SocketAddr, TcpStream}, os::unix::fs::OpenOptionsExt, path::{Path, PathBuf}, process::{Command, Stdio}, time::{Duration, Instant}};
use lookout_mail::Security;
use quick_xml::{events::Event, Reader};

#[path = "exchange_native.rs"]
mod exchange_native;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Server {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: String,
}
#[derive(Clone, Debug)]
pub(crate) enum Discovery {
    Mail { imap: Server, smtp: Server },
    Exchange { ews: Option<String>, oab: Option<String> },
    Microsoft365,
    PasswordRequired,
    ApproveHost(String),
}

fn domain(email: &str) -> Option<String> {
    let (local, domain) = email.trim().rsplit_once('@')?;
    if local.is_empty() || local.contains('@') || local.chars().any(|c| c.is_whitespace() || c.is_control()) { return None; }
    let d = domain.to_ascii_lowercase();
    if d.len() > 253 || !d.contains('.') || d.split('.').any(|s| s.is_empty() || s.len() > 63
        || s.starts_with('-') || s.ends_with('-') || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) { return None; }
    Some(d)
}

fn https_url(value: &str) -> Option<reqwest::Url> {
    let u = reqwest::Url::parse(value.trim()).ok()?;
    (u.scheme() == "https" && u.host_str().is_some() && u.username().is_empty() && u.password().is_none()
        && u.fragment().is_none() && u.query().is_none()).then_some(u)
}

pub(crate) fn valid_ews(value: &str) -> bool {
    https_url(value).is_some_and(|u| u.path().eq_ignore_ascii_case("/ews/exchange.asmx"))
        && value.is_ascii() && !value.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
}

fn properties(path: &Path) -> Result<HashMap<String, String>, String> {
    let data = fs::read_to_string(path).map_err(|_| "Cannot read existing DavMail configuration")?;
    Ok(data.lines().filter_map(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('!') { return None; }
        let (key, value) = line.split_once('=')?;
        Some((key.trim().to_owned(), value.trim().replace("\\:", ":").replace("\\=", "=")))
    }).collect())
}

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute()).ok_or_else(|| "Home directory unavailable".into())
}
fn existing_config() -> Result<PathBuf, String> {
    Ok(home()?.join(".config/davmail/davmail.properties"))
}
fn managed_config() -> Result<PathBuf, String> {
    Ok(home()?.join(".config/lookout/davmail.properties"))
}

// Read a bounded XML tree of leaf paths. No DTD, external entities or
// arbitrary redirects. Keeping the parent path distinguishes incoming,
// outgoing and Exchange protocol blocks with identical field names.
fn leaves(xml: &str) -> Option<Vec<(Vec<String>, String)>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::<String>::new();
    let mut out = Vec::new();
    loop {
        match reader.read_event().ok()? {
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                let server = if name == "incomingServer" || name == "outgoingServer" {
                    e.attributes().filter_map(Result::ok).find(|a| a.key.as_ref() == b"type")
                        .map(|a| String::from_utf8_lossy(a.value.as_ref()).into_owned())
                } else { None };
                stack.push(server.map_or(name.clone(), |kind| format!("{name}:{kind}")));
                if stack.len() > 32 { return None; }
            }
            Event::Text(t) => {
                let text = t.decode().ok()?.into_owned();
                let text = quick_xml::escape::unescape(&text).ok()?.into_owned();
                if !text.is_empty() { out.push((stack.clone(), text)); }
                if out.len() > 4096 { return None; }
            }
            Event::End(_) => { stack.pop()?; }
            Event::DocType(_) => return None,
            Event::Eof => break,
            _ => {}
        }
    }
    stack.is_empty().then_some(out)
}

fn parse_mail(xml: &str, email: &str) -> Option<Discovery> {
    let entries = leaves(xml)?;
    let get = |section: &str, key: &str| -> Option<&str> {
        entries.iter().find(|(path, _)| path.iter().any(|p| p == section) && path.last().is_some_and(|p| p == key))
            .map(|(_, value)| value.as_str())
    };
    let endpoint = |section: &str| -> Option<Server> {
        let host = get(section, "hostname")?.to_owned();
        if domain(&format!("x@{host}")).is_none() { return None; }
        let port = get(section, "port")?.parse::<u16>().ok().filter(|p| *p != 0)?;
        let security = match get(section, "socketType")? {
            "SSL" => Security::ImplicitTls,
            "STARTTLS" => Security::StartTls,
            _ => return None,
        };
        // Do not fill password fields for OAuth-only endpoints.
        if !entries.iter().any(|(path, val)| path.iter().any(|p| p == section)
            && path.last().is_some_and(|p| p == "authentication") && matches!(val.as_str(), "password-cleartext" | "password-encrypted")) {
            return None;
        }
        let username = get(section, "username")?.replace("%EMAILADDRESS%", email)
            .replace("%EMAILLOCALPART%", email.rsplit_once('@')?.0).replace("%EMAILDOMAIN%", &domain(email)?);
        if username.is_empty() || username.contains('%') { return None; }
        Some(Server { host, port, security, username })
    };
    Some(Discovery::Mail { imap: endpoint("incomingServer:imap")?, smtp: endpoint("outgoingServer:smtp")? })
}

async fn xml_response(mut response: reqwest::Response) -> Option<String> {
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > 512 * 1024) { return None; }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > 512 * 1024 { return None; }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).ok()
}

async fn mail_probe(client: &reqwest::Client, url: String, email: &str) -> Option<Discovery> {
    let mut url = reqwest::Url::parse(&url).ok()?;
    url.query_pairs_mut().append_pair("emailaddress", email);
    let response = client.get(url).send().await.ok()?;
    parse_mail(&xml_response(response).await?, email)
}

// Exchange needs authenticated POX, redirect handling and SRV discovery.
// Use the existing distro NTLM stack (also used by OAB); no passwords
// appear in process arguments, environment or logs.
const AUTODISCOVER: &str = include_str!("exchange_discover.py");

fn exchange_discovery(email: String, password: String, approved: Vec<String>) -> Result<Discovery, String> {
    match exchange_native::discover(&email, &password, &approved) {
        Ok(result) => return Ok(result),
        Err(exchange_native::Error::LegacyNegotiate) => {},
        Err(error) => return Err(error.message().into()),
    }
    // Only a server offering Negotiate without native NTLM uses the old
    // compatibility transport. Never retry a rejected password this way.
    let input = serde_json::to_vec(&serde_json::json!({
        "email": email, "password": password, "approved": approved,
    })).map_err(|_| "Cannot prepare Autodiscover request")?;
    let mut child = Command::new("/usr/bin/python3").arg("-I").arg("-c").arg(AUTODISCOVER)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| "Cannot start Exchange Autodiscover helper")?;
    let written = child.stdin.take().ok_or("Autodiscover helper has no input")?.write_all(&input);
    if written.is_err() { let _ = child.kill(); let _ = child.wait(); return Err("Cannot pass Autodiscover request".into()); }
    let output = child.wait_with_output().map_err(|_| "Autodiscover helper failed")?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 { return Err("Autodiscover timed out or stopped".into()); }
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|_| "Invalid Autodiscover response")?;
    let field = |key: &str| response.get(key).and_then(|v| v.as_str()).map(str::to_owned);
    match field("status").as_deref() {
        Some("exchange") => {
            let ews = field("ews").filter(|v| valid_ews(v)).ok_or("Autodiscover did not return a valid EWS endpoint")?;
            let oab = field("oab").filter(|v| crate::oab_sync::valid_url(v));
            Ok(Discovery::Exchange { ews: Some(ews), oab })
        }
        Some("cloud") => Ok(Discovery::Microsoft365),
        Some("password") => Ok(Discovery::PasswordRequired),
        Some("approval") => field("host").filter(|h| domain(&format!("x@{h}")).is_some())
            .map(Discovery::ApproveHost).ok_or_else(|| "Invalid Autodiscover redirect host".into()),
        Some("authentication") => Err("Exchange rejected the password. Check your credentials before retrying.".into()),
        Some("dependencies") => Err("Exchange discovery requires python3-requests and python3-requests-ntlm (install the Lookout recommended packages).".into()),
        _ => Err("Autodiscover could not locate your mailbox. Check network/VPN access and your organization's Autodiscover configuration.".into()),
    }
}

pub(crate) async fn discover(email: &str, password: &str, approved: Vec<String>) -> Result<Discovery, String> {
    let d = domain(email).ok_or("Enter a valid email address")?;
    if matches!(d.as_str(), "outlook.com" | "hotmail.com" | "live.com" | "msn.com" | "outlook.office365.com")
        || d.ends_with(".onmicrosoft.com") { return Ok(Discovery::Microsoft365); }
    let client = reqwest::Client::builder().timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none()).build().map_err(|_| "Cannot initialize account discovery")?;
    let (a,b) = tokio::join!(
        mail_probe(&client, format!("https://autoconfig.{d}/mail/config-v1.1.xml"), email),
        mail_probe(&client, format!("https://{d}/.well-known/autoconfig/mail/config-v1.1.xml"), email),
    );
    if let Some(result) = a.or(b) { return Ok(result); }
    let address = email.to_owned();
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || exchange_discovery(address, password, approved))
        .await.map_err(|_| "Autodiscover worker stopped")?
}

const PORTS: [u16; 4] = [1143, 1025, 1080, 1389];
fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(300)).is_ok()
}
fn service_command(args: &[&str]) -> Result<(), String> {
    let mut child = Command::new("systemctl").arg("--user").args(args)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
        .map_err(|_| "Cannot start systemctl --user")?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(format!("DavMail service command failed: {}", args.join(" "))),
            Ok(None) if start.elapsed() < Duration::from_secs(20) => std::thread::sleep(Duration::from_millis(100)),
            _ => { let _ = child.kill(); let _ = child.wait(); return Err("DavMail service command timed out".into()); }
        }
    }
}
fn create_private(path: &Path, data: &str) -> Result<(), String> {
    fs::create_dir_all(path.parent().ok_or("Invalid configuration path")?).map_err(|_| "Cannot create configuration directory")?;
    let mut file = fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)
        .map_err(|_| "Cannot create configuration file without overwriting an existing file")?;
    file.write_all(data.as_bytes()).map_err(|_| "Cannot write configuration file".to_owned())
}

fn compatible(p: &HashMap<String, String>, ews: &str) -> bool {
    let eq = |key: &str, value: &str| p.get(key).is_some_and(|v| v.eq_ignore_ascii_case(value));
    eq("davmail.url", ews) && (eq("davmail.mode", "ExchangeEWS") || eq("davmail.mode", "EWS"))
        && eq("davmail.allowRemote", "false") && eq("davmail.bindAddress", "127.0.0.1")
        && eq("davmail.imapPort", "1143") && eq("davmail.smtpPort", "1025")
        && eq("davmail.caldavPort", "1080") && eq("davmail.ldapPort", "1389")
}

// Called only after successful discovery and explicit account setup.
// Do not install packages, overwrite a service, or redirect an existing
// gateway to another organization. Passwords are never in these files.
pub(crate) fn prepare_gateway(ews: &str) -> Result<(), String> {
    if !valid_ews(ews) { return Err("Autodiscover returned an invalid EWS endpoint".into()); }
    let home = home()?;
    let existing = existing_config()?;
    let managed = managed_config()?;
    let unit = home.join(".config/systemd/user/lookout-davmail.service");
    let (config, service) = if existing.exists() {
        if !compatible(&properties(&existing)?, ews) { return Err("Existing DavMail configuration uses a different endpoint or ports. It was not changed.".into()); }
        (existing, "davmail.service")
    } else if managed.exists() {
        if !compatible(&properties(&managed)?, ews) { return Err("Lookout's DavMail gateway is configured for a different endpoint. It was not changed.".into()); }
        (managed, "lookout-davmail.service")
    } else {
        if PORTS.iter().copied().any(listening) { return Err("A local gateway or another service already occupies a required port. No configuration was changed.".into()); }
        if !Path::new("/usr/bin/davmail").is_file() { return Err("Install DavMail first (sudo apt install davmail), then retry.".into()); }
        if unit.exists() { return Err("A Lookout DavMail service already exists. Inspect it before configuring a new gateway.".into()); }
        let config = format!("davmail.server=true\ndavmail.mode=ExchangeEWS\ndavmail.url={ews}\ndavmail.allowRemote=false\ndavmail.bindAddress=127.0.0.1\ndavmail.imapPort=1143\ndavmail.smtpPort=1025\ndavmail.caldavPort=1080\ndavmail.ldapPort=1389\ndavmail.popPort=\ndavmail.enableProxy=false\ndavmail.useSystemProxies=false\ndavmail.disableUpdateCheck=true\n");
        create_private(&managed, &config)?;
        create_private(&unit, "[Unit]\nDescription=Lookout local Exchange gateway\nAfter=network-online.target\n[Service]\nType=simple\nExecStart=/usr/bin/davmail -server %h/.config/lookout/davmail.properties\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=default.target\n")?;
        service_command(&["daemon-reload"])?;
        (managed, "lookout-davmail.service")
    };
    // Reuse a compatible existing service without restarting it.
    let _ = config;
    if PORTS.iter().copied().all(listening) {
        service_command(&["is-active", "--quiet", service])?;
        return Ok(());
    }
    if !PORTS.iter().copied().all(listening) {
        if PORTS.iter().copied().any(listening) { return Err("Only some gateway ports are available. Check the existing DavMail service; no restart was attempted.".into()); }
        service_command(&["enable", "--now", service])?;
    }
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if PORTS.iter().copied().all(listening) {
            service_command(&["is-active", "--quiet", service])?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err("DavMail did not open all four local ports. Check the user service journal.".into())
}

/// Verify before saving any secrets or account settings.
pub(crate) async fn verify_credentials(account: &crate::app_config::OtherAccount, imap_password: String, smtp_password: String) -> Result<(), String> {
    use lookout_mail::{AccountConfig, EndpointConfig, Credential};
    let config = AccountConfig {
        account_id: lookout_core::AccountId(account.id.clone()),
        display_name: account.display_name.clone(), email: account.email.clone(),
        mention_addresses: vec![account.email.clone()], mention_names: vec![],
        local_focus_enabled: false, local_focus_contacts: vec![],
        imap: EndpointConfig { host: account.imap_host.clone(), port: account.imap_port,
            security: account.resolved_imap_security(), username: account.imap_username.clone() },
        smtp: EndpointConfig { host: account.smtp_host.clone(), port: account.smtp_port,
            security: account.resolved_smtp_security(), username: account.smtp_username.clone() },
    };
    let timeout = Duration::from_secs(30);
    tokio::time::timeout(timeout, lookout_mail::session::verify_account_login(&config, Credential::Password(imap_password)))
        .await.map_err(|_| "IMAP login timed out. Check the server and network.")?
        .map_err(|_| "IMAP login failed. Check the server, TLS settings, username and password.")?;
    tokio::time::timeout(timeout, lookout_mail::send::verify_smtp_login(&config.smtp, smtp_password))
        .await.map_err(|_| "SMTP login timed out. Check the server and network.")?
        .map_err(|_| "SMTP login failed. Check the server, TLS settings, username and password.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_setup_validates_addresses_and_ews() {
        assert_eq!(domain("alice@Example.test").as_deref(), Some("example.test"));
        assert!(domain("alice@bad/path").is_none());
        assert!(domain("a@foo..test").is_none());
        assert!(valid_ews("https://mail.example.test/EWS/Exchange.asmx"));
        assert!(!valid_ews("http://mail.example.test/EWS/Exchange.asmx"));
        assert!(!valid_ews("https://user:secret@mail.example.test/EWS/Exchange.asmx"));
    }
    #[test]
    fn account_setup_parses_secure_autoconfig() {
        let xml = r#"<clientConfig><emailProvider><incomingServer type="imap"><hostname>imap.example.test</hostname><port>993</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication></incomingServer><outgoingServer type="smtp"><hostname>smtp.example.test</hostname><port>587</port><socketType>STARTTLS</socketType><username>%EMAILLOCALPART%</username><authentication>password-cleartext</authentication></outgoingServer></emailProvider></clientConfig>"#;
        let Some(Discovery::Mail { imap, smtp }) = parse_mail(xml, "alice@example.test") else { panic!("no configuration") };
        assert_eq!(imap.username, "alice@example.test");
        assert_eq!(smtp.username, "alice");
        assert_eq!(smtp.port, 587);
        assert!(parse_mail(&xml.replace("password-cleartext", "OAuth2"), "alice@example.test").is_none());
        assert!(parse_mail(&xml.replace("STARTTLS", "plain"), "alice@example.test").is_none());
    }
}
