//! Opt-in, credential-free comparison of the SMTP TLS paths. Never sends mail.
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use lettre::transport::smtp::{
    client::{AsyncSmtpConnection, TlsParameters},
    extension::ClientId,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{lookup_host, TcpStream, ToSocketAddrs};

const HOST: &str = "smtp.gmail.com";
type ProbeResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn reply<S: AsyncRead + Unpin>(stream: &mut BufReader<S>, expected: u16) -> ProbeResult<()> {
    for _ in 0..100 {
        let mut line = String::new();
        if stream.read_line(&mut line).await? == 0 {
            return Err("SMTP peer closed the connection".into());
        }
        let code: u16 = line.get(..3).ok_or("invalid SMTP reply")?.parse()?;
        if code != expected {
            return Err(format!("SMTP expected {expected}, got {code}").into());
        }
        match line.as_bytes().get(3) {
            Some(b' ') => return Ok(()),
            Some(b'-') => continue,
            _ => return Err("invalid SMTP reply separator".into()),
        }
    }
    Err("too many SMTP reply lines".into())
}

async fn command<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufReader<S>, text: &[u8], expected: u16,
) -> ProbeResult<()> {
    stream.get_mut().write_all(text).await?;
    stream.get_mut().flush().await?;
    reply(stream, expected).await
}

async fn raw_probe(addr: SocketAddr) -> ProbeResult<()> {
    let tcp = TcpStream::connect(addr).await?;
    println!("raw {addr}: TCP connected, peer={}", tcp.peer_addr()?);
    let tcp = if addr.port() == 587 {
        let mut stream = BufReader::new(tcp);
        reply(&mut stream, 220).await?;
        println!("raw {addr}: greeting received");
        command(&mut stream, b"EHLO localhost\r\n", 250).await?;
        println!("raw {addr}: EHLO accepted");
        command(&mut stream, b"STARTTLS\r\n", 220).await?;
        println!("raw {addr}: STARTTLS 220 received");
        if !stream.buffer().is_empty() {
            return Err("unexpected buffered plaintext after STARTTLS".into());
        }
        stream.into_inner()
    } else { tcp };
    println!("raw {addr}: rustls handshake starting");
    let tls = crate::connection::tls_connect_over(tcp, HOST).await?;
    println!("raw {addr}: rustls handshake OK, protocol={:?}", tls.get_ref().1.protocol_version());
    let mut stream = BufReader::new(tls);
    if addr.port() == 465 {
        reply(&mut stream, 220).await?;
        println!("raw {addr}: encrypted greeting received");
    }
    command(&mut stream, b"EHLO localhost\r\n", 250).await?;
    println!("raw {addr}: encrypted EHLO accepted");
    Ok(())
}

async fn lettre_probe<T: ToSocketAddrs>(target: T, port: u16, label: &str) -> ProbeResult<()> {
    let hello = ClientId::default();
    let tls = if port == 465 { Some(TlsParameters::new(HOST.into())?) } else { None };
    println!("{label}: lettre connect starting");
    let mut connection = AsyncSmtpConnection::connect_tokio1(
        target, Some(Duration::from_secs(20)), &hello, tls, None,
    ).await?;
    println!("{label}: lettre connect/EHLO OK");
    if port == 587 {
        println!("{label}: lettre STARTTLS starting");
        connection.starttls(TlsParameters::new(HOST.into())?, &hello).await?;
        println!("{label}: lettre STARTTLS OK");
    }
    if !connection.is_encrypted() {
        return Err("SMTP connection is not encrypted".into());
    }
    // No AUTH, MAIL FROM, RCPT TO, or DATA in this probe.
    Ok(())
}

async fn run_case(label: &str, future: impl std::future::Future<Output = ProbeResult<()>>) {
    let started = std::time::Instant::now();
    match tokio::time::timeout(Duration::from_secs(22), future).await {
        Ok(Ok(())) => println!("RESULT {label}: OK ({:?})", started.elapsed()),
        Ok(Err(e)) => println!("RESULT {label}: ERROR {e} ({:?})", started.elapsed()),
        Err(_) => println!("RESULT {label}: TIMEOUT ({:?})", started.elapsed()),
    }
}

/// Credential-free diagnostics, usable on the actual application's runtime.
#[doc(hidden)]
pub async fn run_smtp_tls_probe() {
    crate::connection::ensure_crypto_provider_installed();
    println!("SMTP PROBE: pid={} runtime={:?}", std::process::id(), tokio::runtime::Handle::current().runtime_flavor());
    // Keep the trust policy identical to production, even in a test build.
    if std::env::var_os("LOOKOUT_INSECURE_TLS_FOR_TESTS").is_some() {
        println!("SMTP PROBE: unset LOOKOUT_INSECURE_TLS_FOR_TESTS first");
        return;
    }
    let addresses: Vec<_> = match tokio::time::timeout(Duration::from_secs(8), lookup_host((HOST, 465))).await {
        Ok(Ok(addrs)) => addrs.collect(),
        Ok(Err(error)) => { println!("SMTP PROBE: DNS error: {error}"); return; }
        Err(_) => { println!("SMTP PROBE: DNS timeout"); return; }
    };
    println!("DNS {HOST}: {addresses:?}");
    let explicit_ip = match std::env::var("LOOKOUT_SMTP_PROBE_IP") {
        Ok(value) => match value.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => { println!("SMTP PROBE: invalid LOOKOUT_SMTP_PROBE_IP"); return; }
        },
        Err(_) => None,
    };
    let Some(ip) = explicit_ip
        .or_else(|| addresses.iter().find(|addr| addr.is_ipv4()).map(|addr| addr.ip()))
        .or_else(|| addresses.first().map(|addr| addr.ip())) else {
            println!("SMTP PROBE: no SMTP address"); return;
        };
    println!("Fixed probe IP: {ip}");
    for port in [465, 587] {
        let addr = SocketAddr::new(ip, port);
        let label = format!("raw rustls {addr}");
        run_case(&label, raw_probe(addr)).await;
        let label = format!("lettre fixed {addr}");
        run_case(&label, lettre_probe(addr, port, &label)).await;
        let label = format!("lettre DNS {HOST}:{port}");
        run_case(&label, lettre_probe((HOST, port), port, &label)).await;
    }
    println!("Probe complete; inspect RESULT lines. No credentials or mail were transmitted.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "opt-in network diagnostic; no authentication or message submission"]
async fn smtp_tls_probe() {
    run_smtp_tls_probe().await;
}

/// Run exactly once per process, alongside the real SMTP connection.
/// Explicit opt-in only; the probe never receives credentials or MIME.
pub(crate) fn maybe_spawn_live_probe() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if std::env::var("LOOKOUT_SMTP_LIVE_PROBE").as_deref() != Ok("1") {
        return;
    }
    if STARTED.swap(true, Ordering::Relaxed) {
        return;
    }
    tokio::spawn(async {
        tracing::info!("SMTP live diagnostic started");
        run_smtp_tls_probe().await;
        tracing::info!("SMTP live diagnostic finished");
    });
}
