//! NTLMv2 in the HTTP Negotiate scheme (Exchange servers that advertise
//! Negotiate but not NTLM). Use the system GSS-NTLMSSP implementation with
//! explicit password credentials and RFC 5929 TLS channel bindings. Unlike
//! libcurl's Kerberos Negotiate mode, this does not require a ticket cache.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use curl::easy::{Easy, List};
use std::{
    ffi::{c_char, c_int, c_void, CStr},
    ptr,
    time::Instant,
};

const UNAVAILABLE: &str = "Exchange Negotiate requires the system gss-ntlmssp package";
const PROTOCOL: &str = "Exchange Negotiate authentication failed";
const TLS_BINDING: &str = "Exchange Negotiate TLS channel binding failed";
const TIMEOUT: &str = "Exchange Negotiate request timed out";

#[derive(Debug)]
pub(crate) enum Error<E> {
    Transport(E),
    Protocol(&'static str),
}

pub(crate) trait Reply {
    fn status(&self) -> u32;
    fn challenges(&self) -> &[String];
}

fn has_negotiate(headers: &[String]) -> bool {
    headers.iter().any(|h| h.split(',').any(|p| p.split_whitespace().next().is_some_and(|s| s.eq_ignore_ascii_case("Negotiate"))))
}

fn challenge(headers: &[String]) -> Option<Vec<u8>> {
    for part in headers.iter().flat_map(|h| h.split(',')) {
        let mut fields = part.split_whitespace();
        if fields.next().is_some_and(|s| s.eq_ignore_ascii_case("Negotiate")) {
            let Some(token) = fields.next() else { continue };
            if fields.next().is_some() || token.len() > 88_000 {
                continue;
            }
            if let Ok(bytes) = STANDARD.decode(token) {
                if ntlm_type(&bytes, 2) {
                    return Some(bytes);
                }
            }
        }
    }
    None
}

fn ntlm_type(bytes: &[u8], kind: u32) -> bool {
    bytes.len() >= 12 && bytes.len() <= 65536
        && bytes.starts_with(b"NTLMSSP\0")
        && bytes[8..12] == kind.to_le_bytes()
}

fn ntlm_v2_authenticate(bytes: &[u8]) -> bool {
    if !ntlm_type(bytes, 3) || bytes.len() < 64 {
        return false;
    }
    // NTChallengeResponse security buffer, followed by the NTLMv2 blob
    // (16-byte proof + 0x01010000 response version). Never send NTLMv1.
    let len = u16::from_le_bytes([bytes[20], bytes[21]]) as usize;
    let offset = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
    if len < 48 {
        return false;
    }
    offset.checked_add(len).and_then(|end| bytes.get(offset..end))
        .is_some_and(|response| response[16..20] == [1, 1, 0, 0])
}

fn headers(post: bool, token: Option<&[u8]>) -> Result<List, curl::Error> {
    let mut list = List::new();
    if post {
        list.append("Content-Type: text/xml; charset=utf-8")?;
        list.append("Expect:")?;
    }
    if let Some(token) = token {
        list.append(&format!("Authorization: Negotiate {}", STANDARD.encode(token)))?;
    }
    Ok(list)
}

// libcurl owns the connection and verifies TLS. It also supplies the actual
// peer certificate from that connection; never compute CBT from a second
// independently connected socket.
fn certificate(easy: &Easy) -> Option<Vec<u8>> {
    let mut info: *mut curl_sys::curl_certinfo = ptr::null_mut();
    // SAFETY: valid easy handle; CERTINFO writes a pointer to its own
    // certificate list. Copy the leaf PEM while the handle owns that list.
    unsafe {
        if curl_sys::curl_easy_getinfo(easy.raw(), curl_sys::CURLINFO_CERTINFO, &mut info) != curl_sys::CURLE_OK
            || info.is_null() || (*info).num_of_certs < 1 || (*info).certinfo.is_null()
        {
            return None;
        }
        let mut node = *(*info).certinfo;
        for _ in 0..256 {
            if node.is_null() { break; }
            if !(*node).data.is_null() {
                let field = CStr::from_ptr((*node).data).to_bytes();
                if let Some(pem) = field.strip_prefix(b"Cert:") {
                    if !pem.is_empty() && pem.len() <= 256 * 1024 {
                        return Some(pem.to_vec());
                    }
                }
            }
            node = (*node).next;
        }
    }
    None
}

fn certificate_binding(pem: &[u8]) -> Option<Vec<u8>> {
    use openssl_sys as ssl;
    // OpenSSL 1.1.1+ resolves the digest for composite schemes (RSA-PSS
    // included); X509_get_signature_nid alone cannot do that.
    extern "C" {
        fn X509_get_signature_info(x: *mut ssl::X509, mdnid: *mut c_int, pknid: *mut c_int, secbits: *mut c_int, flags: *mut u32) -> c_int;
    }
    struct Cert(*mut ssl::X509);
    impl Drop for Cert {
        fn drop(&mut self) { unsafe { ssl::X509_free(self.0) } }
    }
    // SAFETY: BIO points to live PEM bytes for the duration of parsing;
    // OpenSSL owns the returned X509. All output buffers are sized.
    unsafe {
        let bio = ssl::BIO_new_mem_buf(pem.as_ptr().cast(), c_int::try_from(pem.len()).ok()?);
        if bio.is_null() { return None; }
        let cert = ssl::PEM_read_bio_X509(bio, ptr::null_mut(), None, ptr::null_mut());
        ssl::BIO_free_all(bio);
        if cert.is_null() { return None; }
        let cert = Cert(cert);
        let mut mdnid = 0;
        if X509_get_signature_info(cert.0, &mut mdnid, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) != 1 {
            return None;
        }
        let name = ssl::OBJ_nid2sn(mdnid);
        let digest = if mdnid == 0 || (!name.is_null() && matches!(CStr::from_ptr(name).to_bytes(), b"MD5" | b"SHA1" | b"MD5-SHA1")) {
            // RFC 5929: use SHA-256 for MD5/SHA-1 signatures. RFC 9266:
            // likewise for schemes with no single associated hash.
            ssl::EVP_sha256()
        } else if name.is_null() {
            return None;
        } else {
            ssl::EVP_get_digestbyname(name)
        };
        if digest.is_null() { return None; }
        let mut result = [0u8; 128];
        let mut len = 0u32;
        if ssl::X509_digest(cert.0, digest, result.as_mut_ptr(), &mut len) != 1
            || len == 0 || len as usize > result.len()
        {
            return None;
        }
        let mut binding = b"tls-server-end-point:".to_vec();
        binding.extend_from_slice(&result[..len as usize]);
        Some(binding)
    }
}

// GSSAPI is a stable C ABI; load the provider only for Negotiate. The
// normal NTLM / Basic paths need no GSSAPI package or Kerberos service.
type Handle = *mut c_void;
#[repr(C)]
struct Buffer { length: usize, value: Handle }
impl Buffer {
    fn empty() -> Self { Self { length: 0, value: ptr::null_mut() } }
    fn bytes(bytes: &[u8]) -> Self { Self { length: bytes.len(), value: bytes.as_ptr().cast_mut().cast() } }
}
#[repr(C)]
struct Oid { length: u32, elements: Handle }
impl Oid {
    fn bytes(bytes: &[u8]) -> Self { Self { length: bytes.len() as u32, elements: bytes.as_ptr().cast_mut().cast() } }
}
#[repr(C)]
struct OidSet { count: usize, elements: *mut Oid }
#[repr(C)]
struct Bindings {
    initiator_addrtype: u32,
    initiator_address: Buffer,
    acceptor_addrtype: u32,
    acceptor_address: Buffer,
    application_data: Buffer,
}

// 1.3.6.1.4.1.311.2.2.10; explicit mechanism, not Kerberos/SPNEGO.
const NTLM_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
// GSS_C_NT_USER_NAME and GSS_C_NT_HOSTBASED_SERVICE.
const USER_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01];
const HOST_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];

type Import = unsafe extern "C" fn(*mut u32, *mut Buffer, *mut Oid, *mut Handle) -> u32;
type Acquire = unsafe extern "C" fn(*mut u32, Handle, *mut Buffer, u32, *mut OidSet, c_int, *mut Handle, *mut *mut OidSet, *mut u32) -> u32;
type Init = unsafe extern "C" fn(*mut u32, Handle, *mut Handle, Handle, *mut Oid, u32, u32, *mut Bindings, *mut Buffer, *mut *mut Oid, *mut Buffer, *mut u32, *mut u32) -> u32;
type Release = unsafe extern "C" fn(*mut u32, *mut Handle) -> u32;
type ReleaseBuffer = unsafe extern "C" fn(*mut u32, *mut Buffer) -> u32;
type Delete = unsafe extern "C" fn(*mut u32, *mut Handle, *mut Buffer) -> u32;
type Indicate = unsafe extern "C" fn(*mut u32, *mut *mut OidSet) -> u32;
type ReleaseSet = unsafe extern "C" fn(*mut u32, *mut *mut OidSet) -> u32;

struct Library(Handle);
impl Drop for Library {
    fn drop(&mut self) { unsafe { libc::dlclose(self.0); } }
}
struct Api {
    _library: Library,
    import: Import,
    acquire: Acquire,
    init: Init,
    release_name: Release,
    release_cred: Release,
    release_buffer: ReleaseBuffer,
    delete: Delete,
    indicate: Indicate,
    release_set: ReleaseSet,
}

impl Api {
    fn load() -> Option<Self> {
        // SAFETY: load known system library; resolve only exact GSSAPI
        // symbols, using their documented signatures. Keep the handle alive.
        unsafe {
            let handle = libc::dlopen(c"libgssapi_krb5.so.2".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if handle.is_null() { return None; }
            let library = Library(handle);
            macro_rules! sym {
                ($name:literal, $ty:ty) => {{
                    let p = libc::dlsym(handle, concat!($name, "\0").as_ptr().cast::<c_char>());
                    if p.is_null() { return None; }
                    std::mem::transmute::<Handle, $ty>(p)
                }};
            }
            Some(Self {
                import: sym!("gss_import_name", Import),
                acquire: sym!("gss_acquire_cred_with_password", Acquire),
                init: sym!("gss_init_sec_context", Init),
                release_name: sym!("gss_release_name", Release),
                release_cred: sym!("gss_release_cred", Release),
                release_buffer: sym!("gss_release_buffer", ReleaseBuffer),
                delete: sym!("gss_delete_sec_context", Delete),
                indicate: sym!("gss_indicate_mechs", Indicate),
                release_set: sym!("gss_release_oid_set", ReleaseSet),
                _library: library,
            })
        }
    }

    fn ntlm_available(&self) -> bool {
        let mut minor = 0;
        let mut set: *mut OidSet = ptr::null_mut();
        // SAFETY: GSSAPI allocates the returned set; compare its OIDs
        // before releasing the set through the same library.
        unsafe {
            let status = (self.indicate)(&mut minor, &mut set);
            let mut found = false;
            if status == 0 && !set.is_null() && !(*set).elements.is_null() && (*set).count <= 1024 {
                for oid in std::slice::from_raw_parts((*set).elements, (*set).count) {
                    if oid.length as usize == NTLM_OID.len() && !oid.elements.is_null()
                        && std::slice::from_raw_parts(oid.elements.cast::<u8>(), oid.length as usize) == NTLM_OID
                    {
                        found = true;
                        break;
                    }
                }
            }
            if !set.is_null() { (self.release_set)(&mut minor, &mut set); }
            found
        }
    }
}

struct Client {
    api: Api,
    user: Handle,
    target: Handle,
    cred: Handle,
    context: Handle,
}

impl Drop for Client {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: every non-null handle was acquired from this API, and
        // the API library remains loaded until after Drop returns.
        unsafe {
            if !self.context.is_null() { (self.api.delete)(&mut minor, &mut self.context, ptr::null_mut()); }
            if !self.cred.is_null() { (self.api.release_cred)(&mut minor, &mut self.cred); }
            if !self.target.is_null() { (self.api.release_name)(&mut minor, &mut self.target); }
            if !self.user.is_null() { (self.api.release_name)(&mut minor, &mut self.user); }
        }
    }
}

impl Client {
    fn new(login: &str, password: &str, host: &str) -> Result<Self, &'static str> {
        let api = Api::load().filter(Api::ntlm_available).ok_or(UNAVAILABLE)?;
        if login.is_empty() || password.is_empty() || login.contains('\0') || password.contains('\0') {
            return Err(PROTOCOL);
        }
        let mut client = Self { api, user: ptr::null_mut(), target: ptr::null_mut(), cred: ptr::null_mut(), context: ptr::null_mut() };
        let mut minor = 0;
        let target = format!("HTTP@{host}");
        let mut mech = Oid::bytes(NTLM_OID);
        let mut mechs = OidSet { count: 1, elements: &mut mech };
        // SAFETY: input buffers and OIDs live throughout the synchronous
        // calls. GSS owns the resulting handles; Client releases them.
        unsafe {
            if (client.api.import)(&mut minor, &mut Buffer::bytes(login.as_bytes()), &mut Oid::bytes(USER_OID), &mut client.user) != 0
                || (client.api.import)(&mut minor, &mut Buffer::bytes(target.as_bytes()), &mut Oid::bytes(HOST_OID), &mut client.target) != 0
                || (client.api.acquire)(&mut minor, client.user, &mut Buffer::bytes(password.as_bytes()), 0, &mut mechs, 1, &mut client.cred, ptr::null_mut(), ptr::null_mut()) != 0
            {
                return Err(PROTOCOL);
            }
        }
        Ok(client)
    }

    fn step(&mut self, token: Option<&[u8]>, binding: &[u8]) -> Result<(bool, Vec<u8>), &'static str> {
        let mut input = Buffer::bytes(token.unwrap_or_default());
        let mut output = Buffer::empty();
        let mut bindings = Bindings { initiator_addrtype: 0, initiator_address: Buffer::empty(), acceptor_addrtype: 0, acceptor_address: Buffer::empty(), application_data: Buffer::bytes(binding) };
        let mut minor = 0;
        let mut mech = Oid::bytes(NTLM_OID);
        // SAFETY: all inputs live for the synchronous call; copy and release
        // GSS-owned output even on failure. No delegation or default creds.
        unsafe {
            let status = (self.api.init)(&mut minor, self.cred, &mut self.context, self.target, &mut mech,
                4 | 8 | 16 | 32, 0, &mut bindings,
                if token.is_some() { &mut input } else { ptr::null_mut() },
                ptr::null_mut(), &mut output, ptr::null_mut(), ptr::null_mut());
            let bytes = if !output.value.is_null() && output.length <= 65536 {
                std::slice::from_raw_parts(output.value.cast::<u8>(), output.length).to_vec()
            } else { Vec::new() };
            (self.api.release_buffer)(&mut minor, &mut output);
            if status > 1 || bytes.is_empty() {
                return Err(PROTOCOL);
            }
            Ok((status == 0, bytes))
        }
    }
}

extern "C" fn deny_new_socket(_: Handle, _: curl_sys::curlsocktype, _: *mut curl_sys::curl_sockaddr) -> curl_sys::curl_socket_t {
    curl_sys::CURL_SOCKET_BAD
}

// The caller creates a fresh easy handle, sets the URL, TLS verification,
// redirect policy, HTTP/1.1 and GET/POST data. Each callback performs exactly
// one transfer on that same handle. Intermediate 401 bodies are discarded
// by the caller; only the final successful response reaches its sink.
pub(crate) fn perform<R: Reply, E>(
    easy: &mut Easy,
    host: &str,
    login: &str,
    password: &str,
    post: bool,
    deadline: Instant,
    mut once: impl FnMut(&mut Easy) -> Result<R, E>,
) -> Result<R, Error<E>> {
    let protocol = |_| Error::Protocol(PROTOCOL);
    let timeout = |easy: &mut Easy| -> Result<(), Error<E>> {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(Error::Protocol(TIMEOUT))?;
        if remaining.is_zero() { return Err(Error::Protocol(TIMEOUT)); }
        easy.timeout(remaining).map_err(protocol)
    };
    easy.certinfo(true).map_err(protocol)?;
    easy.http_headers(headers(post, None).map_err(protocol)?).map_err(protocol)?;
    timeout(easy)?;
    let first = once(easy).map_err(Error::Transport)?;
    if first.status() != 401 || !has_negotiate(first.challenges()) {
        return Ok(first);
    }
    let binding = certificate(easy).and_then(|pem| certificate_binding(&pem)).ok_or(Error::Protocol(TLS_BINDING))?;
    let mut client = Client::new(login, password, host).map_err(Error::Protocol)?;
    let (complete, type1) = client.step(None, &binding).map_err(Error::Protocol)?;
    if complete || !ntlm_type(&type1, 1) { return Err(Error::Protocol(PROTOCOL)); }
    easy.http_headers(headers(post, Some(&type1)).map_err(protocol)?).map_err(protocol)?;
    timeout(easy)?;
    let second = once(easy).map_err(Error::Transport)?;
    if second.status() != 401 {
        // A redirect or a successful anonymous response is handled by the
        // caller. Do not send a Type 3 token in either case.
        return Ok(second);
    }
    // Type 1 may reconnect after the anonymous challenge. Verify that the
    // certificate on the actual handshake connection has the same CBT.
    if easy.num_connects().map_err(protocol)? > 0 {
        let current = certificate(easy).and_then(|pem| certificate_binding(&pem)).ok_or(Error::Protocol(TLS_BINDING))?;
        if current != binding { return Err(Error::Protocol(TLS_BINDING)); }
    }
    let type2 = challenge(second.challenges()).ok_or(Error::Protocol(PROTOCOL))?;
    let (complete, type3) = client.step(Some(&type2), &binding).map_err(Error::Protocol)?;
    if !complete || !ntlm_v2_authenticate(&type3) { return Err(Error::Protocol(PROTOCOL)); }
    // Never deliver the password proof on a new connection. An NTLM
    // challenge is connection-bound, so a reconnect must fail, not retry.
    // SAFETY: valid handle; the static callback has libcurl's exact ABI
    // and no state. It remains valid for the life of this Easy handle.
    let rc = unsafe { curl_sys::curl_easy_setopt(easy.raw(), curl_sys::CURLOPT_OPENSOCKETFUNCTION, deny_new_socket as curl_sys::curl_opensocket_callback) };
    if rc != curl_sys::CURLE_OK { return Err(Error::Protocol(PROTOCOL)); }
    easy.http_headers(headers(post, Some(&type3)).map_err(protocol)?).map_err(protocol)?;
    timeout(easy)?;
    once(easy).map_err(Error::Transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_negotiate_only_accepts_raw_ntlm_type2() {
        let mut token = b"NTLMSSP\0".to_vec();
        token.extend_from_slice(&2u32.to_le_bytes());
        let encoded = STANDARD.encode(&token);
        assert_eq!(challenge(&[format!("Basic realm=\"test\", Negotiate {encoded}")]), Some(token));
        assert!(challenge(&["Negotiate YWJj".into()]).is_none());
        assert!(challenge(&["Negotiate".into()]).is_none());
        assert!(challenge(&[format!("NTLM {encoded}")]).is_none());
    }

    #[test]
    fn native_negotiate_rejects_ntlmv1_and_invalid_offsets() {
        let mut token = vec![0u8; 112];
        token[..8].copy_from_slice(b"NTLMSSP\0");
        token[8..12].copy_from_slice(&3u32.to_le_bytes());
        token[20..22].copy_from_slice(&48u16.to_le_bytes());
        token[24..28].copy_from_slice(&64u32.to_le_bytes());
        assert!(!ntlm_v2_authenticate(&token));
        token[80..84].copy_from_slice(&[1, 1, 0, 0]);
        assert!(ntlm_v2_authenticate(&token));
        token[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!ntlm_v2_authenticate(&token));
    }

    // Requires the optional runtime plugin. No network or real credentials.
    #[test]
    #[ignore = "requires system gss-ntlmssp package"]
    fn native_negotiate_gss_type1() {
        let mut client = Client::new("alice@example.test", "test-only-password", "mail.example.test").unwrap();
        let (complete, token) = client.step(None, b"tls-server-end-point:test").unwrap();
        assert!(!complete);
        assert!(ntlm_type(&token, 1));
    }
}
