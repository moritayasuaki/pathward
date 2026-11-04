//! TLS transport and atomic certificate selection. Rustls and OS I/O are trusted.
use crate::http::{self, Transport};
use pathward::tls::{activate, identity_allowed};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    server::{Acceptor, ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    fmt,
    io::{self, Read, Write},
    net::TcpStream,
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const HANDSHAKE_BUDGET: Duration = Duration::from_secs(5);
pub fn unix_now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| io::Error::other("invalid system clock"))
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "TLS identity policy")
}

pub struct Certificate {
    pub(crate) key: Arc<CertifiedKey>,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
}
impl Certificate {
    pub fn parse(bytes: &[u8], domains: &[String]) -> io::Result<Self> {
        if bytes.len() > 1_048_576 {
            return Err(denied());
        }
        let mut pems = pem::parse_many(bytes).map_err(|_| denied())?;
        if pems.len() < 2
            || pems.len() > 10
            || pems[0].tag() != "PRIVATE KEY"
            || pems[1..].iter().any(|p| p.tag() != "CERTIFICATE")
        {
            return Err(denied());
        }
        let private = rustls::pki_types::PrivatePkcs8KeyDer::from(pems.remove(0).into_contents());
        let signing =
            rustls::crypto::ring::sign::any_ecdsa_type(&private.into()).map_err(|_| denied())?;
        let chain: Vec<_> = pems
            .into_iter()
            .map(|p| rustls::pki_types::CertificateDer::from(p.into_contents()))
            .collect();
        let key = CertifiedKey::new(chain, signing);
        key.keys_match().map_err(|_| denied())?;
        let (rest, cert) =
            x509_parser::parse_x509_certificate(&key.cert[0]).map_err(|_| denied())?;
        if !rest.is_empty() {
            return Err(denied());
        }
        let not_before =
            u64::try_from(cert.validity().not_before.timestamp()).map_err(|_| denied())?;
        let not_after =
            u64::try_from(cert.validity().not_after.timestamp()).map_err(|_| denied())?;
        if not_before >= not_after {
            return Err(denied());
        }
        let san = cert
            .subject_alternative_name()
            .map_err(|_| denied())?
            .ok_or_else(denied)?;
        let mut actual = Vec::new();
        for name in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(name) = name {
                actual.push((*name).to_owned());
            } else {
                return Err(denied());
            }
        }
        actual.sort();
        let mut expected = domains.to_vec();
        expected.sort();
        if actual != expected {
            return Err(denied());
        }
        let parsed =
            rustls::server::ParsedCertificate::try_from(&key.cert[0]).map_err(|_| denied())?;
        for name in domains {
            rustls::client::verify_server_name(
                &parsed,
                &rustls::pki_types::ServerName::try_from(name.as_str()).map_err(|_| denied())?,
            )
            .map_err(|_| denied())?;
        }
        Ok(Self {
            key: Arc::new(key),
            not_before,
            not_after,
        })
    }
    fn active(&self) -> bool {
        unix_now().is_ok_and(|now| activate(self.not_before, self.not_after, now, true, true, true))
    }
}
struct Challenge {
    domain: String,
    key: Arc<CertifiedKey>,
    until: Instant,
}
pub struct Identity {
    domains: Vec<String>,
    pub(crate) certificate: RwLock<Option<Arc<Certificate>>>,
    challenge: RwLock<Option<Challenge>>,
}
impl Identity {
    /// Public certificate validity only; never returns certificate/key material.
    pub fn certificate_times(&self) -> Option<(u64, u64)> {
        self.certificate
            .read()
            .ok()?
            .as_ref()
            .map(|c| (c.not_before, c.not_after))
    }

    pub(crate) fn new(domains: Vec<String>, certificate: Option<Certificate>) -> Self {
        Self {
            domains,
            certificate: RwLock::new(certificate.map(Arc::new)),
            challenge: RwLock::new(None),
        }
    }
    pub(crate) fn challenge(&self, domain: String, key: CertifiedKey) -> io::Result<()> {
        if !self.domains.contains(&domain) {
            return Err(denied());
        }
        *self.challenge.write().map_err(|_| denied())? = Some(Challenge {
            domain,
            key: Arc::new(key),
            until: Instant::now() + Duration::from_secs(300),
        });
        Ok(())
    }
    pub(crate) fn clear_challenge(&self) {
        if let Ok(mut challenge) = self.challenge.write() {
            *challenge = None;
        }
    }
    pub(crate) fn install(&self, certificate: Certificate, persisted: bool) -> io::Result<()> {
        if !activate(
            certificate.not_before,
            certificate.not_after,
            unix_now()?,
            true,
            true,
            persisted,
        ) {
            return Err(denied());
        }
        *self.certificate.write().map_err(|_| denied())? = Some(Arc::new(certificate));
        Ok(())
    }
    fn known(&self, name: &str) -> bool {
        self.domains
            .iter()
            .any(|d| identity_allowed(name.as_bytes(), name.as_bytes(), d.as_bytes()))
    }
}
struct Resolver {
    identity: Arc<Identity>,
    challenge: bool,
}
impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PathWardCertificateResolver")
    }
}
impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?;
        if !self.identity.known(name) {
            return None;
        }
        if self.challenge {
            let locked = self.identity.challenge.read().ok()?;
            let cert = locked.as_ref()?;
            if cert.domain != name || Instant::now() >= cert.until {
                return None;
            }
            Some(cert.key.clone())
        } else {
            let locked = self.identity.certificate.read().ok()?;
            let cert = locked.as_ref()?;
            cert.active().then(|| cert.key.clone())
        }
    }
}
pub struct TlsServer {
    identity: Arc<Identity>,
    normal: Arc<ServerConfig>,
    challenge: Arc<ServerConfig>,
}
impl TlsServer {
    pub fn new(identity: Arc<Identity>) -> io::Result<Self> {
        let config = |challenge| -> io::Result<Arc<ServerConfig>> {
            let mut cfg = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|_| denied())?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver {
                identity: identity.clone(),
                challenge,
            }));
            cfg.alpn_protocols = if challenge {
                vec![b"acme-tls/1".to_vec()]
            } else {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            };
            cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            cfg.send_tls13_tickets = 0;
            cfg.max_early_data_size = 0;
            Ok(Arc::new(cfg))
        };
        let normal = config(false)?;
        let challenge = config(true)?;
        Ok(Self {
            identity,
            normal,
            challenge,
        })
    }
    pub(crate) fn quic_config(&self) -> io::Result<quinn::ServerConfig> {
        let mut cfg = self.normal.as_ref().clone();
        cfg.alpn_protocols = vec![b"h3".to_vec()];
        // Stateful, single-use resumption tickets. Secrets remain in bounded memory.
        cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
        cfg.send_tls13_tickets = 2;
        cfg.max_early_data_size = u32::MAX;
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(cfg).map_err(|_| denied())?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config
            .migration(true)
            .max_incoming(64)
            .incoming_buffer_size(131072)
            .incoming_buffer_size_total(8388608);
        let transport = Arc::get_mut(&mut config.transport).ok_or_else(denied)?;
        transport
            .max_concurrent_bidi_streams(32u32.into())
            .max_concurrent_uni_streams(3u32.into())
            .stream_receive_window(16384u32.into())
            .receive_window(65535u32.into())
            .send_window(131072)
            .crypto_buffer_size(131072)
            .datagram_receive_buffer_size(None)
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .max_idle_timeout(Some(
                Duration::from_secs(30).try_into().map_err(|_| denied())?,
            ));
        Ok(config)
    }
    pub(crate) fn current_identity(&self, name: &str) -> bool {
        self.identity.known(name)
            && self
                .identity
                .certificate
                .read()
                .ok()
                .is_some_and(|c| c.as_ref().is_some_and(|c| c.active()))
    }
    /// Blocking compatibility API for embedders and focused transport tests.
    pub fn accept(&self, stream: TcpStream, accepted: Instant) -> io::Result<Option<TlsTransport>> {
        let result = futures_lite::future::block_on(self.accept_async(stream, accepted))?;
        if let Some(transport) = &result {
            transport.stream.sock.stream.set_nonblocking(false)?;
        }
        Ok(result)
    }
    /// ACME validation connections complete TLS and return without HTTP dispatch.
    pub async fn accept_async(
        &self,
        stream: TcpStream,
        accepted: Instant,
    ) -> io::Result<Option<TlsTransport>> {
        stream.set_nonblocking(true)?;
        let mut socket = DeadlineTcp {
            stream,
            deadline: accepted + HANDSHAKE_BUDGET,
            read_left: Some(131_072),
        };
        let mut acceptor = Acceptor::default();
        let accepted = loop {
            if crate::async_http::operation(socket.deadline, || acceptor.read_tls(&mut socket))
                .await?
                == 0
            {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            match acceptor.accept() {
                Ok(Some(a)) => break a,
                Ok(None) => {}
                Err(_) => return Err(denied()),
            }
        };
        let hello = accepted.client_hello();
        let name = hello.server_name().ok_or_else(denied)?.to_owned();
        if !self.identity.known(&name) {
            return Err(denied());
        }
        let protocols: Vec<_> = hello.alpn().into_iter().flatten().collect();
        let challenge = protocols == [b"acme-tls/1".as_slice()];
        if !challenge && protocols.iter().any(|p| *p == b"acme-tls/1") {
            return Err(denied());
        }
        let config = if challenge {
            self.challenge.clone()
        } else {
            self.normal.clone()
        };
        let mut conn = accepted.into_connection(config).map_err(|_| denied())?;
        conn.set_buffer_limit(Some(32_768));
        while conn.is_handshaking() {
            crate::async_http::operation(socket.deadline, || conn.complete_io(&mut socket)).await?;
        }
        while conn.wants_write() {
            crate::async_http::operation(socket.deadline, || conn.write_tls(&mut socket)).await?;
        }
        if challenge {
            return Ok(None);
        }
        socket.read_left = None;
        Ok(Some(TlsTransport {
            stream: StreamOwned::new(conn, socket),
            sni: name,
        }))
    }
}
pub struct DeadlineTcp {
    stream: TcpStream,
    deadline: Instant,
    read_left: Option<usize>,
}
impl DeadlineTcp {
    fn prepare(&self) -> io::Result<()> {
        let left = http::remaining(self.deadline)?;
        self.stream.set_read_timeout(Some(left))?;
        self.stream.set_write_timeout(Some(left))
    }
}
impl Read for DeadlineTcp {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.prepare()?;
        let limit = self.read_left.unwrap_or(b.len()).min(b.len());
        if limit == 0 && !b.is_empty() {
            return Err(denied());
        }
        let n = self.stream.read(&mut b[..limit])?;
        if let Some(left) = &mut self.read_left {
            *left -= n;
        }
        Ok(n)
    }
}
impl Write for DeadlineTcp {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.prepare()?;
        self.stream.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.prepare()?;
        self.stream.flush()
    }
}
pub struct TlsTransport {
    stream: StreamOwned<ServerConnection, DeadlineTcp>,
    pub sni: String,
}
impl Read for TlsTransport {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.stream.read(b)
    }
}
impl Write for TlsTransport {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.stream.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
impl Transport for TlsTransport {
    fn nonblocking(&mut self) -> io::Result<()> {
        self.stream.conn.set_buffer_limit(Some(32768));
        self.stream.sock.stream.set_nonblocking(true)
    }
    fn deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.stream.sock.deadline = deadline;
        self.stream.sock.prepare()
    }
    fn local_port(&self) -> io::Result<u16> {
        Ok(self.stream.sock.stream.local_addr()?.port())
    }
    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.stream.sock.stream.peer_addr().ok().map(|a| a.ip())
    }
}
impl TlsTransport {
    pub(crate) fn is_h2(&self) -> bool {
        self.stream.conn.alpn_protocol() == Some(b"h2")
    }
    pub fn finish(&mut self) -> io::Result<()> {
        self.stream.conn.send_close_notify();
        self.stream.flush()
    }
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
