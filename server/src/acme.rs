//! One bounded ACME worker for the fixed configured SAN set. No client-driven issuance.
use crate::{
    secrets::SecretStore,
    tls::{Certificate, Identity, unix_now},
};
use futures_lite::future;
use rustls::{ClientConfig, RootCertStore};
use rustls_acme::{
    acme::{Account, AuthStatus, Directory, Identifier, OrderStatus},
    https_helper::HttpsClient,
};
use std::{
    io,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const STAGING: &str = rustls_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY;
pub const PRODUCTION: &str = rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY;
const ORDER_BUDGET: Duration = Duration::from_secs(600);
fn error() -> io::Error {
    io::Error::other("ACME operation failed")
}

pub fn public_client_config() -> io::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| error())?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub struct Manager {
    domains: Vec<String>,
    contact: Vec<String>,
    directory: String,
    client: Arc<HttpsClient>,
    account_key: Vec<u8>,
    cache: SecretStore,
    identity: Arc<Identity>,
}
impl Manager {
    /// Custom HTTPS origins/trust roots are an explicit library/test boundary.
    /// The shipped CLI permits only the two fixed Let's Encrypt directories.
    pub fn new(
        domains: Vec<String>,
        roots: &[&str],
        cache_path: &Path,
        directory: &str,
        contact: Vec<String>,
        client: Arc<ClientConfig>,
    ) -> io::Result<Self> {
        if domains.is_empty()
            || domains.len() > 16
            || domains.iter().any(|d| {
                !d.contains('.')
                    || d.len() > 253
                    || d.parse::<std::net::IpAddr>().is_ok()
                    || !d.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                            && label.as_bytes()[0].is_ascii_alphanumeric()
                            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    })
            })
        {
            return Err(error());
        }
        let mut unique = domains.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != domains.len()
            || contact.len() > 1
            || contact.iter().any(|c| {
                c.len() > 254
                    || !c.starts_with("mailto:")
                    || !c.bytes().all(|b| (0x21..=0x7e).contains(&b))
            })
        {
            return Err(error());
        }
        let client = Arc::new(HttpsClient::new(directory, client)?);
        let cache = SecretStore::open(cache_path, roots)?;
        let binding = format!(
            "pathward-acme-v1\n{directory}\n{}\n{}\n",
            unique.join("\n"),
            contact.join("\n")
        );
        cache.bind(binding.as_bytes())?;
        let account_key = match cache.load_account()? {
            Some(bytes) => bytes,
            None => {
                let bytes = Account::generate_key_pair().map_err(|_| error())?;
                cache.store_account(&bytes)?;
                bytes
            }
        };
        // Corrupt account data fails startup; never silently create a replacement account.
        ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &account_key,
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|_| error())?;
        let certificate = cache
            .load_certificate()?
            .map(|pem| Certificate::parse(&pem, &domains))
            .transpose()?;
        let identity = Arc::new(Identity::new(domains.clone(), certificate));
        Ok(Self {
            domains,
            contact,
            directory: directory.to_owned(),
            client,
            account_key,
            cache,
            identity,
        })
    }
    pub fn identity(&self) -> Arc<Identity> {
        self.identity.clone()
    }
    fn due(&self) -> bool {
        let Ok(now) = unix_now() else { return true };
        self.identity
            .certificate
            .read()
            .ok()
            .and_then(|c| {
                c.as_ref()
                    .map(|c| pathward::tls::renewal_due(c.not_before, c.not_after, now))
            })
            .unwrap_or(true)
    }
    async fn order(&self) -> io::Result<Vec<u8>> {
        let directory = Directory::discover(&self.client, &self.directory)
            .await
            .map_err(|_| error())?;
        for url in [
            &directory.new_nonce,
            &directory.new_account,
            &directory.new_order,
        ] {
            self.client.check_url(url)?;
        }
        let account =
            Account::create_with_keypair(&self.client, directory, &self.contact, &self.account_key)
                .await
                .map_err(|_| error())?;
        self.client.check_url(&account.kid)?;
        let mut params =
            rcgen::CertificateParams::new(self.domains.clone()).map_err(|_| error())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|_| error())?;
        let csr = params.serialize_request(&key).map_err(|_| error())?;
        let (order_url, mut order) = account
            .new_order(&self.client, self.domains.clone())
            .await
            .map_err(|_| error())?;
        self.client.check_url(&order_url)?;
        for _ in 0..64 {
            if order.authorizations.len() > self.domains.len() {
                return Err(error());
            }
            match order.status {
                OrderStatus::Pending => {
                    let mut authorized = Vec::new();
                    for url in &order.authorizations {
                        let auth = account.auth(&self.client, url).await.map_err(|_| error())?;
                        let Identifier::Dns(domain) = auth.identifier;
                        if !self.domains.contains(&domain)
                            || authorized.contains(&domain)
                            || auth.challenges.len() > 16
                        {
                            return Err(error());
                        }
                        authorized.push(domain.clone());
                        match auth.status {
                            AuthStatus::Valid => continue,
                            AuthStatus::Pending => {}
                            _ => return Err(error()),
                        }
                        let (challenge, cert) = account
                            .tls_alpn_01(&auth.challenges, domain.clone())
                            .map_err(|_| error())?;
                        self.identity.challenge(domain.clone(), cert)?;
                        account
                            .challenge(&self.client, &challenge.url)
                            .await
                            .map_err(|_| error())?;
                        let mut valid = false;
                        for _ in 0..60 {
                            async_io::Timer::after(Duration::from_secs(1)).await;
                            let auth =
                                account.auth(&self.client, url).await.map_err(|_| error())?;
                            let Identifier::Dns(name) = auth.identifier;
                            if name != domain {
                                return Err(error());
                            }
                            match auth.status {
                                AuthStatus::Valid => {
                                    valid = true;
                                    break;
                                }
                                AuthStatus::Pending => {}
                                _ => return Err(error()),
                            }
                        }
                        self.identity.clear_challenge();
                        if !valid {
                            return Err(error());
                        }
                    }
                }
                OrderStatus::Ready => {
                    order = account
                        .finalize(&self.client, &order.finalize, csr.der())
                        .await
                        .map_err(|_| error())?;
                    continue;
                }
                OrderStatus::Processing => {}
                OrderStatus::Valid { certificate } => {
                    let chain = account
                        .certificate(&self.client, certificate)
                        .await
                        .map_err(|_| error())?;
                    let pem = format!("{}\n{chain}", key.serialize_pem()).into_bytes();
                    if pem.len() > 1_048_576 {
                        return Err(error());
                    }
                    return Ok(pem);
                }
                OrderStatus::Invalid => return Err(error()),
            }
            async_io::Timer::after(Duration::from_secs(2)).await;
            order = account
                .order(&self.client, &order_url)
                .await
                .map_err(|_| error())?;
        }
        Err(error())
    }
    /// Failed orders keep the last durable certificate, with bounded backoff.
    /// Poll continuously; stopping this worker stops automatic renewal.
    pub fn run(&self, shutdown: &AtomicBool) {
        future::block_on(async {
            let mut next = Instant::now();
            let mut retry = 60u64;
            let mut previous = "";
            while !shutdown.load(Ordering::Acquire) {
                let now = unix_now().unwrap_or(0);
                let health = self
                    .identity
                    .certificate
                    .read()
                    .ok()
                    .and_then(|c| {
                        c.as_ref().map(|c| {
                            if now < c.not_before || now >= c.not_after {
                                "unavailable"
                            } else if pathward::tls::renewal_due(c.not_before, c.not_after, now) {
                                "renewal_due"
                            } else {
                                "ready"
                            }
                        })
                    })
                    .unwrap_or("awaiting_certificate");
                if health != previous {
                    eprintln!("tls certificate state={health}");
                    previous = health;
                }
                if self.due() && Instant::now() >= next {
                    eprintln!("acme event=order_started");
                    let result = future::or(self.order(), async {
                        let deadline = Instant::now() + ORDER_BUDGET;
                        loop {
                            if shutdown.load(Ordering::Acquire) || Instant::now() >= deadline {
                                return Err(error());
                            }
                            async_io::Timer::after(Duration::from_millis(100)).await;
                        }
                    })
                    .await;
                    self.identity.clear_challenge();
                    if shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    let result = result.and_then(|pem| {
                        let cert = Certificate::parse(&pem, &self.domains)?;
                        if !pathward::tls::activate(
                            cert.not_before,
                            cert.not_after,
                            unix_now()?,
                            true,
                            true,
                            true,
                        ) {
                            return Err(error());
                        }
                        self.cache.store_certificate(&pem)?;
                        self.identity.install(cert, true)
                    });
                    if result.is_ok() {
                        eprintln!("acme event=certificate_persisted_and_activated");
                        retry = 60;
                        // Even an unusually short-lived CA certificate cannot cause a tight order loop.
                        next = Instant::now() + Duration::from_secs(1);
                    } else {
                        eprintln!("acme event=order_or_persistence_failed retry_seconds={retry}");
                        next = Instant::now() + Duration::from_secs(retry);
                        retry = (retry * 2).min(3600);
                    }
                }
                async_io::Timer::after(Duration::from_secs(1)).await;
            }
            self.identity.clear_challenge();
        });
    }
}
