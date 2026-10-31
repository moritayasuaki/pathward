//! PathWard's narrowly maintained, attributed low-level rustls-acme fork.
//! See PROVENANCE.md. No upstream cache, resolver, acceptor or renewal state.
#![forbid(unsafe_code)]
pub mod acme;
pub mod https_helper;
mod jose;
use ring as crypto;
pub(crate) fn any_ecdsa_type(
    der: &futures_rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<
    std::sync::Arc<dyn futures_rustls::rustls::sign::SigningKey>,
    futures_rustls::rustls::Error,
> {
    futures_rustls::rustls::crypto::ring::sign::any_ecdsa_type(der)
}
