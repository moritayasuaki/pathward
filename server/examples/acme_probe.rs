//! Read-only public-CA transport probe: GET directory and HEAD nonce only.
//! No account, order, validation request, certificate, or cache is created.
use pathward_server::acme;
use rustls_acme::{acme::Directory, https_helper::HttpsClient};
use std::{sync::Arc, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let url = match args.as_slice() {
        [name] if name == "production" => acme::PRODUCTION,
        [name] if name == "staging" => acme::STAGING,
        _ => return Err("usage: acme_probe production|staging (read-only)".into()),
    };
    let client = Arc::new(HttpsClient::new(url, acme::public_client_config()?)?);
    let started = Instant::now();
    futures_lite::future::block_on(async {
        let directory = Directory::discover(&client, url).await?;
        for endpoint in [
            &directory.new_nonce,
            &directory.new_account,
            &directory.new_order,
        ] {
            client.check_url(endpoint)?;
        }
        let nonce = directory.nonce(&client).await?;
        if nonce.is_empty() {
            return Err("missing replay nonce".into());
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    println!(
        "ACME_READ_ONLY_OK: verified directory and nonce in {} ms; no issuance requested",
        started.elapsed().as_millis()
    );
    Ok(())
}
