use std::{
  io,
  pin::Pin,
  sync::Arc,
  sync::OnceLock,
  task::{Context as TaskContext, Poll},
  time::Duration,
};

use anyhow::{Context, Result};
use moka::future::Cache;
use rustls::{
  ClientConfig, RootCertStore, ServerConfig,
  pki_types::{CertificateDer, PrivateKeyDer, ServerName},
  server::ResolvesServerCert,
  sign::CertifiedKey,
};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
  net::TcpStream,
  sync::Mutex,
};
use tokio_rustls::{
  TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream,
  server::TlsStream as ServerTlsStream,
};

use crate::rule_table::{MirrorAddr, TlsInterceptConfig};

const MIRROR_CLIENT_PREFIX: u8 = 0x00;
const MIRROR_SERVER_PREFIX: u8 = 0x01;

/// A stream wrapper that prepends buffered bytes before reading from the underlying stream.
struct PrefixedStream {
  prefix: Vec<u8>,
  pos: usize,
  inner: TcpStream,
}

impl PrefixedStream {
  fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
    Self {
      prefix,
      pos: 0,
      inner,
    }
  }
}

impl AsyncRead for PrefixedStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    let remaining = self.prefix.len() - self.pos;
    if remaining > 0 {
      let to_copy = remaining.min(buf.remaining());
      buf.put_slice(&self.prefix[self.pos..self.pos + to_copy]);
      self.pos += to_copy;
      return Poll::Ready(Ok(()));
    }
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl AsyncWrite for PrefixedStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

pub struct TlsInterceptor {
  server_config: Arc<ServerConfig>,
  client_config: Arc<ClientConfig>,
  mirror: MirrorAddr,
}

impl TlsInterceptor {
  pub async fn new(config: &TlsInterceptConfig, hostname: &str) -> Result<Self> {
    let cert = get_or_generate_cert(&config.ca_cert, &config.ca_key, hostname).await?;
    let resolver = SingleCertResolver(cert);

    let server_config = ServerConfig::builder()
      .with_no_client_auth()
      .with_cert_resolver(Arc::new(resolver));

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = ClientConfig::builder()
      .with_root_certificates(root_store)
      .with_no_client_auth();

    Ok(Self {
      server_config: Arc::new(server_config),
      client_config: Arc::new(client_config),
      mirror: config.mirror.clone(),
    })
  }

  pub async fn intercept(
    self,
    client: TcpStream,
    upstream: TcpStream,
    client_hello: Vec<u8>,
    hostname: &str,
  ) -> Result<()> {
    let acceptor = TlsAcceptor::from(self.server_config);
    let connector = TlsConnector::from(self.client_config);

    // Get client address before wrapping the stream
    let client_addr = client.peer_addr()?;
    let mirror_addr = self.mirror.resolve(client_addr);

    let server_name: ServerName<'static> = hostname.to_owned().try_into()?;
    let upstream_tls = connector.connect(server_name, upstream).await?;

    // Wrap the client stream with the buffered ClientHello so the acceptor can read it
    let prefixed_client = PrefixedStream::new(client_hello, client);
    let client_tls = acceptor.accept(prefixed_client).await?;

    let mirror = TcpStream::connect(mirror_addr).await?;

    relay_intercepted(client_tls, upstream_tls, mirror).await
  }
}

async fn relay_intercepted(
  client: ServerTlsStream<PrefixedStream>,
  upstream: ClientTlsStream<TcpStream>,
  mirror: TcpStream,
) -> Result<()> {
  let (mut client_r, mut client_w) = tokio::io::split(client);
  let (mut upstream_r, mut upstream_w) = tokio::io::split(upstream);
  let (mut mirror_r, mirror_w) = mirror.into_split();
  let mirror_w = Arc::new(Mutex::new(mirror_w));

  let mw1 = mirror_w.clone();
  let upload = async move {
    let mut buf = vec![0u8; 16384];
    loop {
      let n = match client_r.read(&mut buf).await {
        Ok(0) => break Ok::<_, io::Error>(()),
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break Ok(()),
        Err(e) => break Err(e),
      };

      // Mirror: prefix 0x00 + LE32 size (errors are non-fatal)
      let mut frame = vec![MIRROR_CLIENT_PREFIX];
      frame.extend_from_slice(&(n as u32).to_le_bytes());
      frame.extend_from_slice(&buf[..n]);
      {
        let mut guard = mw1.lock().await;
        let _ = guard.write_all(&frame).await;
      }

      upstream_w.write_all(&buf[..n]).await?;
    }
  };

  let mw2 = mirror_w.clone();
  let download = async move {
    let mut buf = vec![0u8; 16384];
    loop {
      let n = match upstream_r.read(&mut buf).await {
        Ok(0) => break Ok::<_, io::Error>(()),
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break Ok(()),
        Err(e) => break Err(e),
      };

      // Mirror: prefix 0x01 + LE32 size (errors are non-fatal)
      let mut frame = vec![MIRROR_SERVER_PREFIX];
      frame.extend_from_slice(&(n as u32).to_le_bytes());
      frame.extend_from_slice(&buf[..n]);
      {
        let mut guard = mw2.lock().await;
        let _ = guard.write_all(&frame).await;
      }

      client_w.write_all(&buf[..n]).await?;
    }
  };

  let mut mirror_probe = [0u8; 1];
  let res = tokio::select! {
    x = upload => x,
    x = download => x,
    _ = mirror_r.read(&mut mirror_probe) => Ok(()),
  };
  match res {
    Ok(_) => {}
    Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {}
    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
    Err(e) => return Err(e.into()),
  }
  Ok(())
}

fn cert_cache() -> &'static Cache<String, Arc<CertifiedKey>> {
  static CACHE: OnceLock<Cache<String, Arc<CertifiedKey>>> = OnceLock::new();
  CACHE.get_or_init(|| {
    Cache::builder()
      .max_capacity(1_000)
      .time_to_live(Duration::from_secs(600))
      .build()
  })
}

struct Ca {
  cert: x509_cert::Certificate,
  signer: p256::ecdsa::SigningKey,
}

async fn load_ca(ca_cert_path: &str, ca_key_path: &str) -> Result<Ca> {
  use der::Decode;
  use p256::pkcs8::DecodePrivateKey;
  use sec1::DecodeEcPrivateKey;

  let ca_cert_pem = tokio::fs::read(ca_cert_path)
    .await
    .with_context(|| format!("failed to read CA cert: {}", ca_cert_path))?;
  let ca_key_pem = tokio::fs::read(ca_key_path)
    .await
    .with_context(|| format!("failed to read CA key: {}", ca_key_path))?;

  let ca_cert_der = rustls_pemfile::certs(&mut ca_cert_pem.as_slice())
    .next()
    .context("no certificate found")?
    .context("failed to parse CA cert")?;
  let ca_key = rustls_pemfile::private_key(&mut ca_key_pem.as_slice())
    .context("failed to parse CA key")?
    .context("no private key found")?;

  let cert =
    x509_cert::Certificate::from_der(&ca_cert_der).context("failed to parse CA cert as X.509")?;

  // Try PKCS#8 first, then SEC1 format
  let signer = p256::ecdsa::SigningKey::from_pkcs8_der(ca_key.secret_der())
    .or_else(|_| p256::ecdsa::SigningKey::from_sec1_der(ca_key.secret_der()))
    .context("CA key must be ECDSA P-256")?;

  Ok(Ca { cert, signer })
}

async fn get_or_generate_cert(
  ca_cert_path: &str,
  ca_key_path: &str,
  hostname: &str,
) -> Result<Arc<CertifiedKey>> {
  let cache = cert_cache();

  cache
    .try_get_with(hostname.to_owned(), async {
      let ca = load_ca(ca_cert_path, ca_key_path).await?;
      Ok(Arc::new(generate_cert(&ca, hostname)?))
    })
    .await
    .map_err(|e: Arc<anyhow::Error>| anyhow::anyhow!("{e}"))
}

fn generate_cert(ca: &Ca, hostname: &str) -> Result<CertifiedKey> {
  use der::{Decode, Encode};
  use p256::ecdsa::DerSignature;
  use p256::pkcs8::EncodePrivateKey;
  use spki::EncodePublicKey;
  use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    ext::pkix::{SubjectAltName, name::GeneralName},
    serial_number::SerialNumber,
    time::Validity,
  };

  // Generate leaf key pair (ECDSA P-256)
  let leaf_signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
  let leaf_spki_doc = leaf_signing_key.verifying_key().to_public_key_der()?;
  let leaf_spki_der = spki::SubjectPublicKeyInfoOwned::from_der(leaf_spki_doc.as_bytes())?;

  // Subject name: CN=hostname
  let cn_attr = x509_cert::attr::AttributeTypeAndValue {
    oid: const_oid::db::rfc4519::CN,
    value: der::asn1::Any::from(der::asn1::Utf8StringRef::new(hostname)?),
  };
  let rdn =
    x509_cert::name::RelativeDistinguishedName::from(der::asn1::SetOfVec::try_from(vec![cn_attr])?);
  let subject = x509_cert::name::RdnSequence(vec![rdn]);

  // Issuer: CA's subject DN
  let issuer = ca.cert.tbs_certificate.subject.clone();

  // Validity: now to +1 day
  let validity = Validity::from_now(std::time::Duration::from_secs(86400))?;

  // Random serial number
  let mut serial_bytes = [0u8; 16];
  rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut serial_bytes);
  serial_bytes[0] &= 0x7f; // Ensure positive
  let serial = SerialNumber::new(&serial_bytes)?;

  // SAN extension
  let san = SubjectAltName(vec![GeneralName::DnsName(der::asn1::Ia5String::new(
    hostname,
  )?)]);

  let profile = Profile::Leaf {
    issuer,
    enable_key_agreement: true,
    enable_key_encipherment: true,
    include_subject_key_identifier: true,
  };

  // Build and sign certificate
  let mut builder = CertificateBuilder::new(
    profile,
    serial,
    validity,
    subject,
    leaf_spki_der,
    &ca.signer,
  )?;
  builder.add_extension(&san)?;
  let leaf_cert_der = builder.build::<DerSignature>()?.to_der()?;

  // Convert to rustls types
  let cert_der = CertificateDer::from(leaf_cert_der);
  let leaf_key_der = leaf_signing_key.to_pkcs8_der()?;
  let key_der = PrivateKeyDer::Pkcs8(leaf_key_der.as_bytes().to_vec().into());
  let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der)?;

  Ok(CertifiedKey::new(vec![cert_der], signing_key))
}

#[derive(Debug)]
struct SingleCertResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for SingleCertResolver {
  fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    Some(self.0.clone())
  }
}

#[cfg(test)]
mod tests {
  use super::PrefixedStream;
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
  };

  #[tokio::test]
  async fn prefixed_stream_replays_prefix_then_delegates_io() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let client = client.unwrap();
    let mut peer = accepted.unwrap().0;
    let mut stream = PrefixedStream::new(b"prefix".to_vec(), client);

    peer.write_all(b"socket").await.unwrap();
    let mut read = [0u8; 12];
    stream.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, b"prefixsocket");

    stream.write_all(b"reply").await.unwrap();
    let mut reply = [0u8; 5];
    peer.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");
  }
}
