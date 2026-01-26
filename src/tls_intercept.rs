use std::{io, sync::Arc, sync::OnceLock, time::Duration};

use anyhow::{Context, Result};
use moka::future::Cache;
use monoio::{
  BufResult,
  buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut},
  io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Split, Splitable},
  net::TcpStream,
};
use monoio_rustls::{ServerTlsStream, TlsConnector};
use rustls::{
  ClientConfig, RootCertStore, ServerConfig,
  pki_types::{CertificateDer, PrivateKeyDer, ServerName},
  server::ResolvesServerCert,
  sign::CertifiedKey,
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

impl AsyncReadRent for PrefixedStream {
  async fn read<T: IoBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
    let remaining = self.prefix.len() - self.pos;
    if remaining > 0 {
      let to_copy = remaining.min(buf.bytes_total());
      let slice = unsafe { std::slice::from_raw_parts_mut(buf.write_ptr(), to_copy) };
      slice.copy_from_slice(&self.prefix[self.pos..self.pos + to_copy]);
      self.pos += to_copy;
      unsafe { buf.set_init(to_copy) };
      return (Ok(to_copy), buf);
    }
    self.inner.read(buf).await
  }

  async fn readv<T: IoVecBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
    // monoio-rustls does not use readv for reading client hello
    // Delegate to inner stream for vectored reads (prefix should be consumed during handshake)
    self.inner.readv(buf).await
  }
}

impl AsyncWriteRent for PrefixedStream {
  async fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
    self.inner.write(buf).await
  }

  async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
    self.inner.writev(buf).await
  }

  async fn flush(&mut self) -> std::io::Result<()> {
    self.inner.flush().await
  }

  async fn shutdown(&mut self) -> std::io::Result<()> {
    self.inner.shutdown().await
  }
}

unsafe impl Split for PrefixedStream {}

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
    let acceptor = monoio_rustls::TlsAcceptor::from(self.server_config);
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
  upstream: monoio_rustls::ClientTlsStream<TcpStream>,
  mirror: TcpStream,
) -> Result<()> {
  let (mut client_r, mut client_w) = client.into_split();
  let (mut upstream_r, mut upstream_w) = upstream.into_split();
  let (mut mirror_r, mirror_w) = mirror.into_split();
  let mirror_w = Arc::new(futures::lock::Mutex::new(mirror_w));

  let mw1 = mirror_w.clone();
  let upload = async move {
    let mut buf = vec![0u8; 16384];
    loop {
      let (res, b) = client_r.read(buf).await;
      buf = b;
      let n = match res {
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
        let _ = guard.write_all(frame).await;
      }

      let slice = buf.slice(..n);
      let (res, slice) = upstream_w.write_all(slice).await;
      buf = slice.into_inner();
      res?;
    }
  };

  let mw2 = mirror_w.clone();
  let download = async move {
    let mut buf = vec![0u8; 16384];
    loop {
      let (res, b) = upstream_r.read(buf).await;
      buf = b;
      let n = match res {
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
        let _ = guard.write_all(frame).await;
      }

      let slice = buf.slice(..n);
      let (res, slice) = client_w.write_all(slice).await;
      buf = slice.into_inner();
      res?;
    }
  };

  let res = monoio::select! {
    x = upload => x,
    x = download => x,
    _ = mirror_r.read(vec![0u8; 1]) => Ok(()),
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

  let ca_cert_pem = monoio::fs::read(ca_cert_path)
    .await
    .with_context(|| format!("failed to read CA cert: {}", ca_cert_path))?;
  let ca_key_pem = monoio::fs::read(ca_key_path)
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
