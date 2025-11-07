mod rule_table;

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use rule_table::RuleTable;
use std::{
  collections::{HashMap, HashSet},
  io,
  net::{IpAddr, SocketAddr, ToSocketAddrs},
  os::fd::{AsRawFd, RawFd},
  path::PathBuf,
  str,
  sync::{Arc, Mutex, OnceLock},
  time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use http::{Method, StatusCode, Version, header};
use moka::future::Cache;
use monoio::{
  IoUringDriver,
  io::{AsyncReadRentExt, AsyncWriteRentExt, Splitable, copy, sink::Sink, stream::Stream},
  net::{TcpListener, TcpStream},
};
use monoio_http::{
  common::{body::Body, error::HttpError, request::Request},
  h1::{codec::ClientCodec, payload::Payload},
};
use monoio_rustls::{ClientTlsStream, TlsConnector};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use tls_parser::{
  SNIType, TlsExtension, TlsMessage, TlsMessageHandshake, TlsPlaintext,
  parse_tls_client_hello_extensions, parse_tls_plaintext,
};
use url::{Url, form_urlencoded};
use webpki_roots::TLS_SERVER_ROOTS;

const DEFAULT_DOH_PATH: &str = "/dns-query";
const MAX_CLIENT_HELLO_SIZE: usize = 64 * 1024;
const TARGET_PORT: u16 = 443;
const USER_AGENT: &str = concat!("zerosni/", env!("CARGO_PKG_VERSION"));
const DNS_CACHE_TTL_SECS: u64 = 180;
const DNS_CACHE_CAPACITY: u64 = 16384;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
  /// Address to accept redirected TLS connections from.
  #[arg(long)]
  listen: SocketAddr,
  /// DNS-over-HTTPS resolver endpoint (must be HTTPS).
  #[arg(long)]
  resolver: String,
  /// Firewall mark to apply to outbound sockets (Linux only).
  #[arg(long)]
  fwmark: Option<u32>,
  /// Path to a JSON rule table that overrides resolver/fwmark per hostname.
  #[arg(long = "rule-table")]
  rule_table: Option<PathBuf>,
}

struct ProxyContext {
  doh: Arc<DohClient>,
  default_resolver: String,
  default_fwmark: Option<u32>,
  rule_table: Arc<ArcSwapOption<RuleTable>>,
}

struct RouteSelection {
  resolver_url: String,
  fwmark: Option<u32>,
}

impl ProxyContext {
  fn select_route(&self, hostname: &str) -> RouteSelection {
    let overrides = self
      .rule_table
      .load_full()
      .as_ref()
      .and_then(|table| table.lookup(hostname));
    let resolver_url = overrides
      .as_ref()
      .and_then(|rule| rule.resolver.clone())
      .unwrap_or_else(|| self.default_resolver.clone());
    let fwmark = overrides
      .as_ref()
      .and_then(|rule| rule.fwmark)
      .or(self.default_fwmark);
    RouteSelection {
      resolver_url,
      fwmark,
    }
  }
}

struct DohClient {
  connector: TlsConnector,
  cache: &'static Cache<String, Vec<IpAddr>>,
  resolvers: Mutex<HashMap<String, Arc<ResolverConfig>>>,
}

#[derive(Debug, Clone)]
struct ResolverConfig {
  server_name: ServerName<'static>,
  host: String,
  port: u16,
  authority: String,
  path: String,
  base_query: Vec<(String, String)>,
}

#[derive(Clone, Copy)]
enum RecordType {
  A,
  Aaaa,
}

#[derive(Deserialize)]
struct DohResponse {
  #[serde(rename = "Status")]
  status: u32,
  #[serde(rename = "Answer")]
  answers: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
  #[serde(rename = "type")]
  record_type: u16,
  #[serde(rename = "data")]
  data: String,
}

struct ClientHelloCapture {
  hostname: String,
  buffer: Vec<u8>,
}

fn install_crypto_provider() -> Result<()> {
  static INSTALLED: OnceLock<()> = OnceLock::new();
  INSTALLED.get_or_init(|| {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
  });
  Ok(())
}

fn main() -> Result<()> {
  monoio::RuntimeBuilder::<IoUringDriver>::new()
    .build()
    .expect("zerosni: failed to build io_uring runtime")
    .block_on(amain())
}

async fn amain() -> Result<()> {
  let args = Cli::parse();

  let default_resolver = args.resolver.clone();
  let fwmark = args.fwmark.filter(|mark| *mark != 0);
  let doh = Arc::new(DohClient::new()?);
  let rule_table_path = args.rule_table.clone();
  let initial_rule_table = if let Some(path) = rule_table_path.as_ref() {
    Some(Arc::new(RuleTable::from_file(path)?))
  } else {
    None
  };
  let rule_table = Arc::new(ArcSwapOption::from(initial_rule_table));

  eprintln!(
    "zerosni listening on {} (resolver: {})",
    args.listen, default_resolver
  );

  let ctx = Arc::new(ProxyContext {
    doh,
    default_resolver,
    default_fwmark: fwmark,
    rule_table: rule_table.clone(),
  });

  if let Some(path) = rule_table_path {
    install_rule_table_reloader(rule_table, path);
  }
  let listener = TcpListener::bind(args.listen)?;

  loop {
    let accepted = listener.accept().await;
    match accepted {
      Ok((stream, peer)) => {
        if let Err(err) = stream.set_nodelay(true) {
          eprintln!("failed to set nodelay on accepted stream: {err}");
        }
        let ctx = ctx.clone();
        monoio::spawn(async move {
          if let Err(err) = handle_client(stream, peer, ctx).await {
            eprintln!("connection from {peer} failed: {err:?}");
          }
        });
      }
      Err(err) => {
        eprintln!("accept error: {err}");
      }
    }
  }
}

fn install_rule_table_reloader(rule_table: Arc<ArcSwapOption<RuleTable>>, path: PathBuf) {
  use signal_hook::consts::signal::SIGHUP;
  use signal_hook::iterator::Signals;

  let path_display = path.display().to_string();
  if let Err(err) = std::thread::Builder::new()
    .name("zerosni-sighup".into())
    .spawn(move || {
      let mut signals = match Signals::new([SIGHUP]) {
        Ok(sig) => sig,
        Err(err) => {
          eprintln!("failed to install SIGHUP handler: {err}");
          return;
        }
      };
      for _ in signals.forever() {
        match RuleTable::from_file(&path) {
          Ok(table) => {
            rule_table.store(Some(Arc::new(table)));
            eprintln!("reloaded rule table from {path_display}");
          }
          Err(err) => {
            eprintln!("failed to reload rule table {path_display}: {err}");
          }
        }
      }
    })
  {
    eprintln!("failed to spawn rule-table reload handler: {err}");
  }
}

async fn handle_client(
  mut client: TcpStream,
  peer: SocketAddr,
  ctx: Arc<ProxyContext>,
) -> Result<()> {
  let hello = capture_client_hello(&mut client).await?;
  eprintln!("{peer} requested {}", hello.hostname);

  let RouteSelection {
    resolver_url,
    fwmark,
  } = ctx.select_route(&hello.hostname);

  let candidates = ctx
    .doh
    .resolve(&resolver_url, &hello.hostname, fwmark)
    .await
    .with_context(|| format!("resolver lookup for {}", hello.hostname))?;

  if candidates.is_empty() {
    bail!("no DNS answers for {}", hello.hostname);
  }

  let upstream = connect_to_any(&candidates, fwmark).await?;

  relay_streams(client, upstream, hello.buffer).await?;
  Ok(())
}

async fn capture_client_hello(stream: &mut TcpStream) -> Result<ClientHelloCapture> {
  let mut captured = Vec::with_capacity(1024);
  let mut total = 0usize;

  loop {
    let (hdr_res, header) = stream.read_exact(vec![0u8; 5]).await;
    let header = header;
    hdr_res.context("failed to read TLS record header")?;
    total += header.len();
    if total > MAX_CLIENT_HELLO_SIZE {
      bail!("TLS ClientHello exceeds {MAX_CLIENT_HELLO_SIZE} bytes");
    }
    captured.extend_from_slice(&header);
    if header[0] != 0x16 {
      bail!("connection does not begin with a TLS handshake");
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let (payload_res, payload) = stream.read_exact(vec![0u8; len]).await;
    let payload = payload;
    payload_res.context("failed to read TLS record payload")?;
    total += len;
    if total > MAX_CLIENT_HELLO_SIZE {
      bail!("TLS ClientHello exceeds {MAX_CLIENT_HELLO_SIZE} bytes");
    }
    captured.extend_from_slice(&payload);

    let start = captured.len() - (5 + len);
    let record = &captured[start..];
    let (_, plaintext) =
      parse_tls_plaintext(record).map_err(|_| anyhow!("unable to parse TLS record"))?;
    if let Some(hostname) = extract_sni(&plaintext) {
      return Ok(ClientHelloCapture {
        hostname,
        buffer: captured,
      });
    } else {
      bail!("TLS ClientHello did not include an SNI extension");
    }
  }
}

fn extract_sni(record: &TlsPlaintext) -> Option<String> {
  for msg in &record.msg {
    if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = msg {
      let ext_bytes = hello.ext?;
      if let Ok((_, extensions)) = parse_tls_client_hello_extensions(ext_bytes) {
        for ext in extensions {
          if let TlsExtension::SNI(entries) = ext {
            for (kind, value) in entries {
              if kind == SNIType::HostName && !value.is_empty() {
                if let Ok(host) = str::from_utf8(value) {
                  if host.len() <= 255 {
                    return Some(host.to_string());
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  None
}

async fn relay_streams(client: TcpStream, upstream: TcpStream, initial: Vec<u8>) -> Result<()> {
  let (mut client_reader, mut client_writer) = client.into_split();
  let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

  let upload = async {
    if !initial.is_empty() {
      let (res, _buf) = upstream_writer.write_all(initial).await;
      res?;
    }
    copy(&mut client_reader, &mut upstream_writer).await
  };

  let download = async { copy(&mut upstream_reader, &mut client_writer).await };

  let (up_res, down_res) = monoio::join!(upload, download);
  for outcome in [up_res, down_res] {
    match outcome {
      Ok(_) => {}
      Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {}
      Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
      Err(err) => return Err(err.into()),
    }
  }
  Ok(())
}

impl DohClient {
  fn new() -> Result<Self> {
    install_crypto_provider()?;

    let root_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
      .with_root_certificates(root_store)
      .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let cache = &*Box::leak(Box::new(
      Cache::builder()
        .time_to_live(Duration::from_secs(DNS_CACHE_TTL_SECS))
        .max_capacity(DNS_CACHE_CAPACITY)
        .build(),
    ));

    std::thread::Builder::new()
      .name("zerosni-gc".into())
      .spawn(move || {
        let mut rt = monoio::RuntimeBuilder::<IoUringDriver>::new()
          .enable_timer()
          .build()
          .expect("zerosni-gc: failed to build io_uring runtime");
        rt.block_on(async {
          loop {
            monoio::time::sleep(Duration::from_secs(5)).await;
            cache.run_pending_tasks().await;
          }
        })
      })
      .expect("failed to spawn zerosni-gc");

    Ok(Self {
      connector,
      cache,
      resolvers: Mutex::new(HashMap::new()),
    })
  }

  async fn resolve(
    &self,
    resolver_url: &str,
    hostname: &str,
    fwmark: Option<u32>,
  ) -> Result<Vec<IpAddr>> {
    let resolver = self.get_resolver(resolver_url)?;
    let host = hostname.to_string();
    match self
      .cache
      .try_get_with(hostname.to_string(), async move {
        self.resolve_uncached(resolver, &host, fwmark).await
      })
      .await
    {
      Ok(addrs) => Ok(addrs),
      Err(err) => match Arc::try_unwrap(err) {
        Ok(inner) => Err(inner),
        Err(shared) => Err(anyhow!(shared.as_ref().to_string())),
      },
    }
  }

  fn get_resolver(&self, uri: &str) -> Result<Arc<ResolverConfig>> {
    let mut guard = self.resolvers.lock().expect("resolver cache poisoned");
    if let Some(existing) = guard.get(uri) {
      return Ok(existing.clone());
    }
    let config = Arc::new(ResolverConfig::parse(uri)?);
    guard.insert(uri.to_string(), config.clone());
    Ok(config)
  }

  async fn resolve_uncached(
    &self,
    resolver: Arc<ResolverConfig>,
    hostname: &str,
    fwmark: Option<u32>,
  ) -> Result<Vec<IpAddr>> {
    let mut seen = HashSet::new();
    let mut addrs = Vec::new();
    for ty in [RecordType::A, RecordType::Aaaa] {
      let mut records = self
        .query_rr(resolver.as_ref(), hostname, ty, fwmark)
        .await?;
      records.retain(|addr| seen.insert(*addr));
      addrs.extend(records);
    }
    Ok(addrs)
  }

  async fn query_rr(
    &self,
    resolver: &ResolverConfig,
    hostname: &str,
    ty: RecordType,
    fwmark: Option<u32>,
  ) -> Result<Vec<IpAddr>> {
    let path = Self::build_request_path(resolver, hostname, ty);
    let tls = self.open_tls_stream(resolver, fwmark).await?;
    let mut codec = ClientCodec::new(tls);
    let request = Request::builder()
      .method(Method::GET)
      .version(Version::HTTP_11)
      .uri(path)
      .header(header::HOST, resolver.authority.as_str())
      .header(header::USER_AGENT, USER_AGENT)
      .header(header::ACCEPT, "application/dns-json")
      .header(header::CONNECTION, "close")
      .body(Payload::<Bytes, HttpError>::None)
      .expect("static request build cannot fail");
    codec.send(request).await?;
    <ClientCodec<ClientTlsStream<TcpStream>> as Sink<
            http::Request<Payload<Bytes, HttpError>>,
        >>::flush(&mut codec)
        .await?;
    let response = codec
      .next()
      .await
      .ok_or_else(|| anyhow!("resolver closed the connection"))??;
    if response.status() != StatusCode::OK {
      bail!("resolver returned {}", response.status());
    }
    let (_, body) = response.into_parts();
    let mut payload = body.with_io(&mut codec);
    let mut body_bytes = Vec::new();
    while let Some(chunk) = payload.next_data().await {
      let bytes = chunk?;
      body_bytes.extend_from_slice(bytes.as_ref());
    }
    let parsed: DohResponse =
      serde_json::from_slice(&body_bytes).context("failed to parse resolver response")?;
    if parsed.status != 0 {
      bail!("resolver returned DNS error status {}", parsed.status);
    }
    let mut addrs = Vec::new();
    if let Some(records) = parsed.answers {
      for record in records {
        if record.record_type == ty.code() {
          if let Ok(ip) = record.data.parse::<IpAddr>() {
            addrs.push(ip);
          }
        }
      }
    }
    Ok(addrs)
  }

  fn build_request_path(resolver: &ResolverConfig, hostname: &str, ty: RecordType) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (k, v) in &resolver.base_query {
      serializer.append_pair(k, v);
    }
    serializer.append_pair("name", hostname);
    serializer.append_pair("type", ty.label());
    let query = serializer.finish();
    if query.is_empty() {
      resolver.path.clone()
    } else {
      format!("{}?{}", resolver.path, query)
    }
  }

  async fn open_tls_stream(
    &self,
    resolver: &ResolverConfig,
    fwmark: Option<u32>,
  ) -> Result<ClientTlsStream<TcpStream>> {
    let mut last_err = None;
    for addr in resolve_host(&resolver.host, resolver.port)? {
      match connect_with_mark(addr, fwmark).await {
        Ok(stream) => {
          return self
            .connector
            .connect(resolver.server_name.clone(), stream)
            .await
            .map_err(Into::into);
        }
        Err(err) => last_err = Some(err),
      }
    }
    let err = last_err
      .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "unable to resolve resolver host"));
    Err(err.into())
  }
}

impl ResolverConfig {
  fn parse(uri: &str) -> Result<Self> {
    let mut url = Url::parse(uri).context("invalid resolver URL")?;
    if url.scheme() != "https" {
      bail!("resolver URL must use https://");
    }
    if url.path().is_empty() || url.path() == "/" {
      url.set_path(DEFAULT_DOH_PATH);
    }
    let host = url
      .host_str()
      .ok_or_else(|| anyhow!("resolver URL missing host"))?
      .to_string();
    let port = url
      .port_or_known_default()
      .ok_or_else(|| anyhow!("resolver URL missing port"))?;
    let authority = if port == 443 {
      host.clone()
    } else {
      format!("{host}:{port}")
    };
    let server_name = ServerName::try_from(host.clone())
      .map_err(|_| anyhow!("resolver host is not a valid TLS name"))?;
    let base_query = url
      .query_pairs()
      .map(|(k, v)| (k.into_owned(), v.into_owned()))
      .collect();
    Ok(Self {
      server_name,
      host,
      port,
      authority,
      path: url.path().to_string(),
      base_query,
    })
  }
}

impl RecordType {
  fn label(self) -> &'static str {
    match self {
      RecordType::A => "A",
      RecordType::Aaaa => "AAAA",
    }
  }

  fn code(self) -> u16 {
    match self {
      RecordType::A => 1,
      RecordType::Aaaa => 28,
    }
  }
}

async fn connect_to_any(candidates: &[IpAddr], fwmark: Option<u32>) -> Result<TcpStream> {
  let mut last_err = None;
  for ip in candidates {
    let addr = SocketAddr::new(*ip, TARGET_PORT);
    match connect_with_mark(addr, fwmark).await {
      Ok(stream) => return Ok(stream),
      Err(err) => last_err = Some(err),
    }
  }
  let err = last_err
    .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to connect to resolved host"));
  Err(err.into())
}

async fn connect_with_mark(addr: SocketAddr, fwmark: Option<u32>) -> io::Result<TcpStream> {
  let domain = match addr {
    SocketAddr::V4(_) => Domain::IPV4,
    SocketAddr::V6(_) => Domain::IPV6,
  };
  let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
  socket.set_nonblocking(true)?;
  socket.set_nodelay(true)?;
  if let Some(mark) = fwmark {
    socket.set_mark(mark)?;
  }
  let sock_addr = socket2::SockAddr::from(addr);
  if let Err(err) = socket.connect(&sock_addr) {
    if err.kind() != io::ErrorKind::WouldBlock
      && err.kind() != io::ErrorKind::Interrupted
      && err.raw_os_error() != Some(libc::EINPROGRESS)
    {
      return Err(err);
    }
  }
  let std_stream: std::net::TcpStream = socket.into();
  std_stream.set_nonblocking(true)?;
  let stream = TcpStream::from_std(std_stream)?;
  stream.writable(true).await?;
  check_connect_error(stream.as_raw_fd())?;
  Ok(stream)
}

fn check_connect_error(fd: RawFd) -> io::Result<()> {
  let mut error: libc::c_int = 0;
  let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
  let ret = unsafe {
    libc::getsockopt(
      fd,
      libc::SOL_SOCKET,
      libc::SO_ERROR,
      &mut error as *mut _ as *mut libc::c_void,
      &mut len,
    )
  };
  if ret != 0 {
    return Err(io::Error::last_os_error());
  }
  if error == 0 {
    Ok(())
  } else {
    Err(io::Error::from_raw_os_error(error))
  }
}

fn resolve_host(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
  let target = if host.contains(':') {
    format!("[{host}]:{port}")
  } else {
    format!("{host}:{port}")
  };
  target.to_socket_addrs().map(|iter| iter.collect())
}
