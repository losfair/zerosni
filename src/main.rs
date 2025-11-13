mod rule_table;
mod util;

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use rule_table::RuleTable;
use std::{
  collections::{HashMap, HashSet},
  io,
  mem::ManuallyDrop,
  net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
  os::fd::{AsRawFd, FromRawFd, RawFd},
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

use crate::util::read_to_end;

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
  /// Send a PROXY protocol v1 header to upstream servers.
  #[arg(long = "enable-proxy-protocol")]
  enable_proxy_protocol: bool,
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
  enable_proxy_protocol: bool,
}

enum RouteTarget {
  Resolve(String),
  Direct(SocketAddr),
}

struct RouteSelection {
  target: RouteTarget,
  fwmark: Option<u32>,
}

impl ProxyContext {
  fn select_route(&self, hostname: &str) -> RouteSelection {
    let overrides = self
      .rule_table
      .load_full()
      .as_ref()
      .and_then(|table| table.lookup(hostname));
    let fwmark = overrides
      .as_ref()
      .and_then(|rule| rule.fwmark)
      .or(self.default_fwmark);
    let target = match overrides {
      Some(rule) => {
        if let Some(addr) = rule.direct {
          RouteTarget::Direct(addr)
        } else {
          let resolver_url = rule
            .resolver
            .unwrap_or_else(|| self.default_resolver.clone());
          RouteTarget::Resolve(resolver_url)
        }
      }
      None => RouteTarget::Resolve(self.default_resolver.clone()),
    };
    RouteSelection { target, fwmark }
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
  hostname: Option<String>,
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
    enable_proxy_protocol: args.enable_proxy_protocol,
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
  let peer_mac = lookup_peer_mac(peer.ip()).await;
  let peer_log_label = format_peer_with_mac(peer, peer_mac.as_ref().map(|x| &***x));
  let hello = capture_client_hello(&mut client).await?;
  let socket = ManuallyDrop::new(unsafe { socket2::Socket::from_raw_fd(client.as_raw_fd()) });
  let upstream = if let Some(hostname) = &hello.hostname {
    eprintln!("{peer_log_label} requested {}", hostname);
    let RouteSelection { target, fwmark } = ctx.select_route(hostname);
    match target {
      RouteTarget::Direct(addr) => connect_with_mark(addr, fwmark).await?,
      RouteTarget::Resolve(resolver_url) => {
        let candidates = ctx
          .doh
          .resolve(&resolver_url, hostname, fwmark)
          .await
          .with_context(|| format!("resolver lookup for {}", hostname))?;

        if candidates.is_empty() {
          bail!("no DNS answers for {}", hostname);
        }

        connect_to_any(&candidates, fwmark).await?
      }
    }
  } else {
    let original_dst = socket
      .original_dst()?
      .as_socket()
      .with_context(|| "failed to get original_dst ip")?
      .ip();
    eprintln!("{peer_log_label} bypass {}", original_dst);
    connect_to_any(&[original_dst], ctx.default_fwmark).await?
  };

  let proxy_header = if ctx.enable_proxy_protocol {
    Some(build_proxy_header(peer, upstream.peer_addr()?))
  } else {
    None
  };

  relay_streams(client, upstream, hello.buffer, proxy_header).await?;
  Ok(())
}

async fn capture_client_hello(stream: &mut TcpStream) -> Result<ClientHelloCapture> {
  let mut captured = Vec::with_capacity(1024);
  let mut total = 0usize;
  let peer_addr = stream.peer_addr()?;

  let (hdr_res, header) = stream.read_exact(vec![0u8; 5]).await;
  hdr_res.context("failed to read TLS record header")?;
  total += header.len();
  if total > MAX_CLIENT_HELLO_SIZE {
    bail!("TLS ClientHello exceeds {MAX_CLIENT_HELLO_SIZE} bytes");
  }
  captured.extend_from_slice(&header);
  if header[0] != 0x16 {
    eprintln!("{peer_addr}: connection does not begin with a TLS handshake");

    return Ok(ClientHelloCapture {
      hostname: None,
      buffer: captured,
    });
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
  let hostname = extract_sni(&plaintext);
  if hostname.is_none() {
    eprintln!("{peer_addr}: TLS ClientHello did not include an SNI extension",);
  }
  Ok(ClientHelloCapture {
    hostname,
    buffer: captured,
  })
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

async fn relay_streams(
  client: TcpStream,
  upstream: TcpStream,
  initial: Vec<u8>,
  proxy_header: Option<Vec<u8>>,
) -> Result<()> {
  let (mut client_reader, mut client_writer) = client.into_split();
  let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

  let upload = async {
    if let Some(header) = proxy_header {
      let (res, _buf) = upstream_writer.write_all(header).await;
      res?;
    }
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

fn build_proxy_header(mut src: SocketAddr, mut dst: SocketAddr) -> Vec<u8> {
  for x in [&mut src, &mut dst] {
    x.set_ip(x.ip().to_canonical());
  }

  let v6 = |x: IpAddr| match x {
    IpAddr::V4(x) => x.to_ipv6_mapped(),
    IpAddr::V6(x) => x,
  };

  match (src, dst) {
    (SocketAddr::V4(s), SocketAddr::V4(d)) => format!(
      "PROXY TCP4 {} {} {} {}\r\n",
      s.ip(),
      d.ip(),
      s.port(),
      d.port()
    )
    .into_bytes(),
    (s, d) => format!(
      "PROXY TCP6 {} {} {} {}\r\n",
      v6(s.ip()),
      v6(d.ip()),
      s.port(),
      d.port()
    )
    .into_bytes(),
  }
}

#[cfg(test)]
mod proxy_tests {
  use super::build_proxy_header;
  use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

  #[test]
  fn builds_ipv4_proxy_header() {
    let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234));
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 443));
    let header = build_proxy_header(src, dst);
    assert_eq!(header, b"PROXY TCP4 10.0.0.1 203.0.113.10 1234 443\r\n");
  }

  #[test]
  fn builds_ipv6_proxy_header() {
    let src = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5555, 0, 0));
    let dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0));
    let header = build_proxy_header(src, dst);
    assert_eq!(header, b"PROXY TCP6 ::1 ::1 5555 8443\r\n");
  }

  #[test]
  fn falls_back_to_unknown_on_mixed_families() {
    let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
    let dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 2, 0, 0));
    let header = build_proxy_header(src, dst);
    assert_eq!(header, b"PROXY UNKNOWN\r\n");
  }
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
            unsafe {
              libc::malloc_trim(0);
            }
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

fn format_peer_with_mac(peer: SocketAddr, mac: Option<&str>) -> String {
  match mac {
    Some(mac) => format!("{peer} (mac: {mac})"),
    None => format!("{peer} (mac: unknown)"),
  }
}

async fn lookup_peer_mac(addr: IpAddr) -> Option<Arc<String>> {
  static CACHE: OnceLock<moka::future::Cache<Ipv4Addr, Option<Arc<String>>>> = OnceLock::new();
  let cache = CACHE.get_or_init(|| {
    moka::future::Cache::builder()
      .time_to_live(Duration::from_secs(10))
      .build()
  });
  let ip = match addr {
    IpAddr::V4(ip) => ip,
    IpAddr::V6(ip) => ip.to_ipv4_mapped()?,
  };
  cache.run_pending_tasks().await;
  cache
    .get_with(
      ip,
      async move { lookup_mac_from_arp(ip).await.map(Arc::new) },
    )
    .await
}

async fn lookup_mac_from_arp(needle: std::net::Ipv4Addr) -> Option<String> {
  let contents = String::from_utf8(read_to_end("/proc/net/arp").await.ok()?).ok()?;
  for line in contents.lines().skip(1) {
    let mut fields = line.split_whitespace().into_iter();
    let Some(ip) = fields.next().and_then(|x| x.parse::<Ipv4Addr>().ok()) else {
      continue;
    };
    if ip != needle {
      continue;
    }
    fields.next();
    fields.next();
    let Some(mac) = fields.next() else {
      continue;
    };
    if mac != "00:00:00:00:00:00" {
      return Some(mac.to_ascii_lowercase());
    }
  }
  None
}
