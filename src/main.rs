mod async_print;
mod rule_table;
mod tls_intercept;
mod util;

use arc_swap::ArcSwapOption;
use compact_str::CompactString;
use dns_parser::{Builder, Packet, QueryClass, QueryType, RData, ResponseCode};
use rule_table::RuleTable;
use std::{
  collections::{HashMap, HashSet},
  io,
  net::{IpAddr, Ipv4Addr, SocketAddr},
  os::fd::{AsRawFd, RawFd},
  path::PathBuf,
  str,
  sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU16, Ordering},
  },
  time::Duration,
};
use tls_intercept::TlsInterceptor;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use moka::future::Cache;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tls_parser::{
  SNIType, TlsExtension, TlsMessage, TlsMessageHandshake, TlsPlaintext,
  parse_tls_client_hello_extensions, parse_tls_plaintext,
};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt, copy},
  net::{TcpListener, TcpStream, UdpSocket},
};
use url::Url;

use crate::rule_table::TlsInterceptConfig;
use crate::util::read_to_end;

const MAX_CLIENT_HELLO_SIZE: usize = 64 * 1024;
const TARGET_PORT: u16 = 443;
const DNS_CACHE_TTL_SECS: u64 = 180;
const DNS_CACHE_CAPACITY: u64 = 16384;
const DNS_DEFAULT_PORT: u16 = 53;
const MAX_DNS_MESSAGE_SIZE: usize = 4096;

static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(0);

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
  /// Address to accept redirected TLS connections from.
  #[arg(long)]
  listen: SocketAddr,
  /// UDP resolver to query for hostnames (host[:port], defaults to 53).
  #[arg(long)]
  resolver: String,
  /// Send a PROXY protocol v1 header to upstream servers.
  #[arg(long = "enable-proxy-protocol")]
  enable_proxy_protocol: bool,
  /// Firewall mark to apply to outbound sockets (Linux only).
  #[arg(long, default_value = "0")]
  fwmark: u32,
  /// Path to a JSON rule table that overrides resolver/fwmark per hostname.
  #[arg(long = "rule-table")]
  rule_table: Option<PathBuf>,
}

struct ProxyContext {
  dns: Arc<DnsClient>,
  default_resolver: CompactString,
  default_fwmark: u32,
  rule_table: Arc<ArcSwapOption<RuleTable>>,
  enable_proxy_protocol: bool,
}

enum RouteTarget {
  Resolve(CompactString),
  Direct(SocketAddr),
}

struct RouteSelection {
  target: RouteTarget,
  fwmark: u32,
  tls_intercept: Option<TlsInterceptConfig>,
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
      .map(|rule| rule.fwmark)
      .unwrap_or(self.default_fwmark);
    let tls_intercept = overrides.as_ref().and_then(|r| r.tls_intercept.clone());
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
    RouteSelection {
      target,
      fwmark,
      tls_intercept,
    }
  }
}

struct DnsClient {
  cache: &'static Cache<String, Vec<IpAddr>>,
  resolvers: Mutex<HashMap<String, Arc<ResolverConfig>>>,
}

#[derive(Debug, Clone)]
struct ResolverConfig {
  addr: SocketAddr,
}

#[derive(Clone, Copy)]
enum RecordType {
  A,
  Aaaa,
}

struct ClientHelloCapture {
  hostname: Option<String>,
  buffer: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
  amain().await
}

async fn amain() -> Result<()> {
  let args = Cli::parse();

  let default_resolver = CompactString::new(&args.resolver);
  let fwmark = args.fwmark;
  let dns = Arc::new(DnsClient::new()?);
  let rule_table_path = args.rule_table.clone();
  let initial_rule_table = if let Some(path) = rule_table_path.as_ref() {
    Some(Arc::new(RuleTable::from_file(path)?))
  } else {
    None
  };
  let rule_table = Arc::new(ArcSwapOption::from(initial_rule_table));

  aeprintln!(
    "zerosni listening on {} (resolver: {})",
    args.listen,
    default_resolver
  );

  let ctx = Arc::new(ProxyContext {
    dns,
    default_resolver,
    default_fwmark: fwmark,
    rule_table: rule_table.clone(),
    enable_proxy_protocol: args.enable_proxy_protocol,
  });

  if let Some(path) = rule_table_path {
    install_rule_table_reloader(rule_table, path);
  }
  let listener = bind_listener(args.listen)?;

  loop {
    let accepted = listener.accept().await;
    match accepted {
      Ok((stream, peer)) => {
        if let Err(err) = stream.set_nodelay(true) {
          aeprintln!("failed to set nodelay on accepted stream: {err}");
        }
        let ctx = ctx.clone();
        tokio::spawn(async move {
          if let Err(err) = handle_client(stream, peer, ctx).await {
            aeprintln!("connection from {peer} failed: {err:?}");
          }
        });
      }
      Err(err) => {
        aeprintln!("accept error: {err}");
      }
    }
  }
}

fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
  let domain = match addr {
    SocketAddr::V4(_) => Domain::IPV4,
    SocketAddr::V6(_) => Domain::IPV6,
  };
  let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
  socket.set_nonblocking(true)?;
  socket.set_reuse_port(true)?;
  socket.bind(&addr.into())?;
  socket.listen(1024)?;
  TcpListener::from_std(socket.into())
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
  let upstream = if let Some(hostname) = &hello.hostname {
    aeprintln!("{peer_log_label} requested {}", hostname);
    let RouteSelection {
      target,
      fwmark,
      tls_intercept,
    } = ctx.select_route(hostname);
    let upstream = match target {
      RouteTarget::Direct(addr) => connect_with_mark(addr, fwmark).await?,
      RouteTarget::Resolve(resolver_url) => {
        let candidates = ctx
          .dns
          .resolve(&resolver_url, hostname, fwmark)
          .await
          .with_context(|| format!("resolver lookup for {}", hostname))?;

        if candidates.is_empty() {
          bail!("no DNS answers for {}", hostname);
        }

        connect_to_any(&candidates, fwmark).await?
      }
    };

    if let Some(intercept_cfg) = tls_intercept {
      let should_intercept = match intercept_cfg.match_fwmark {
        Some(required_mark) => SockRef::from(&client).mark().unwrap_or(0) == required_mark,
        None => true,
      };
      if should_intercept {
        aeprintln!("{peer_log_label} intercepting TLS for {}", hostname);
        let interceptor = TlsInterceptor::new(&intercept_cfg, hostname).await?;
        return interceptor
          .intercept(client, upstream, hello.buffer, hostname)
          .await;
      }
    }

    upstream
  } else {
    let local_addr = client.local_addr()?;
    let socket = SockRef::from(&client);
    let original_dst = match local_addr {
      SocketAddr::V4(_) => socket.original_dst_v4()?,
      SocketAddr::V6(_) => socket.original_dst_v6()?,
    }
    .as_socket()
    .with_context(|| "failed to get original_dst ip")?
    .ip();
    if original_dst.to_canonical() == local_addr.ip().to_canonical() {
      aeprintln!("{peer_log_label} not bypassing {}", original_dst);
      return Ok(());
    }
    aeprintln!("{peer_log_label} bypass {}", original_dst);
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

  let mut header = [0u8; 5];
  stream
    .read_exact(&mut header)
    .await
    .context("failed to read TLS record header")?;
  total += header.len();
  if total > MAX_CLIENT_HELLO_SIZE {
    bail!("TLS ClientHello exceeds {MAX_CLIENT_HELLO_SIZE} bytes");
  }
  captured.extend_from_slice(&header);
  if header[0] != 0x16 {
    aeprintln!("{peer_addr}: connection does not begin with a TLS handshake");

    return Ok(ClientHelloCapture {
      hostname: None,
      buffer: captured,
    });
  }
  let len = u16::from_be_bytes([header[3], header[4]]) as usize;
  let mut payload = vec![0u8; len];
  stream
    .read_exact(&mut payload)
    .await
    .context("failed to read TLS record payload")?;
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
    aeprintln!("{peer_addr}: TLS ClientHello did not include an SNI extension",);
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
              if kind == SNIType::HostName
                && !value.is_empty()
                && let Ok(host) = str::from_utf8(value)
                && host.len() <= 255
              {
                return Some(host.to_string());
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
      upstream_writer.write_all(&header).await?;
    }
    if !initial.is_empty() {
      upstream_writer.write_all(&initial).await?;
    }
    copy(&mut client_reader, &mut upstream_writer).await
  };

  let download = async { copy(&mut upstream_reader, &mut client_writer).await };

  let res = tokio::select! {
    x = upload => x,
    x = download => x,
  };
  match res {
    Ok(_) => {}
    Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {}
    Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
    Err(err) => return Err(err.into()),
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

impl DnsClient {
  fn new() -> Result<Self> {
    let cache = &*Box::leak(Box::new(
      Cache::builder()
        .time_to_live(Duration::from_secs(DNS_CACHE_TTL_SECS))
        .max_capacity(DNS_CACHE_CAPACITY)
        .build(),
    ));

    std::thread::Builder::new()
      .name("zerosni-gc".into())
      .spawn(move || {
        tokio::runtime::Builder::new_current_thread()
          .enable_time()
          .build()
          .expect("zerosni-gc: failed to build Tokio runtime")
          .block_on(async {
            loop {
              tokio::time::sleep(Duration::from_secs(5)).await;
              cache.run_pending_tasks().await;
              unsafe {
                libc::malloc_trim(0);
              }
            }
          });
      })
      .expect("failed to spawn zerosni-gc");

    Ok(Self {
      cache,
      resolvers: Mutex::new(HashMap::new()),
    })
  }

  async fn resolve(&self, resolver_url: &str, hostname: &str, fwmark: u32) -> Result<Vec<IpAddr>> {
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
        Err(shared) => Err(anyhow!("{:?}", shared.as_ref())),
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
    fwmark: u32,
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
    fwmark: u32,
  ) -> Result<Vec<IpAddr>> {
    let (query, query_id) = build_dns_query(hostname, ty)?;
    let response = Self::send_query(&[resolver.addr], query, fwmark).await?;
    Self::parse_response(&response, ty, query_id)
  }

  async fn send_query(addrs: &[SocketAddr], payload: Vec<u8>, fwmark: u32) -> Result<Vec<u8>> {
    if addrs.is_empty() {
      bail!("resolver host does not resolve to any addresses");
    }
    let mut last_err = None;
    let mut query = payload;
    for (idx, addr) in addrs.iter().copied().enumerate() {
      let buf = if idx + 1 == addrs.len() {
        std::mem::take(&mut query)
      } else {
        query.clone()
      };
      match Self::send_single_query(addr, buf, fwmark).await {
        Ok(resp) => return Ok(resp),
        Err(err) => last_err = Some(err),
      }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("unknown DNS resolver error")))
  }

  async fn send_single_query(addr: SocketAddr, payload: Vec<u8>, fwmark: u32) -> Result<Vec<u8>> {
    let domain = match addr {
      SocketAddr::V4(_) => Domain::IPV4,
      SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    if fwmark != 0 {
      socket.set_mark(fwmark)?;
    }
    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(std_socket)?;
    let send_loop = async {
      loop {
        let _ = udp.send_to(&payload, addr).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
      }
    };
    let mut buf = vec![0u8; MAX_DNS_MESSAGE_SIZE];
    let read_res = tokio::time::timeout(Duration::from_secs(5), async {
      tokio::select! {
        x = udp.recv_from(&mut buf) => x,
        _ = send_loop => unreachable!("DNS retransmission loop does not complete"),
      }
    })
    .await
    .map_err(|_| anyhow::anyhow!("query timeout"))?;
    let (len, src) = read_res?;
    if src.ip().to_canonical() != addr.ip().to_canonical() || src.port() != addr.port() {
      bail!("received DNS response from unexpected address {src}");
    }
    Ok(buf[..len.min(buf.len())].to_vec())
  }

  fn parse_response(bytes: &[u8], ty: RecordType, query_id: u16) -> Result<Vec<IpAddr>> {
    let packet = Packet::parse(bytes).context("failed to parse DNS response")?;
    if packet.header.id != query_id {
      bail!("DNS response transaction ID mismatch");
    }
    if packet.header.response_code != ResponseCode::NoError {
      bail!(
        "resolver returned DNS error {:?}",
        packet.header.response_code
      );
    }
    let mut addrs = Vec::new();
    for answer in packet.answers {
      match (ty, answer.data) {
        (RecordType::A, RData::A(record)) => addrs.push(IpAddr::V4(record.0)),
        (RecordType::Aaaa, RData::AAAA(record)) => addrs.push(IpAddr::V6(record.0)),
        _ => {}
      }
    }
    Ok(addrs)
  }
}

impl ResolverConfig {
  fn parse(uri: &str) -> Result<Self> {
    let formatted = if uri.contains("://") {
      uri.to_string()
    } else {
      format!("udp://{uri}")
    };
    let url = Url::parse(&formatted).or_else(|_| {
      if uri.contains("://") || uri.contains('[') || !uri.contains(':') {
        return Err(anyhow!("invalid resolver address"));
      }
      let bracketed = format!("udp://[{uri}]");
      Url::parse(&bracketed).map_err(|_| anyhow!("invalid resolver address"))
    })?;
    if url.scheme() != "udp" {
      bail!("resolver must use udp://");
    }
    let host = url
      .host_str()
      .ok_or_else(|| anyhow!("resolver missing host"))?;
    let port = url.port().unwrap_or(DNS_DEFAULT_PORT);
    let addr = SocketAddr::new(
      host
        .parse()
        .with_context(|| "host is not a valid ip address")?,
      port,
    );
    Ok(Self { addr })
  }
}

impl RecordType {
  fn query_type(self) -> QueryType {
    match self {
      RecordType::A => QueryType::A,
      RecordType::Aaaa => QueryType::AAAA,
    }
  }
}

fn build_dns_query(hostname: &str, ty: RecordType) -> Result<(Vec<u8>, u16)> {
  validate_dns_hostname(hostname)?;
  let query_id = next_query_id();
  let mut builder = Builder::new_query(query_id, true);
  builder.add_question(hostname, false, ty.query_type(), QueryClass::IN);
  let packet = match builder.build() {
    Ok(buf) | Err(buf) => buf,
  };
  Ok((packet, query_id))
}

fn validate_dns_hostname(hostname: &str) -> Result<()> {
  if hostname.is_empty() || hostname.len() > 255 {
    bail!("hostname is not a valid DNS name");
  }
  for label in hostname.split('.') {
    if label.is_empty() {
      bail!("hostname contains an empty DNS label");
    }
    // the dns-parser crate contains a check `assert!(part.len() < 63)`
    if label.len() >= 63 {
      bail!("hostname label must be shorter than 63 characters");
    }
  }
  Ok(())
}

fn next_query_id() -> u16 {
  DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed)
}

async fn connect_to_any(candidates: &[IpAddr], fwmark: u32) -> Result<TcpStream> {
  let mut last_err = None;
  for ip in candidates {
    let addr = SocketAddr::new(*ip, TARGET_PORT);
    match connect_with_mark(addr, fwmark).await {
      Ok(stream) => return Ok(stream),
      Err(err) => last_err = Some(err),
    }
  }
  let err = last_err.unwrap_or_else(|| io::Error::other("failed to connect to resolved host"));
  Err(err.into())
}

async fn connect_with_mark(addr: SocketAddr, fwmark: u32) -> io::Result<TcpStream> {
  let domain = match addr {
    SocketAddr::V4(_) => Domain::IPV4,
    SocketAddr::V6(_) => Domain::IPV6,
  };
  let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
  socket.set_nonblocking(true)?;
  socket.set_tcp_nodelay(true)?;
  if fwmark != 0 {
    socket.set_mark(fwmark)?;
  }
  let sock_addr = socket2::SockAddr::from(addr);
  if let Err(err) = socket.connect(&sock_addr)
    && err.kind() != io::ErrorKind::WouldBlock
    && err.kind() != io::ErrorKind::Interrupted
    && err.raw_os_error() != Some(libc::EINPROGRESS)
  {
    return Err(err);
  }
  let std_stream: std::net::TcpStream = socket.into();
  std_stream.set_nonblocking(true)?;
  let stream = TcpStream::from_std(std_stream)?;
  stream.writable().await?;
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
    let mut fields = line.split_whitespace();
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

#[cfg(test)]
mod proxy_tests {
  use super::{DnsClient, build_proxy_header, relay_streams};
  use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Duration, timeout},
  };

  async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (client.unwrap(), accepted.unwrap().0)
  }

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

  #[tokio::test]
  async fn relays_initial_data_proxy_header_and_both_directions() {
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let relay = tokio::spawn(relay_streams(
      proxy_client,
      proxy_upstream,
      b"hello".to_vec(),
      Some(b"proxy".to_vec()),
    ));

    let mut initial = [0u8; 10];
    timeout(Duration::from_secs(5), upstream.read_exact(&mut initial))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&initial, b"proxyhello");

    client.write_all(b"upload").await.unwrap();
    let mut upload = [0u8; 6];
    upstream.read_exact(&mut upload).await.unwrap();
    assert_eq!(&upload, b"upload");

    upstream.write_all(b"download").await.unwrap();
    let mut download = [0u8; 8];
    client.read_exact(&mut download).await.unwrap();
    assert_eq!(&download, b"download");

    drop(client);
    drop(upstream);
    timeout(Duration::from_secs(5), relay)
      .await
      .unwrap()
      .unwrap()
      .unwrap();
  }

  #[tokio::test]
  async fn sends_dns_query_and_accepts_reply_from_configured_resolver() {
    let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver_addr = resolver.local_addr().unwrap();
    let server = tokio::spawn(async move {
      let mut buf = [0u8; 32];
      let (len, peer) = resolver.recv_from(&mut buf).await.unwrap();
      assert_eq!(&buf[..len], b"query");
      resolver.send_to(b"response", peer).await.unwrap();
    });

    let response = DnsClient::send_single_query(resolver_addr, b"query".to_vec(), 0)
      .await
      .unwrap();
    assert_eq!(response, b"response");
    server.await.unwrap();
  }
}
