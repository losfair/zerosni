# zerosni

`io_uring`-based SNI-inspecting TCP transparent proxy. It decodes outgoing TCP streams on port 443, resolves the SNI hostname through the provided DNS-over-HTTPS resolver, and proxies the stream to the resolved host.

## Dependencies

- `monoio`: the `io_uring` runtime
- [tls-parser](https://crates.io/crates/tls-parser): TLS protocol decoder
- `clap`: Argument parser (use derive macro)
- `monoio-http` and `monoio-rustls`: HTTP + TLS client to use for DNS-over-HTTPS queries

## Usage

Start `zerosni`:

```bash
zerosni --fwmark 1 --listen 0.0.0.0:1510 --resolver https://1.1.1.1
```

Set up iptables

```bash
# allow redirecting back to loopback
sudo sysctl -w net.ipv4.conf.lo.route_localnet=1

PORT=1510

# Redirect TCP traffic to the proxy, excluding the proxy's own connections (whose fwmark is set to non-zero).
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 \
  -m mark --mark 0 \
  ! -d 127.0.0.0/8 \
  -j REDIRECT --to-ports "$PORT"

# Redirect routed traffic
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports "$PORT"

```
