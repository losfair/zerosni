# zerosni

`io_uring`-based SNI-inspecting TCP transparent proxy. It decodes outgoing TCP streams on port 443, resolves the SNI hostname through the provided UDP resolver, and proxies the stream to the resolved host.

## Dependencies

- `monoio`: the `io_uring` runtime
- [tls-parser](https://crates.io/crates/tls-parser): TLS protocol decoder
- `dns-parser`: DNS query builder/parser for UDP lookups
- `clap`: Argument parser (use derive macro)

## Usage

Start `zerosni`:

```bash
zerosni --fwmark 1 --listen 0.0.0.0:1510 --resolver 1.1.1.1:53
```

To override the resolver, direct target, and/or fwmark for specific hostnames, pass `--rule-table PATH` with a JSON rule file (see `examples/rule_table.json`).

To forward the original client/target metadata to upstream servers, add `--enable-proxy-protocol` to prepend a PROXY protocol v1 header to every outbound connection.

## Rule table format

The table maps hostname patterns to overrides:

```json
{
  "www.example.com": { "direct": "10.0.1.2:8443", "fwmark": 1 },
  "*.apple.com": { "resolver": "udp://1.1.1.1" },
  "*": { "fwmark": 3 }
}
```

- Exact hostnames are matched case-insensitively first.
- Wildcards must either be `*` (catch-all) or start with `*.` to match any subdomain of the suffix (e.g. `*.example.com`).
- Each rule must set at least one of `resolver`, `direct`, or `fwmark`.
- `direct` takes a `host:port` pair (e.g. `10.0.1.2:8443`) and skips DNS resolution entirely.
- `resolver` accepts a UDP resolver address as `host[:port]` or `udp://host[:port]` (default port 53).
- `direct` and `resolver` are mutually exclusive for a given rule.
- Missing fields fall back to the global `--resolver` / `--fwmark` configuration.

## Hot reloading

When running with `--rule-table`, send the process `SIGHUP` to reload the JSON
file without restarting. The updated table replaces the previous one atomically,
so new connections immediately see the refreshed overrides.

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
