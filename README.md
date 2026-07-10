# zerosni

Tokio-based SNI-inspecting TCP transparent proxy. It decodes outgoing TCP streams on port 443, resolves the SNI hostname through the provided UDP resolver, and proxies the stream to the resolved host.

## Dependencies

- `tokio`: the asynchronous runtime
- `tokio-rustls`: asynchronous TLS support for interception
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

## TLS interception

To decrypt and mirror TLS traffic for specific domains, add a `tls_intercept` block:

```json
{
  "api.example.com": {
    "tls_intercept": {
      "mirror": "127.0.0.1:9000",
      "ca_cert": "/path/to/ca.crt",
      "ca_key": "/path/to/ca.key",
      "match_fwmark": 100
    }
  }
}
```

Options:
- `mirror`: TCP address to send decrypted traffic to (required). Use `_:<port>` to mirror to the client's IP address on the specified port.
- `ca_cert`: Path to CA certificate PEM file (required)
- `ca_key`: Path to CA private key PEM file (required)
- `match_fwmark`: Only intercept if the socket's fwmark matches this value (optional)

See `examples/intercept.json` for a complete example.

Generate a CA certificate (P-256 ECDSA):

```bash
openssl ecparam -genkey -name prime256v1 -out ca_key.pem
openssl req -new -x509 -days 3650 -key ca_key.pem -out ca_cert.pem -subj "/CN=zerosni CA"
```

When enabled, zerosni:
1. Terminates the client TLS connection using a dynamically generated certificate signed by the provided CA
2. Establishes a new TLS connection to the upstream server
3. Mirrors decrypted traffic to the specified TCP address

Mirror stream format:
- Client-to-server chunks: `0x00` + LE32 size + data
- Server-to-client chunks: `0x01` + LE32 size + data

The CA certificate must be trusted by clients for interception to work transparently.

### Mirror receiver

A helper script `tools/mirror_receiver.py` decodes the mirror stream and prints HTTP/1.1 traffic:

```bash
python tools/mirror_receiver.py -p 9000
```

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
