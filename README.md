# telegraff

telegraff checks scheduled payload delivery from registered Linux servers to a hub.
One Rust executable provides both roles. TCP, UDP, IPv4, and IPv6 have separate results.
The hub sends an ntfy alert after three consecutive failed cycles for a channel.

![banner](global/banner.jpg)

## Requirements

Use Linux and working DNS. systemd is optional; monitoring does not require matching agent and hub clocks. HTTPS certificate validity still requires a reasonably accurate agent clock.
Build with Rust 1.98.1, a C compiler, and the system development headers.
On Debian or Ubuntu, install `build-essential` and `pkg-config`.
SQLite is bundled. HTTPS uses rustls and bundled public root certificates.

## Install

1. Build on a host compatible with the destination servers:

   ```sh
   cargo build --release --locked
   sudo install -m 0755 target/release/telegraff /usr/local/bin/telegraff
   sudo useradd --system --home-dir /var/lib/telegraff --shell /usr/sbin/nologin telegraff
   sudo install -d -o root -g telegraff -m 0750 /etc/telegraff
   ```

2. Copy the executable, `examples/`, and `packaging/` to each agent host. Install the executable and create the same service account and configuration directory there.

## Configure the hub

1. Install the hub configuration:

   ```sh
   sudo install -m 0640 -o root -g telegraff examples/hub.toml /etc/telegraff/hub.toml
   ```

2. Edit `/etc/telegraff/hub.toml`. Replace `hub.example.net` with the hub DNS name or IP literal. Set `target` to the address agents use. Set `ntfy.endpoint` to the HTTPS topic URL and subscribe to that topic in ntfy. The URL is sufficient for topics that allow anonymous publishing. For a topic that requires authentication, uncomment `token_file` and save the ntfy access token in that file (owner `telegraff`, mode `0600`). For a local trial without notifications, remove the `[ntfy]` table.

3. Keep hub TCP and UDP listeners on loopback (`127.0.0.1` and `::1`); setup and the example use these addresses. nginx on the same host forwards traffic to that private backend. Open only nginx's public TCP/UDP port in the host and provider firewalls; do not expose the internal hub port. Agents need outbound access to the public port. The hub needs DNS and HTTPS access to ntfy. Remove the `::1` listeners only if IPv6 is unavailable locally. Existing configurations are not rewritten automatically: replace `0.0.0.0` with `127.0.0.1` and `[::]` with `[::1]`, then restart the hub.

4. Start the hub:

   ```sh
   sudo install -m 0644 packaging/telegraff-hub.service /etc/systemd/system/
   sudo -u telegraff telegraff config check --config /etc/telegraff/hub.toml
   sudo systemctl daemon-reload
   sudo systemctl enable --now telegraff-hub.service
   ```

## Quick setup and agent configuration

Run `./telegraff` (or `./telegraff setup`) in a terminal for guided setup. Subsequent bare launches use `telegraff.toml` from the current directory. Hub setup asks for its public DNS name, local listener port, public port and database. It saves one configuration. Agent setup imports the private profile generated on the hub; it never asks you to retype the key, name or hub address.

For agent setup, first copy `NAME.toml` exported by `register` from the hub to the agent. The wizard detects a single profile in the current directory; otherwise enter its filename or full path. Missing or invalid files can be corrected without restarting setup. An existing valid agent configuration is kept and its start command is shown. Nothing needs to be deleted; do not copy the hub configuration or create another key.

```sh
./telegraff hub --config hub.toml -d
./telegraff register node-01 --config hub.toml --output node-01.toml
./telegraff down --config hub.toml
./telegraff hub --config hub.toml -d
```

Transfer `node-01.toml` securely to the agent and keep mode 0600. This **is the complete agent configuration**, including its secret. There is no separate key file, and no need to also keep a copy in `/etc`. By default `register NAME` exports `NAME.toml` in the current directory; `--output` chooses another path. The registration stays in the hub's private registry beside the SQLite database; restart the hub after registration. The secret is never printed to the terminal. `--output` refuses to overwrite an existing file.

```sh
./telegraff agent --config node-01.toml -d
./telegraff down --config node-01.toml
# One diagnostic cycle, then exit:
./telegraff agent --config node-01.toml --once
```

Agent foreground mode now stays running, checks access immediately, and repeats after the configured interval. Failures are reported and retried. `-d` detaches from the terminal using Linux `setsid`; it does not enable boot startup. Runtime PID and log files live in a private per-user temporary directory; the start command prints the log path. Stop with the same user and configuration path. Do not combine `-d` with systemd. For boot startup, enable `telegraff-agent.service` directly; disable the old agent timer first.

Registered profiles run immediately without a scheduled window. The hub assigns incoming cycles to its own interval timeline, anchored when it first loads the registration; agent clocks do not have to match the hub clock. Cycle tokens and interval anchors are persisted, so a previously accepted token cannot count again in a later interval after restart. Upgrade and restart both hub and agent, including for existing profiles. Handwritten legacy `mode = "agent"` configurations retain their explicit scheduling policy; `grace = interval` selects continuous mode on both sides.

For forwarding, set `public_port = 443` in the hub configuration while retaining local listeners on the desired internal port, or pass `register --port 443`. DNS names automatically use HTTPS for TCP: the domain is sent in SNI and HTTP Host, and encrypted telegraff frames travel as `POST /telegraff`. The selected IPv4/IPv6 address is pinned for each attempt. IP literals keep raw TCP by default. Set `tls = false` in an agent profile only for an intentional direct raw TCP connection; TLS failures never fall back automatically. Upgrade the hub first because older hubs cannot read the HTTP envelope.

The agent validates the certificate chain, domain and validity dates using bundled public roots and the system trust store. Existing nginx certificates for the domain work normally. For a private CA or deliberately self-signed certificate, add `ca_file = "/etc/telegraff/ca.pem"` to the agent profile; it must contain public PEM certificates, never the server private key. Name and date checks remain enabled. Certificate and connection errors appear in each failed TCP attempt in the JSON report. Certificate renewal belongs to nginx/ACME; telegraff does not issue certificates.

nginx may terminate TLS and forward HTTP to the hub's existing TCP listener. For example, inside the HTTPS server block for the hub domain:

```nginx
location = /telegraff {
    client_max_body_size 256k;
    proxy_pass http://127.0.0.1:19477;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_request_buffering on;
    proxy_read_timeout 15s;
}
```

If a `stream` SNI router fronts nginx, route the hub domain to this HTTPS server, which then forwards `/telegraff` to the hub. Raw TLS passthrough directly to telegraff is insufficient: its internal listener expects HTTP or legacy raw frames, not TLS. Keep that backend private. The authenticated frame supplies the tested client address family even when nginx uses IPv4 for its upstream connection.

UDP remains the existing encrypted datagram protocol: it is not HTTPS and has no TLS SNI. Forward public UDP separately (for example, nginx `stream` with `listen 443 udp` and `proxy_pass 127.0.0.1:19477`); an HTTP location cannot proxy it. Both transports still use the profile's advertised port. Hub startup checks public TCP connectivity only; authentication, HTTPS and UDP are checked by the agent's first cycle. The agent does not listen on an inbound port.

## Verify operation

1. Start the agent service to run its first cycle immediately:

   ```sh
   sudo systemctl start telegraff-agent.service
   sudo journalctl -u telegraff-agent.service -n 10 --no-pager
   ```

   Expected result: each required channel has a successful authenticated receipt. Without a receipt, hub acceptance is unknown to the agent. The hub may have received data successfully.

2. On the hub, inspect the matrix:

   ```sh
   sudo -u telegraff telegraff status --config /etc/telegraff/hub.toml
   sudo -u telegraff telegraff status --config /etc/telegraff/hub.toml --json
   ```

   With the default `./telegraff.toml`, run `./telegraff status` without `--config`. The text summary explains recent/stale hub observations, empty registrations, pending checks, failed channels and notification backlog. A recent heartbeat is not proof that every probe passed. Historical monitoring interruptions mean the hub recorded no observations then; they do not prove a network failure. `--json` retains timestamps, DNS signatures and detailed fields for diagnostics. Results finalize after each monitoring interval. A working IPv4 channel does not clear IPv6 failures; a missing AAAA record is acceptable when IPv6 is not expected.

3. To verify alert delivery, stop an agent service for three expected cycles. Expect one failure notification after the third deadline plus grace. Start the service again. Expect recovery after the next successful cycle finalizes. Reminders default to six hours; set `reminder_seconds = 0` to disable them.

## Maintenance and faults

For an explicit `[[agents]]` entry, set `paused = true` and restart the hub before maintenance. Set it to `false` and restart to resume without counting the maintenance backlog. Configuration changes require a restart. Keep the SQLite file and its WAL files together during backup; use SQLite online backup for a running hub.

| Condition | Action |
|---|---|
| TCP works, UDP fails | Check UDP firewall rules and delivery loss. |
| IPv4 works, IPv6 fails | Check AAAA records, IPv6 listeners, routing, and firewalls. |
| No agent traffic | Check the running agent, exported profile, forwarding and startup report. |
| Secret file rejected | Set mode `0600` and the service account owner. |
| Notification queued | Check ntfy URL, token, network access, and service logs. |
| DNS family warning | Compare advertised and expected families; edit the registry if intentional. |

Version 0.2 encrypts TCP and UDP frames with XChaCha20-Poly1305. The agent sends its token inside each encrypted request. The hub verifies the token before accepting data. The routing name is visible on the wire. Upgrade the hub and all agents together. Existing explicit registry entries and key files work with the new binaries. Logs and status contain technical names and aggregate results. The hub retains transfer summaries for 30 days and records observation gaps after downtime. It cannot alert while stopped: monitor its service or heartbeat from an independent system.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Network tests require IPv4 and IPv6 loopback.
