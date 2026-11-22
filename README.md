# telegraff

telegraff checks scheduled payload delivery from registered Linux servers to a hub.
One Rust executable provides both roles. TCP, UDP, IPv4, and IPv6 have separate results.
The hub sends an ntfy alert after three consecutive failed cycles for a channel.

![graff](global/baner.png)


## Requirements

Use Linux with systemd, synchronized clocks, and working DNS.
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

3. Allow inbound TCP **and** UDP port `9477` in the host and provider firewalls for each configured address family. Agents need outbound access to that port. The hub needs DNS and HTTPS access to ntfy. Remove IPv6 listener entries only if the hub has no IPv6 support.

4. Start the hub:

   ```sh
   sudo install -m 0644 packaging/telegraff-hub.service /etc/systemd/system/
   sudo -u telegraff telegraff config check --config /etc/telegraff/hub.toml
   sudo systemctl daemon-reload
   sudo systemctl enable --now telegraff-hub.service
   ```

## Configure an agent

1. On the hub, register the agent and load its registration:

   ```sh
   sudo -u telegraff telegraff register node-01
   sudo systemctl restart telegraff-hub
   ```

   The command prints the path to a private profile. It uses the configured hub address, the first TCP listener's port, and the hourly timer. Use `--port` for port forwarding. Both transports must reach the hub on the advertised port. Each name has its own secret. Keep the hub's copy for future restarts.

2. Transfer the profile over SSH to a private directory on the agent. Install it as the agent configuration:

   ```sh
   sudo install -o telegraff -g telegraff -m 0600 node-01.profile /etc/telegraff/agent.toml
   sudo -u telegraff telegraff config check --config /etc/telegraff/agent.toml
   ```

   The hub enrolls address families from DNS. TCP and UDP each send three transfers of 150 KiB per family. To revoke a registration, remove its profile from the hub registry and restart the hub.

3. Install the service and timer:

   ```sh
   sudo install -m 0644 packaging/telegraff-agent.service packaging/telegraff-agent.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now telegraff-agent.timer
   ```

   The supplied timer matches `interval = 3600`, `offset = 0`. To run at five minutes past the hour, register with `--offset 300` and set the timer minute to `05`. Do not enable persistent catch-up or random delays.

## Verify operation

1. Wait for the next scheduled run, or run the agent during the first ten minutes after its scheduled hour:

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

   Cycle states finalize after the grace period. `FAILING` means one or two misses. `ALERT` means three or more. A working IPv4 channel does not clear IPv6 failures. No AAAA record is acceptable when IPv6 is not expected.

3. To verify alert delivery, stop an agent timer for three expected cycles. Expect one failure notification after the third deadline plus grace. Start the timer again. Expect recovery after the next successful cycle finalizes. Reminders default to six hours; set `reminder_seconds = 0` to disable them.

## Maintenance and faults

For an explicit `[[agents]]` entry, set `paused = true` and restart the hub before maintenance. Set it to `false` and restart to resume without counting the maintenance backlog. Configuration changes require a restart. Keep the SQLite file and its WAL files together during backup; use SQLite online backup for a running hub.

| Condition | Action |
|---|---|
| TCP works, UDP fails | Check UDP firewall rules and delivery loss. |
| IPv4 works, IPv6 fails | Check AAAA records, IPv6 listeners, routing, and firewalls. |
| No agent traffic | Check the timer, clock, name, key, and schedule. |
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
