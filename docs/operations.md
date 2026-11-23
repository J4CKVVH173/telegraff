# Operations

## Process and output

Run commands from the directory containing `telegraff.toml`, or use `--config PATH`.
Use the same OS account to start and stop the process. With no subcommand, an existing default config starts
its role in the foreground; without a config, the setup wizard opens. Use `-d` to detach, or systemd for boot startup.
Do not combine `-d` with systemd. Disable any legacy agent timer when enabling the continuous agent service.

Default output is a short text summary, even in pipes. `-v` / `--verbose` enables configuration metadata,
DNS, interval history, per-attempt results and error causes; it also propagates to background workers.
Private keys, profile secrets and ntfy topic/token values are not printed by configuration diagnostics.
`--json` on `status` or `agent` emits the complete structured result without colors; verbose runtime messages use stderr.
Without JSON, terminal output uses green for success, yellow for pending/warnings and red for failures.
`NO_COLOR` or `TERM=dumb` disables colors. `hub -dv` or `agent -dv` prints the runtime log path.

## TLS and forwarding

An empty hub `[tls]` table enables TLS 1.2/1.3 on every TCP listener. Certificate paths default to
`/etc/letsencrypt/live/<target>/fullchain.pem` and `privkey.pem`. For custom paths or a certbot lineage such as `domain-0001`:

```toml
[tls]
certificate_file = "/custom/fullchain.pem"
private_key_file = "/custom/privkey.pem"
```

The chain must cover the public domain; the private key must match, be unencrypted and readable by the hub account.
Certbot issues/renews certificates; telegraff reads them at startup. Arrange a restart using your process manager's
certbot deploy hook. Keep private key permissions restricted. A missing file or permission error prevents startup;
run `./telegraff config check -v` to see the underlying error.

With native TLS, nginx `stream` passes the hub domain's TLS connection to `tcp_listen` without decrypting it.
Keep TCP listeners on `127.0.0.1` / `::1` when the proxy runs on the same host. UDP needs its own route; it has no SNI.
`public_port` advertises the external TCP port, independently of local listener ports. UDP uses the same public port
unless `public_udp_port` is set. `udp_target` optionally advertises a different host for direct UDP.
The hub's startup TCP check proves reachability only; an agent cycle checks receipts and authentication.

For HTTPS on TCP 443 through a proxy and direct UDP 9477, set these top-level hub fields:

```toml
public_port = 443
public_udp_port = 9477
tcp_listen = ["127.0.0.1:9477", "[::1]:9477"]
udp_listen = ["0.0.0.0:9477", "[::]:9477"]
# udp_target = "origin.example.net" # if the proxy and origin use different addresses
```

Allow inbound UDP 9477 in the host/provider firewall; forward it separately if the hub is behind NAT.
Guided setup asks for the public TCP/UDP ports and UDP host. Choose `public` for UDP listener access when agents
connect directly; `loopback` is for a local UDP forwarder.

The exported agent profile contains `port = 443` and `udp_port = 9477`, plus `udp_hub` when `udp_target` is set.
`register NAME --udp-port 9477 --udp-hub origin.example.net` overrides those UDP defaults for a new profile.
Existing exported profiles keep their settings; edit them to add `udp_port` / `udp_hub`, or copy the updated profile
securely to the agent. Keep its secret unchanged. Upgrade the hub and agents before using the new fields. Omitted UDP fields preserve the old shared endpoint behavior.
Both names should provide the address families monitored by the policy; TCP and UDP failures remain independent.
UDP DNS failures do not fall back to the proxy's address. Separate UDP DNS details appear in verbose/JSON reports.


Alternatively, nginx can terminate TLS. Omit `[tls]` from the hub and add this to nginx's HTTPS server for the domain
(replace 9477 with the hub listener port):

```nginx
location = /telegraff {
    if ($request_method != POST) { return 405; }
    client_max_body_size 256k;
    proxy_pass http://127.0.0.1:9477;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_request_buffering on;
    proxy_read_timeout 15s;
}
```

DNS agent targets default to HTTPS with SNI, Host and certificate verification; IP literals default to raw TCP.
Native-TLS registrations explicitly enable TLS, including for IP targets (which need explicit certificate paths).
Use `tls = false` only for intentional plain TCP. TLS failures never fall back to plaintext.
For a private CA, set `ca_file = "/path/ca.pem"` in the agent profile; domain and date validation remain enabled.
TLS needs a reasonably accurate clock; monitoring intervals do not need synchronized agent clocks.

## Registration and monitoring

`register NAME` exports `NAME.toml` (0600); `--output PATH` changes the destination and refuses overwrites.
The private registry is stored beside the hub database. Registration automatically restarts a running `hub -d` daemon and preserves its working directory. Transfer the profile securely.
Stopped hubs stay stopped. Foreground and systemd hubs print a reminder to restart using their existing process manager.
`unregister NAME` revokes credentials immediately, removes the live policy/pending alerts within one second,
and preserves history and exported files. Explicit `[[agents]]` entries must be removed from the config, followed by restart.
Re-registering creates a new credential: replace the agent profile as well.

Registered agents probe immediately, then repeat at their configured interval. The hub assigns cycles to persisted
intervals. A transfer meeting the channel success threshold immediately shows `OK` in status, including JSON, superseding older failures. Missing or insufficient transfers retain the previous result until the interval closes. `RECEIVED` indicates provisional intake that has not met the success threshold. Finalized monitoring counters and notification timing are unchanged.
`status -v` shows the interval length and next result time. No receipt means delivery is
unconfirmed, even if the hub received some data. Three failed intervals trigger an alert; recovery is notified after
a successful interval. Reminders default to six hours (`reminder_seconds = 0` disables them).
Hub downtime in `status -v` uses UTC dates and human durations; it describes missing observations, not proof of network failure.
Raw timestamps, DNS signatures and all channel fields remain in `status --json`.
The hub cannot alert while stopped; monitor its process independently.

## Troubleshooting and updates

| Symptom | Check |
|---|---|
| Hub `STALE` | Hub process, permissions, database and logs (`hub -v`). |
| TCP fails | `agent --once -v`: DNS, public route, certificate and key permissions. |
| UDP fails | Separate UDP forwarding, firewall, reachability and loss. |
| IPv6 fails | AAAA records, IPv6 route/listeners and firewall. |
| Pending notifications | ntfy configuration, token-file permissions, network and hub logs. |
| Already running | Stop the matching config before `agent --once`. |

Replace binaries atomically to avoid `Text file busy`:

```sh
cp /path/to/new/telegraff ./telegraff.new
chmod +x ./telegraff.new
mv -f ./telegraff.new ./telegraff
./telegraff down
./telegraff hub -d                 # or agent -d
```

For systemd, use its restart command instead of `down`/`-d`. For explicit policies, set `paused = true` and restart
before maintenance. Use SQLite online backup for a running hub; preserve the database and WAL files together.
Transfer summaries are retained for 30 days by default. Probe frames use XChaCha20-Poly1305; routing names are visible.

## Build and development

`make release` builds locked dependencies for `x86_64-unknown-linux-musl`, verifies no ELF dynamic loader/shared-library
dependencies, and atomically writes `dist/telegraff`. The first build downloads the Rust target and dependencies.
Override `OUTPUT` or `CARGO_TARGET_DIR` as needed; other `TARGET` architectures require a matching musl cross compiler.

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Network tests require IPv4 and IPv6 loopback. [Example configs](../examples/) list policy settings;
[systemd units](../packaging/) supply service installation paths.


## Ingress overload protection

Admission control runs before TLS/frame authentication and is shared across hub listeners. Defaults are:

| Resource | Limit |
| --- | --- |
| TCP admissions | 128/s globally, 32/s per IP |
| Active TCP connections | `max_connections = 64` globally, 16 per IP, 4 per authenticated agent |
| UDP packets admitted to authentication | 50,000/s globally, 2,000/s per IP |
| Authenticated requests/packets | 4,096/s per agent across TCP/UDP |
| IP tracking | 4,096 records; inactive records expire after 120 seconds |
| UDP assemblies | `max_assemblies = 256` globally, 8 per agent; expire after 120 seconds |

Rate buckets start full and allow a burst of twice the configured per-second rate. Excess traffic is dropped/closed;
there is no waiting queue for admission. A full IP table rejects new IPs until records expire. IPv4-mapped IPv6 shares
its IPv4 quota. TCP retains its ten-second deadline including TLS. Frame size limits, credential verification and
per-agent cycle byte quotas also remain active. The bounded intake queue rejects excess events; delivery acknowledgements
have a bounded wait. A dropped receipt causes a failed attempt/retry, never a false success.

Tune `[ingress]` using the commented defaults in `examples/hub.toml`. Fields must be positive; invalid limits fail
configuration validation. Limits apply to the socket peer: agents behind NAT share a quota, and a reverse proxy's
connections share its IP quota. Increase per-IP limits for expected aggregate traffic. Forwarded HTTP headers cannot
change the quota identity. Registered agent quotas remain independent after authentication.

Rejections are counted by reason and logged at most once every 30 seconds, without peer addresses or request contents.
Counters cover rate/capacity, authentication/frame errors, agent quotas, assembly limits, oversize UDP, queue pressure
and timeouts. These are interval counts in the hub log, not persisted status statistics; restart clears them.

This bounds application work and memory. It cannot prevent link saturation or guarantee availability under distributed
traffic; network/provider filtering is still needed for volumetric attacks. Limits may cause failed monitoring cycles
under load, which is preferable to reporting delivery that did not complete.

## Bounded logs, history and memory

Detached mode (`hub -d` / `agent -d`) automatically rotates its private runtime `.log` file at 10 MiB and keeps
three archives (`.log.1` through `.log.3`), at most 40 MiB per configuration. Both stdout and stderr pass through
a separate streaming sink with an 8 KiB buffer and a bounded OS pipe; a slow disk applies backpressure. Rotation
runs on writes, including a single oversized write. Restart keeps the existing log/archives. On upgrade an oversized
active log is reduced to its latest 10 MiB. Log rotation may split a line at a file boundary. Old runtime logs belonging
to other configuration paths are not automatically removed.

Hub history defaults (top-level TOML fields):

```toml
retention_days = 30
max_transfer_records = 100000
database_max_mib = 256
```

Age and record count both apply; the oldest history goes first. The same record cap applies to SQL history, hub RAM,
the persistence cache and `status` reads. Configure at least 12 records per registered agent so an entire active cycle
fits. SQLite's page cache targets 4 MiB and memory mapping is disabled. The record cap is configurable up to 1,000,000;
RAM usage also depends on the number of configured agents and active connections, so this is not an absolute RSS cap.

SQLite uses FULL synchronous commits, full auto-vacuum and a TRUNCATE rollback journal, which is emptied after each
commit. This avoids a WAL accumulating behind long-lived readers; reads and writes can briefly block one another
(up to the five-second busy timeout). A legacy WAL database is migrated on the next hub startup, with history pruning
and one VACUUM to enable space reclamation. That first startup can take longer and needs temporary disk space.
`status` remains read-only. Do not copy or delete live database journal files.

`database_max_mib` limits the main database (16..16384 MiB), not the entire directory: a transaction's rollback journal
can temporarily approach the database size, and migration/VACUUM needs additional temporary space. If the remaining
active state cannot fit after cleanup, startup or persistence fails explicitly; it does not acknowledge unpersisted
delivery or remove active incidents just to satisfy the cap. Metadata snapshots are limited to 8 MiB. Existing secrets,
registration profiles and current monitoring counters are retained.

In-memory metadata also has bounds: 1,024 notification messages (up to 4 KiB of text each), 1,024 observation gaps,
and 1,024 replay tokens per agent across the current/previous hub interval. Without ntfy configured, pending notifications
are cleared on the next tick. If notification delivery stays unavailable and the queue fills, the first/in-flight message
and the newest waiting messages are kept. The persisted discard count is shown in text/JSON `status`.

Old replay-token mappings are compacted into a persisted per-agent watermark. Previously retired tokens cannot count
as new successes after a restart. New tokens below that watermark are rejected too: if an agent clock moves far backwards,
restore its clock or re-register it with a new credential. A fixed difference between hub and agent clocks still works.

For foreground redirection, the caller manages output-file rotation. Under systemd, journald manages the logs; detached
mode's file sink is not used. For a separate bounded telegraff journal, install `packaging/journald@telegraff.conf` as
`/etc/systemd/journald@telegraff.conf` and add a drop-in to the telegraff units:

```ini
[Service]
LogNamespace=telegraff
```

Restart the telegraff journal namespace and services after installing the configuration. Read it with
`journalctl --namespace=telegraff -u telegraff-hub` (or `telegraff-agent`). The namespace's limits apply only to its own
journal; journald can exceed the target temporarily by active journal-file overhead. See
[systemd journal namespaces and limits](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html).
For an absolute process-memory safety net, a service drop-in can set `MemoryHigh=192M` and `MemoryMax=256M`;
size these for the agent count/history cap. The kernel may terminate the service at `MemoryMax`, and `Restart=on-failure`
then restarts it. These optional service settings are not installed automatically.
