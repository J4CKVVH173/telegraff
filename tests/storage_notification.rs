mod common;
use telegraff::{
    application::{State, delivery::deliver, ports::Repository},
    infrastructure::{notification::Ntfy, store::SqliteStore},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn sqlite_restart_preserves_incidents_and_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite");
    let mut m = common::monitor();
    m.tick(600);
    m.tick(4200);
    m.tick(7800);
    SqliteStore::open(&path).unwrap().save(&m.state).unwrap();
    let loaded = SqliteStore::open(&path).unwrap().load().unwrap();
    assert_eq!(loaded.channels["node-01"]["ipv4/tcp"].failures, 3);
    assert_eq!(loaded.outbox.len(), 1);
    assert_eq!(
        loaded.channels["node-01"]["ipv4/tcp"].incident,
        m.state.channels["node-01"]["ipv4/tcp"].incident
    );
}
#[tokio::test]
async fn ntfy_retries_in_order_against_local_stub() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/topic", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        for (status, authenticated) in [
            ("200 OK", false),
            ("503 Service Unavailable", true),
            ("200 OK", true),
            ("200 OK", true),
        ] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            let n = socket.read(&mut buffer).await.unwrap();
            let headers = String::from_utf8_lossy(&buffer[..n]).to_ascii_lowercase();
            assert_eq!(
                headers.contains("\r\nauthorization: bearer "),
                authenticated
            );
            socket
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    use telegraff::{application::ports::Notifier, infrastructure::config::NtfyConfig};
    let public = Ntfy::new(&NtfyConfig {
        endpoint: endpoint.clone(),
        token_file: None,
    })
    .unwrap();
    public.publish("public topic").await.unwrap();
    let token = common::key_file(dir.path());
    let notifier = Ntfy::new(&telegraff::infrastructure::config::NtfyConfig {
        endpoint,
        token_file: Some(token),
    })
    .unwrap();
    let mut state = State::default();
    state.enqueue("node-01", 100, "failure at 100".into());
    state.enqueue("node-01", 101, "recovery at 101".into());
    deliver(&mut state, &notifier, 101).await.unwrap();
    assert_eq!(state.outbox.len(), 2);
    assert_eq!(state.outbox[0].attempts, 1);
    assert!(!deliver(&mut state, &notifier, 102).await.unwrap());
    deliver(&mut state, &notifier, 111).await.unwrap();
    assert_eq!(state.outbox[0].text, "recovery at 101");
    deliver(&mut state, &notifier, 112).await.unwrap();
    assert!(state.outbox.is_empty());
    server.await.unwrap();
}

#[test]
fn retention_removes_old_transfer_rows_without_rewriting_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite");
    let mut store = SqliteStore::open(&path).unwrap();
    let mut state = State::default();
    state.transfers.push(common::transfer(
        0,
        telegraff::application::Family::Ipv4,
        telegraff::application::Protocol::Tcp,
        153600,
    ));
    store.save(&state).unwrap();
    store.save(&state).unwrap();
    assert_eq!(store.load().unwrap().transfers.len(), 1);
    state.transfers.clear();
    state.observed_until = 86400;
    store.save(&state).unwrap();
    assert!(store.load().unwrap().transfers.is_empty());
}

#[test]
fn bounded_history_and_outbox_preserve_inflight_notification() {
    let mut state = State::default();
    for n in 0..1100 {
        state.enqueue("node-01", n, "ж".repeat(3000));
    }
    assert_eq!(state.outbox.len(), 1024);
    assert_eq!(state.outbox[0].id, 1);
    assert_eq!(state.outbox.last().unwrap().id, 1100);
    assert_eq!(state.discarded_notifications, 76);
    assert!(state.outbox.iter().all(|n| n.text.len() <= 4096));
    assert!(state.complete_notification(1, true, 1200));
    assert_eq!(state.outbox[0].id, 78);
    for n in 0..2000 {
        state.gaps.push((n, n + 1));
        state.transfers.push(common::transfer(
            n,
            telegraff::application::Family::Ipv4,
            telegraff::application::Protocol::Tcp,
            153600,
        ));
    }
    state.bound_history(12);
    assert_eq!(state.transfers.len(), 12);
    assert_eq!(state.transfers[0].cycle, 1988);
    assert_eq!(state.gaps.len(), 1024);
    assert_eq!(state.gaps.last(), Some(&(1999, 2000)));
}

#[test]
fn old_sqlite_history_is_capped_on_open_and_read_without_losing_incidents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.sqlite");
    let mut state = State {
        observed_until: 100,
        ..State::default()
    };
    state.enqueue("node-01", 100, "pending alert".into());
    for cycle in 1..=50 {
        state.transfers.push(common::transfer(
            cycle,
            telegraff::application::Family::Ipv4,
            telegraff::application::Protocol::Tcp,
            153600,
        ));
    }
    {
        let mut store = SqliteStore::open(&path).unwrap();
        store.save(&state).unwrap();
    }
    // A read is bounded even before startup migration/cleanup runs.
    let read = SqliteStore::read_bounded(&path, 5).unwrap();
    assert_eq!(read.transfers.len(), 5);
    assert_eq!(read.transfers[0].cycle, 46);
    let mut store = SqliteStore::open_bounded(&path, 10, 16, 30).unwrap();
    let mut state = store.load().unwrap();
    assert_eq!(state.transfers.len(), 10);
    assert_eq!(state.transfers[0].cycle, 41);
    assert_eq!(state.outbox.len(), 1);
    state.transfers.push(common::transfer(
        51,
        telegraff::application::Family::Ipv4,
        telegraff::application::Protocol::Tcp,
        153600,
    ));
    state.bound_history(10);
    store.save(&state).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM transfers", [], |r| r
            .get::<_, usize>(0))
            .unwrap(),
        10
    );
    assert_eq!(store.load().unwrap().transfers.last().unwrap().cycle, 51);
}
