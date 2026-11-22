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
        for status in ["503 Service Unavailable", "200 OK", "200 OK"] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            let n = socket.read(&mut buffer).await.unwrap();
            assert!(n > 0);
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
    let token = common::key_file(dir.path());
    let notifier = Ntfy::new(&telegraff::infrastructure::config::NtfyConfig {
        endpoint,
        token_file: token,
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
